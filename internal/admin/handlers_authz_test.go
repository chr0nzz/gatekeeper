package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const admAuthzChrome = `id="sidebar"`

var admAuthzGetPages = []struct {
	name string
	path string
}{
	{"dashboard", "/"},
	{"users", "/users"},
	{"new user", "/users/new"},
	{"clients", "/clients"},
	{"policies", "/policies"},
	{"groups", "/groups"},
	{"invites", "/invites"},
	{"audit", "/audit"},
	{"audit export", "/audit/export.csv"},
	{"settings", "/settings"},
	{"social", "/social"},
	{"webhooks", "/webhooks"},
	{"integrations", "/integrations"},
	{"backups", "/backups"},
	{"admins", "/admins"},
	{"profile", "/profile"},
	{"dashboard stats api", "/api/dashboard-stats"},
	{"search api", "/api/search"},
}

func admAuthzCount(t *testing.T, a *adminHarness, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := a.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

func admAuthzGetWithAPIKey(a *adminHarness, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Api-Key", key)
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	return rec
}

func admAuthzAssertDenied(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	switch rec.Code {
	case http.StatusUnauthorized, http.StatusForbidden:
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
		if loc := adminLocation(rec); !strings.HasSuffix(loc, "/login") {
			t.Fatalf("%s redirected an anonymous caller to %q, want the login page", what, loc)
		}
	default:
		t.Fatalf("%s served an anonymous caller with status %d", what, rec.Code)
	}
	if strings.Contains(rec.Body.String(), admAuthzChrome) {
		t.Fatalf("%s leaked admin content to an anonymous caller", what)
	}
}

func TestAdminPagesDenyAnonymousCallers(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)

	for _, tc := range admAuthzGetPages {
		t.Run(tc.name, func(t *testing.T) {
			admAuthzAssertDenied(t, a.get(tc.path), "GET "+tc.path)

			rec := a.get(tc.path, cookie)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s with an admin session returned %d, want 200", tc.path, rec.Code)
			}
		})
	}
}

func TestAdminPageDeniesForgedSessionCookie(t *testing.T) {
	a := newAdminHarness(t)
	a.signIn(t)

	forged := &http.Cookie{Name: "gk_admin", Value: "00000000-0000-0000-0000-000000000000"}
	admAuthzAssertDenied(t, a.get("/users", forged), "GET /users with an unknown session id")
}

func TestAdminMutationsDenyAnonymousCallers(t *testing.T) {
	a := newAdminHarness(t)
	a.signIn(t)
	victim := a.addUser(t, "victim@example.com")
	a.set(t, "login_app_name", "GateKeeper")

	cases := []struct {
		name   string
		path   string
		form   url.Values
		verify func(t *testing.T)
	}{
		{
			name: "create user",
			path: "/users",
			form: url.Values{"email": {"intruder@example.com"}, "passwordless": {"1"}},
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM users WHERE email=?`, "intruder@example.com"); n != 0 {
					t.Fatalf("anonymous POST /users created %d users", n)
				}
			},
		},
		{
			name: "disable user",
			path: "/users/" + victim + "/disable",
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM users WHERE id=? AND disabled=1`, victim); n != 0 {
					t.Fatalf("anonymous POST disabled the user")
				}
			},
		},
		{
			name: "delete user",
			path: "/users/" + victim + "/delete",
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM users WHERE id=?`, victim); n != 1 {
					t.Fatalf("anonymous POST deleted the user")
				}
			},
		},
		{
			name: "revoke user sessions",
			path: "/users/" + victim + "/revoke-sessions",
		},
		{
			name: "create client",
			path: "/clients",
			form: url.Values{"client_id": {"stolen"}, "redirect_uris": {"https://evil.example.com/cb"}},
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM oidc_clients`); n != 0 {
					t.Fatalf("anonymous POST /clients registered %d clients", n)
				}
			},
		},
		{
			name: "create group",
			path: "/groups",
			form: url.Values{"name": {"intruders"}},
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM groups`); n != 0 {
					t.Fatalf("anonymous POST /groups created %d groups", n)
				}
			},
		},
		{
			name: "create policy",
			path: "/policies",
			form: url.Values{"name": {"intruders"}},
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM policies`); n != 0 {
					t.Fatalf("anonymous POST /policies created %d policies", n)
				}
			},
		},
		{
			name: "create admin",
			path: "/admins",
			form: url.Values{"email": {"intruder@example.com"}, "password": {"correct-horse-battery-staple"}, "confirm": {"correct-horse-battery-staple"}},
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM admin_users`); n != 1 {
					t.Fatalf("admin account count is %d, anonymous POST /admins gained a foothold", n)
				}
			},
		},
		{
			name: "create webhook",
			path: "/webhooks",
			form: url.Values{"type": {"generic"}, "url": {"https://evil.example.com/hook"}},
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM webhooks`); n != 0 {
					t.Fatalf("anonymous POST /webhooks created %d webhooks", n)
				}
			},
		},
		{
			name: "save settings",
			path: "/settings",
			form: url.Values{"login_app_name": {"Pwned"}, "allowed_email_domains": {"evil.example.com"}},
			verify: func(t *testing.T) {
				if got := a.settings.Get(context.Background(), "login_app_name", ""); got != "GateKeeper" {
					t.Fatalf("login_app_name is %q, anonymous POST /settings was applied", got)
				}
			},
		},
		{
			name: "rotate api key",
			path: "/profile/api-key/rotate",
			verify: func(t *testing.T) {
				if a.admins.HasAPIKey(context.Background(), a.adminID) {
					t.Fatalf("anonymous POST minted an API key")
				}
			},
		},
		{
			name: "run backup",
			path: "/backups/now",
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM backups`); n != 0 {
					t.Fatalf("anonymous POST /backups/now produced %d backups", n)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admAuthzAssertDenied(t, a.postForm(tc.path, tc.form), "POST "+tc.path)
			if tc.verify != nil {
				tc.verify(t)
			}
		})
	}
}

func TestAdminMutationsRejectMissingCSRFToken(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	victim := a.addUser(t, "victim@example.com")
	a.set(t, "login_app_name", "GateKeeper")
	if err := a.admins.SetAPIKey(context.Background(), a.adminID, "admauthz-existing-key"); err != nil {
		t.Fatalf("seed api key: %v", err)
	}

	cases := []struct {
		name   string
		path   string
		verify func(t *testing.T)
	}{
		{
			name: "delete user",
			path: "/users/" + victim + "/delete",
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM users WHERE id=?`, victim); n != 1 {
					t.Fatalf("forged POST deleted the user")
				}
			},
		},
		{
			name: "disable user",
			path: "/users/" + victim + "/disable",
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM users WHERE id=? AND disabled=1`, victim); n != 0 {
					t.Fatalf("forged POST disabled the user")
				}
			},
		},
		{
			name: "make user admin",
			path: "/users/" + victim + "/make-admin",
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM admin_users`); n != 1 {
					t.Fatalf("forged POST promoted a user to admin")
				}
			},
		},
		{
			name: "save settings",
			path: "/settings",
			verify: func(t *testing.T) {
				if got := a.settings.Get(context.Background(), "login_app_name", ""); got != "GateKeeper" {
					t.Fatalf("login_app_name is %q, forged POST /settings was applied", got)
				}
			},
		},
		{
			name: "save backup settings",
			path: "/backups/settings",
			verify: func(t *testing.T) {
				if got := a.settings.Get(context.Background(), "backup_storage", "unset"); got != "unset" {
					t.Fatalf("backup_storage is %q, forged POST was applied", got)
				}
			},
		},
		{
			name: "change display name",
			path: "/profile/display-name",
			verify: func(t *testing.T) {
				admin, err := a.admins.GetByID(context.Background(), a.adminID)
				if err != nil || admin == nil {
					t.Fatalf("load admin: %v", err)
				}
				if admin.DisplayName != "Test Admin" {
					t.Fatalf("display name is %q, forged POST was applied", admin.DisplayName)
				}
			},
		},
		{
			name: "rotate api key",
			path: "/profile/api-key/rotate",
			verify: func(t *testing.T) {
				if a.admins.GetByAPIKey(context.Background(), "admauthz-existing-key") != a.adminID {
					t.Fatalf("forged POST rotated the API key")
				}
			},
		},
		{
			name: "create admin",
			path: "/admins",
			verify: func(t *testing.T) {
				if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM admin_users`); n != 1 {
					t.Fatalf("forged POST /admins created an account")
				}
			},
		},
		{"create user", "/users", nil},
		{"create client", "/clients", nil},
		{"create group", "/groups", nil},
		{"create policy", "/policies", nil},
		{"create invite", "/invites", nil},
		{"create webhook", "/webhooks", nil},
		{"run backup", "/backups/now", nil},
		{"social settings", "/social", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := a.postWithoutCSRF(tc.path, cookie)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("POST %s without a CSRF token returned %d, want 403", tc.path, rec.Code)
			}
			if tc.verify != nil {
				tc.verify(t)
			}
		})
	}
}

func TestAdminMutationSucceedsWithCSRFToken(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	victim := a.addUser(t, "victim@example.com")

	rec := a.postForm("/users/"+victim+"/disable", nil, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST disable with a CSRF token returned %d, want 302", rec.Code)
	}
	if n := admAuthzCount(t, a, `SELECT COUNT(*) FROM users WHERE id=? AND disabled=1`, victim); n != 1 {
		t.Fatalf("authorised POST did not disable the user")
	}
}

func TestAdminAPIKeyHeaderAuthenticates(t *testing.T) {
	a := newAdminHarness(t)
	a.signIn(t)

	const key = "admauthz-secret-api-key-value"
	if err := a.admins.SetAPIKey(context.Background(), a.adminID, key); err != nil {
		t.Fatalf("set api key: %v", err)
	}

	rec := admAuthzGetWithAPIKey(a, "/api/dashboard-stats", key)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dashboard-stats with a valid API key returned %d, want 200", rec.Code)
	}

	rec = admAuthzGetWithAPIKey(a, "/users", key)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /users with an API key returned %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), admAuthzChrome) {
		t.Fatal("an API key rendered the admin panel")
	}
}

func TestAdminAPIKeyHeaderDoesNotMatchAdminsWithoutAKey(t *testing.T) {
	a := newAdminHarness(t)
	a.signIn(t)

	for _, key := range []string{" ", "''", "%", "\x00"} {
		admAuthzAssertDenied(t, admAuthzGetWithAPIKey(a, "/users", key), "GET /users with blank key")
	}
}
