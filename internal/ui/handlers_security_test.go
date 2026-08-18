package ui

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/chr0nzz/gatekeeper/internal/auth"
)

func secPendingCookie(t *testing.T, u *uiHarness, userID string, data auth.SessionData) *http.Cookie {
	t.Helper()
	rec := newRecorder()
	req := newGetRequest("/")
	if _, err := u.sessions.Create(rec, req, data); err != nil {
		t.Fatalf("create pending session: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gk_session" {
			return c
		}
	}
	t.Fatal("no cookie")
	return nil
}

func TestPendingTOTPSessionCannotReachAccountPages(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "victim@example.com", "correct-horse-battery-staple")
	cookie := secPendingCookie(t, u, id, auth.SessionData{UserID: id, PendingTOTP: true})

	for _, path := range []string{"/", "/profile/totp/enroll", "/register/passkey", "/profile/password"} {
		rec := u.get(path, cookie)
		if rec.Code != http.StatusFound {
			t.Errorf("GET %s with a pending session = %d, want a redirect", path, rec.Code)
		}
		if loc := location(rec); loc != "/login/totp" && loc != "/login" {
			t.Errorf("GET %s redirected to %q, want the second factor step", path, loc)
		}
	}
}

func TestPendingOTPSessionCannotRegisterAPasskey(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "victim2@example.com", "")
	cookie := secPendingCookie(t, u, id, auth.SessionData{UserID: id, PendingOTP: true})

	rec := u.postForm("/register/passkey/begin", url.Values{}, cookie)
	if rec.Code == http.StatusOK {
		t.Error("a pending session started passkey registration")
	}
}

func TestFullSessionStillReachesAccountPages(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "real@example.com", "correct-horse-battery-staple")
	cookie := u.signIn(t, id)

	if rec := u.get("/", cookie); rec.Code != http.StatusOK {
		t.Errorf("GET / with a complete session = %d, want 200", rec.Code)
	}
}

func TestLoginRequiresCSRF(t *testing.T) {
	u := newUIHarness(t)
	u.addUser(t, "csrf@example.com", "correct-horse-battery-staple")

	req := newPostRequest("/login", url.Values{
		"email":    {"csrf@example.com"},
		"password": {"correct-horse-battery-staple"},
	})
	rec := newRecorder()
	u.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /login without a CSRF token = %d, want 403", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gk_session" {
			t.Fatal("a session was issued for a request with no CSRF token")
		}
	}
}

func TestInviteBindsToTheInvitedAddress(t *testing.T) {
	ctx := context.Background()
	u := newUIHarness(t)
	u.set(t, "registration_mode", "invite_only")

	token, err := u.h.invites.Create(ctx, "invited@example.com", "", "admin", 7)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	u.postForm("/register", url.Values{
		"invite_token":     {token},
		"email":            {"attacker@evil.com"},
		"password":         {"correct-horse-battery-staple"},
		"confirm_password": {"correct-horse-battery-staple"},
	})

	if user, _ := u.users.GetByEmail(ctx, "attacker@evil.com"); user != nil {
		t.Fatal("an invite created an account under an address it was not issued to")
	}
}

func TestInviteCannotBeRedeemedTwice(t *testing.T) {
	ctx := context.Background()
	u := newUIHarness(t)
	u.set(t, "registration_mode", "invite_only")

	token, _ := u.h.invites.Create(ctx, "once@example.com", "", "admin", 7)
	form := url.Values{
		"invite_token":     {token},
		"email":            {"once@example.com"},
		"password":         {"correct-horse-battery-staple"},
		"confirm_password": {"correct-horse-battery-staple"},
	}
	u.postForm("/register", form)
	u.postForm("/register", form)

	var n int
	u.db.QueryRow(`SELECT COUNT(*) FROM users WHERE email='once@example.com'`).Scan(&n)
	if n != 1 {
		t.Errorf("one invite produced %d accounts, want 1", n)
	}
}
