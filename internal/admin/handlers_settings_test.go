package admin

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

func admSetRawSetting(t *testing.T, a *adminHarness, key string) string {
	t.Helper()
	var v string
	if err := a.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		t.Fatalf("read raw setting %s: %v", key, err)
	}
	return v
}

func admSetClientSecret(t *testing.T, a *adminHarness, clientID string) string {
	t.Helper()
	var v string
	if err := a.db.QueryRow(`SELECT client_secret FROM oidc_clients WHERE client_id=?`, clientID).Scan(&v); err != nil {
		t.Fatalf("read client secret %s: %v", clientID, err)
	}
	return v
}

func admSetIDFromLocation(t *testing.T, location, prefix string) string {
	t.Helper()
	if !strings.HasPrefix(location, prefix) {
		t.Fatalf("location %q does not start with %q", location, prefix)
	}
	id := strings.TrimPrefix(location, prefix)
	if id == "" {
		t.Fatalf("no id in location %q", location)
	}
	return id
}

func admSetGroupByName(t *testing.T, a *adminHarness, name string) *queries.Group {
	t.Helper()
	groups, err := a.h.groups.List(context.Background())
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i]
		}
	}
	return nil
}

func TestSettingsSavePersistsSubmittedValues(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	rec := a.postForm("/settings", url.Values{
		"allowed_email_domains":        {" example.com,corp.example "},
		"session_ttl_hours":            {"12"},
		"registration_mode":            {"invite"},
		"registration_allowed_domains": {"corp.example"},
		"audit_retention_days":         {"30"},
		"password_require_uppercase":   {"1"},
		"password_require_symbol":      {"1"},
		"login_app_name":               {"Acme SSO"},
	}, cookie)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save settings: got %d want %d", rec.Code, http.StatusSeeOther)
	}
	if got := adminLocation(rec); got != "/settings?saved=1" {
		t.Fatalf("redirect: got %q", got)
	}

	want := map[string]string{
		"allowed_email_domains":        "example.com,corp.example",
		"session_ttl_hours":            "12",
		"registration_mode":            "invite",
		"registration_allowed_domains": "corp.example",
		"audit_retention_days":         "30",
		"password_require_uppercase":   "1",
		"password_require_symbol":      "1",
		"login_app_name":               "Acme SSO",
	}
	for k, v := range want {
		if got := a.settings.Get(ctx, k, "unset"); got != v {
			t.Errorf("setting %s: got %q want %q", k, got, v)
		}
	}
	if got := a.settings.Get(ctx, "password_require_number", "unset"); got != "0" {
		t.Errorf("password_require_number: got %q want 0", got)
	}
}

func TestSettingsUncheckedToggleClearsPreviousValue(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	a.set(t, "password_require_uppercase", "1")
	a.postForm("/settings", url.Values{"session_ttl_hours": {"1"}}, cookie)

	if got := a.settings.Get(ctx, "password_require_uppercase", "unset"); got != "0" {
		t.Fatalf("password_require_uppercase: got %q want 0", got)
	}
}

func TestSettingsPasswordMinLengthRejectsOutOfRange(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	for _, v := range []string{"7", "0", "-1", "129", "1000", "abc", "12.5"} {
		a.postForm("/settings", url.Values{"password_min_length": {v}}, cookie)
		if got := a.settings.Get(ctx, "password_min_length", ""); got != "" {
			t.Fatalf("password_min_length %q was accepted, stored %q", v, got)
		}
	}

	for _, v := range []string{"8", "16", "128"} {
		a.postForm("/settings", url.Values{"password_min_length": {v}}, cookie)
		if got := a.settings.Get(ctx, "password_min_length", ""); got != v {
			t.Fatalf("password_min_length %q: stored %q", v, got)
		}
	}

	a.postForm("/settings", url.Values{"password_min_length": {"4"}}, cookie)
	if got := a.settings.Get(ctx, "password_min_length", ""); got != "128" {
		t.Fatalf("rejected value overwrote stored length: got %q want 128", got)
	}
}

func TestSettingsRedirectAllowedHostsPersists(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	const hosts = "app.example.com,files.example.com"
	a.postForm("/settings", url.Values{"redirect_allowed_hosts": {"  " + hosts + "  "}}, cookie)
	if got := a.settings.Get(ctx, "redirect_allowed_hosts", "unset"); got != hosts {
		t.Fatalf("redirect_allowed_hosts: got %q want %q", got, hosts)
	}

	a.postForm("/settings", url.Values{"redirect_allowed_hosts": {""}}, cookie)
	if got := a.settings.Get(ctx, "redirect_allowed_hosts", "unset"); got != "" {
		t.Fatalf("clearing redirect_allowed_hosts left %q", got)
	}
}

func TestSettingsSMTPPasswordStoredEncrypted(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	const secret = "s3cr3t-smtp-pass"
	a.postForm("/settings", url.Values{
		"smtp_host":     {"mail.example.com"},
		"smtp_username": {"postmaster@example.com"},
		"smtp_password": {secret},
	}, cookie)

	raw := admSetRawSetting(t, a, "smtp_password")
	if raw == "" {
		t.Fatal("smtp_password was not stored")
	}
	if raw == secret || strings.Contains(raw, secret) {
		t.Fatalf("smtp_password stored in clear text: %q", raw)
	}
	if got := a.settings.Get(ctx, "smtp_password", ""); got != secret {
		t.Fatalf("decrypted smtp_password: got %q want %q", got, secret)
	}
	if got := a.settings.GetAll(ctx)["smtp_password"]; got != secret {
		t.Fatalf("GetAll smtp_password: got %q want %q", got, secret)
	}
	if got := admSetRawSetting(t, a, "smtp_username"); got != "postmaster@example.com" {
		t.Fatalf("smtp_username: got %q", got)
	}

	a.postForm("/settings", url.Values{"smtp_host": {"mail2.example.com"}}, cookie)
	if got := a.settings.Get(ctx, "smtp_password", ""); got != secret {
		t.Fatalf("blank submit changed stored password: got %q", got)
	}
}

func TestSocialSettingsClientSecretsStoredEncrypted(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	secrets := map[string]string{
		"social_github_client_secret":  "gh-secret-value",
		"social_google_client_secret":  "goog-secret-value",
		"social_discord_client_secret": "disc-secret-value",
	}
	form := url.Values{
		"social_github_enabled":   {"1"},
		"social_github_client_id": {"gh-client-id"},
	}
	for k, v := range secrets {
		form.Set(k, v)
	}
	rec := a.postForm("/social", form, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save social settings: got %d", rec.Code)
	}

	for key, secret := range secrets {
		if !queries.IsSecretKey(key) {
			t.Fatalf("%s is not treated as a secret key", key)
		}
		raw := admSetRawSetting(t, a, key)
		if raw == secret || strings.Contains(raw, secret) {
			t.Errorf("%s stored in clear text: %q", key, raw)
		}
		if got := a.settings.Get(ctx, key, ""); got != secret {
			t.Errorf("%s round trip: got %q want %q", key, got, secret)
		}
	}

	if got := a.settings.Get(ctx, "social_github_enabled", ""); got != "1" {
		t.Errorf("social_github_enabled: got %q want 1", got)
	}
	if got := a.settings.Get(ctx, "social_google_enabled", ""); got != "0" {
		t.Errorf("social_google_enabled: got %q want 0", got)
	}

	a.postForm("/social", url.Values{"social_github_client_id": {"gh-client-id"}}, cookie)
	if got := a.settings.Get(ctx, "social_github_client_secret", ""); got != secrets["social_github_client_secret"] {
		t.Fatalf("blank submit erased github secret: got %q", got)
	}
}

func TestSettingsRejectsUnauthenticatedAndForgedRequests(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	a.set(t, "login_app_name", "Original")

	rec := a.postForm("/settings", url.Values{"login_app_name": {"Hijacked"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("anonymous save: got %d want redirect to login", rec.Code)
	}
	if got := a.settings.Get(ctx, "login_app_name", ""); got != "Original" {
		t.Fatalf("anonymous request changed settings: got %q", got)
	}

	rec = a.postWithoutCSRF("/settings", cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token: got %d want 403", rec.Code)
	}
	if got := a.settings.Get(ctx, "login_app_name", ""); got != "Original" {
		t.Fatalf("forged request changed settings: got %q", got)
	}

	rec = a.postForm("/social", url.Values{"social_github_client_id": {"nope"}})
	if got := a.settings.Get(ctx, "social_github_client_id", ""); got != "" {
		t.Fatalf("anonymous social save persisted %q (status %d)", got, rec.Code)
	}
}

func TestCreateClientStoresCredentialsAndRedirectURIs(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	rec := a.postForm("/clients", url.Values{
		"client_id":     {"grafana"},
		"client_secret": {"grafana-secret"},
		"name":          {"Grafana"},
		"redirect_uris": {"https://grafana.example.com/login/generic_oauth\n\n  https://grafana.example.com/alt  \n"},
	}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("create client: got %d", rec.Code)
	}

	clients, err := a.h.oidcStorage.ListClients(ctx)
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
	c := clients[0]
	if c.ClientID != "grafana" || c.Name != "Grafana" {
		t.Fatalf("stored client: %+v", c)
	}
	want := []string{
		"https://grafana.example.com/login/generic_oauth",
		"https://grafana.example.com/alt",
	}
	if len(c.RedirectURIs) != len(want) {
		t.Fatalf("redirect URIs: got %v want %v", c.RedirectURIs, want)
	}
	for i, u := range want {
		if c.RedirectURIs[i] != u {
			t.Fatalf("redirect URI %d: got %q want %q", i, c.RedirectURIs[i], u)
		}
	}
	if got := admSetClientSecret(t, a, "grafana"); got != "grafana-secret" {
		t.Fatalf("client secret: got %q", got)
	}

	a.postForm("/clients", url.Values{
		"client_id":     {"grafana"},
		"client_secret": {"attacker-secret"},
		"name":          {"Not Grafana"},
	}, cookie)
	if got := admSetClientSecret(t, a, "grafana"); got != "grafana-secret" {
		t.Fatalf("duplicate create overwrote secret: got %q", got)
	}
}

func TestDeleteClientRemovesOnlyTheNamedClient(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	for _, id := range []string{"keep-me", "delete-me"} {
		a.postForm("/clients", url.Values{
			"client_id":     {id},
			"client_secret": {id + "-secret"},
			"name":          {id},
		}, cookie)
	}

	if rec := a.postWithoutCSRF("/clients/delete-me/delete", cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("delete without CSRF: got %d want 403", rec.Code)
	}
	if got := admSetClientSecret(t, a, "delete-me"); got != "delete-me-secret" {
		t.Fatalf("client changed by forged request: %q", got)
	}

	if rec := a.postForm("/clients/delete-me/delete", nil, cookie); rec.Code != http.StatusFound {
		t.Fatalf("delete client: got %d", rec.Code)
	}

	clients, _ := a.h.oidcStorage.ListClients(ctx)
	if len(clients) != 1 || clients[0].ClientID != "keep-me" {
		t.Fatalf("after delete: %+v", clients)
	}
}

func TestPolicyLifecycleAddsAndRemovesMembers(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	rec := a.postForm("/policies", url.Values{
		"name":        {"admins-only"},
		"description": {"Internal tools"},
	}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("create policy: got %d", rec.Code)
	}
	id := admSetIDFromLocation(t, adminLocation(rec), "/policies/")

	pol, err := a.h.policies.GetByID(ctx, id)
	if err != nil || pol == nil {
		t.Fatalf("policy not stored: %v", err)
	}
	if pol.Name != "admins-only" || pol.Description != "Internal tools" {
		t.Fatalf("policy fields: %+v", pol)
	}

	userID := a.addUser(t, "member@example.com")
	otherID := a.addUser(t, "other@example.com")

	a.postForm("/policies/"+id+"/members", url.Values{"user_id": {userID}}, cookie)
	a.postForm("/policies/"+id+"/members", url.Values{"user_id": {otherID}}, cookie)

	members, _ := a.h.policies.GetMembers(ctx, id)
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
	if in, _ := a.h.policies.IsUserInPolicyByID(ctx, id, userID); !in {
		t.Fatal("member was not added to the policy")
	}

	a.postForm("/policies/"+id+"/members/"+userID+"/remove", nil, cookie)
	if in, _ := a.h.policies.IsUserInPolicyByID(ctx, id, userID); in {
		t.Fatal("member still in policy after removal")
	}
	if in, _ := a.h.policies.IsUserInPolicyByID(ctx, id, otherID); !in {
		t.Fatal("removal dropped the wrong member")
	}

	a.postForm("/policies/"+id+"/delete", nil, cookie)
	if pol, _ := a.h.policies.GetByID(ctx, id); pol != nil {
		t.Fatal("policy still present after delete")
	}
	if rec := a.get("/policies/"+id, cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("deleted policy page: got %d want 404", rec.Code)
	}
}

func TestPolicyCreateIgnoresBlankName(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	rec := a.postForm("/policies", url.Values{"name": {"   "}}, cookie)
	if got := adminLocation(rec); got != "/policies" {
		t.Fatalf("redirect: got %q want /policies", got)
	}
	policies, _ := a.h.policies.List(ctx)
	if len(policies) != 0 {
		t.Fatalf("blank name created %d policies", len(policies))
	}
}

func TestGroupLifecycleAddsAndRemovesMembers(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	ctx := context.Background()

	if rec := a.postForm("/groups", url.Values{"name": {"  "}}, cookie); adminLocation(rec) != "/groups" {
		t.Fatalf("blank group redirect: got %q", adminLocation(rec))
	}
	if groups, _ := a.h.groups.List(ctx); len(groups) != 0 {
		t.Fatalf("blank name created %d groups", len(groups))
	}

	if rec := a.postForm("/groups", url.Values{
		"name":        {"engineering"},
		"description": {"Engineers"},
	}, cookie); rec.Code != http.StatusFound {
		t.Fatalf("create group: got %d", rec.Code)
	}
	group := admSetGroupByName(t, a, "engineering")
	if group == nil {
		t.Fatal("group not stored")
	}
	if group.Description != "Engineers" {
		t.Fatalf("group description: got %q", group.Description)
	}

	userID := a.addUser(t, "dev@example.com")
	a.postForm("/groups/"+group.ID+"/members", url.Values{"user_id": {userID}}, cookie)

	names, _ := a.h.groups.GetUserGroups(ctx, userID)
	if len(names) != 1 || names[0] != "engineering" {
		t.Fatalf("user groups: %v", names)
	}

	if rec := a.postWithoutCSRF("/groups/"+group.ID+"/members/"+userID+"/remove", cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("remove without CSRF: got %d want 403", rec.Code)
	}
	if members, _ := a.h.groups.GetMembers(ctx, group.ID); len(members) != 1 {
		t.Fatal("forged request removed a group member")
	}

	a.postForm("/groups/"+group.ID+"/members/"+userID+"/remove", nil, cookie)
	if members, _ := a.h.groups.GetMembers(ctx, group.ID); len(members) != 0 {
		t.Fatalf("member remains after removal: %v", members)
	}

	a.postForm("/groups/"+group.ID+"/delete", nil, cookie)
	if g, _ := a.h.groups.GetByID(ctx, group.ID); g != nil {
		t.Fatal("group still present after delete")
	}
}
