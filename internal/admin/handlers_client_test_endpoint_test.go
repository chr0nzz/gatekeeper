package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type clientTestResult struct {
	ClientID     string   `json:"client_id"`
	AuthURL      string   `json:"auth_url"`
	RedirectURIs []string `json:"redirect_uris"`
	Checks       []struct {
		Label string `json:"label"`
		OK    bool   `json:"ok"`
		Note  string `json:"note"`
	} `json:"checks"`
}

func seedTestClient(t *testing.T, a *adminHarness, clientID string, redirects []string) {
	t.Helper()
	raw, _ := json.Marshal(redirects)
	_, err := a.db.ExecContext(context.Background(),
		`INSERT INTO oidc_clients (id, client_id, client_secret, redirect_uris, name, created_at, credentials_scopes)
		 VALUES (?,?,?,?,?,?,'')`,
		clientID+"-row", clientID, "s3cret", string(raw), "Test App", 0,
	)
	if err != nil {
		t.Fatalf("seed client: %v", err)
	}
}

func fetchClientTest(t *testing.T, a *adminHarness, clientID string) clientTestResult {
	t.Helper()
	rec := a.get("/clients/"+clientID+"/test", a.signIn(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("test endpoint returned %d, want 200", rec.Code)
	}
	var out clientTestResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func TestClientTestLinkUsesTheRealAuthorizationEndpoint(t *testing.T) {
	a := newAdminHarness(t)
	seedTestClient(t, a, "grafana", []string{"https://grafana.example.com/login/generic_oauth"})

	got := fetchClientTest(t, a, "grafana")
	if got.AuthURL == "" {
		t.Fatal("no authorization URL was generated")
	}
	if strings.Contains(got.AuthURL, "/oauth/authorize") {
		t.Errorf("link points at the unrouted /oauth/authorize endpoint: %s", got.AuthURL)
	}

	u, err := url.Parse(got.AuthURL)
	if err != nil {
		t.Fatalf("generated an unparseable URL %q: %v", got.AuthURL, err)
	}
	if u.Path != "/authorize" {
		t.Errorf("authorize path = %q, want /authorize", u.Path)
	}
}

func TestClientTestLinkEncodesRedirectURI(t *testing.T) {
	a := newAdminHarness(t)
	redirect := "https://app.example.com/callback?tenant=acme&next=/home"
	seedTestClient(t, a, "withquery", []string{redirect})

	got := fetchClientTest(t, a, "withquery")
	u, err := url.Parse(got.AuthURL)
	if err != nil {
		t.Fatalf("unparseable URL: %v", err)
	}
	if u.Query().Get("redirect_uri") != redirect {
		t.Errorf("redirect_uri decoded to %q, want %q", u.Query().Get("redirect_uri"), redirect)
	}
	if u.Query().Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", u.Query().Get("response_type"))
	}
	if u.Query().Get("scope") != "openid profile email" {
		t.Errorf("scope = %q, want openid profile email", u.Query().Get("scope"))
	}
}

func TestClientTestReportsMissingSecretAndRedirect(t *testing.T) {
	a := newAdminHarness(t)
	_, err := a.db.ExecContext(context.Background(),
		`INSERT INTO oidc_clients (id, client_id, client_secret, redirect_uris, name, created_at, credentials_scopes)
		 VALUES ('bare-row','bare','','[]','Bare',0,'')`)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	got := fetchClientTest(t, a, "bare")
	if got.AuthURL != "" {
		t.Error("a client with no redirect URI should not produce a sign-in link")
	}
	failed := map[string]bool{}
	for _, c := range got.Checks {
		if !c.OK {
			failed[c.Label] = true
		}
	}
	for _, label := range []string{"Client secret configured", "Redirect URI configured"} {
		if !failed[label] {
			t.Errorf("check %q passed for a client that is missing it", label)
		}
	}
}

func TestClientTestRequiresAdminSession(t *testing.T) {
	a := newAdminHarness(t)
	seedTestClient(t, a, "private", []string{"https://app.example.com/cb"})

	rec := a.get("/clients/private/test")
	if rec.Code == http.StatusOK {
		t.Error("the client test endpoint served an anonymous request")
	}
}

func TestClientTestReportsTheAttachedPolicy(t *testing.T) {
	a := newAdminHarness(t)
	seedTestClient(t, a, "filebrowser", []string{"https://fb.example.com/api/auth/oidc/callback"})

	ctx := context.Background()
	if _, err := a.db.ExecContext(ctx,
		`INSERT INTO policies (id, name, description, created_at) VALUES ('pol-admin','admin','Admins only',0)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if _, err := a.db.ExecContext(ctx,
		`UPDATE oidc_clients SET policy_id='pol-admin' WHERE client_id='filebrowser'`); err != nil {
		t.Fatalf("attach policy: %v", err)
	}

	got := fetchClientTest(t, a, "filebrowser")
	var note string
	for _, c := range got.Checks {
		if c.Label == "Access policy" {
			note = c.Note
		}
	}
	if !strings.Contains(note, "admin") {
		t.Errorf("access policy note = %q, want it to name the attached policy", note)
	}
	if strings.Contains(strings.ToLower(note), "no policy assigned") {
		t.Error("a client with a policy attached was reported as unrestricted")
	}
}

func TestClientTestReportsNoPolicyWhenNoneAttached(t *testing.T) {
	a := newAdminHarness(t)
	seedTestClient(t, a, "openclient", []string{"https://open.example.com/cb"})

	got := fetchClientTest(t, a, "openclient")
	for _, c := range got.Checks {
		if c.Label == "Access policy" && !strings.Contains(strings.ToLower(c.Note), "no policy") {
			t.Errorf("unrestricted client reported policy %q", c.Note)
		}
	}
}

func TestClientTestReportsRedirectURIsAndApplicationType(t *testing.T) {
	a := newAdminHarness(t)
	seedTestClient(t, a, "immich", []string{
		"https://immich.example.com/auth/login",
		"app.immich:///oauth-callback",
	})

	got := fetchClientTest(t, a, "immich")
	if len(got.RedirectURIs) != 2 {
		t.Fatalf("returned %d redirect URIs, want 2", len(got.RedirectURIs))
	}
	var appType string
	for _, c := range got.Checks {
		if c.Label == "Application type" {
			appType = c.Note
		}
	}
	if !strings.Contains(appType, "Native") {
		t.Errorf("application type = %q, want it to report Native for a custom scheme", appType)
	}

	a2 := newAdminHarness(t)
	seedTestClient(t, a2, "webonly", []string{"https://web.example.com/cb"})
	for _, c := range fetchClientTest(t, a2, "webonly").Checks {
		if c.Label == "Application type" && !strings.Contains(c.Note, "Web") {
			t.Errorf("application type = %q, want Web", c.Note)
		}
	}
}
