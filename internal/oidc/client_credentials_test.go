package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func oidcTestServer(t *testing.T) (*httptest.Server, *Storage) {
	t.Helper()
	conn := oidcTestDB(t)
	s := NewStorage(conn, "https://auth.example.com")
	if err := s.EnsureSigningKey(t.Context()); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO oidc_clients (id, client_id, client_secret, redirect_uris, name, created_at, credentials_scopes)
		VALUES ('row1','svc','s3cret','[]','Service',0,'openid email')`); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	provider, err := op.NewProvider(&op.Config{CryptoKey: [32]byte{1}}, s, op.StaticIssuer("https://auth.example.com"), op.WithAllowInsecure())
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)
	return srv, s
}

func postClientForm(t *testing.T, target string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc", "s3cret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	var body map[string]any
	json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

func TestClientCredentialsTokenIsIssuedAndIntrospects(t *testing.T) {
	srv, s := oidcTestServer(t)

	code, tok := postClientForm(t, srv.URL+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"openid email"}})
	access, _ := tok["access_token"].(string)
	if code != http.StatusOK || access == "" {
		t.Fatalf("token: status %d body %v", code, tok)
	}

	_, active := postClientForm(t, srv.URL+"/oauth/introspect", url.Values{"token": {access}})
	if active["active"] != true || active["sub"] != "svc" || active["client_id"] != "svc" {
		t.Errorf("introspect = %v, want active with sub and client_id svc", active)
	}
	if _, ok := active["email"]; ok {
		t.Errorf("machine token reported an email: %v", active)
	}

	if _, err := s.db.Exec(`DELETE FROM oidc_tokens WHERE client_id='svc'`); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, gone := postClientForm(t, srv.URL+"/oauth/introspect", url.Values{"token": {access}})
	if gone["active"] != false {
		t.Errorf("introspect after revoke = %v, want inactive", gone)
	}
}

func TestMachineTokenCannotBeClaimedByAnotherSubject(t *testing.T) {
	srv, s := oidcTestServer(t)
	code, tok := postClientForm(t, srv.URL+"/oauth/token", url.Values{"grant_type": {"client_credentials"}})
	if code != http.StatusOK {
		t.Fatalf("token: status %d body %v", code, tok)
	}
	var id string
	if err := s.db.QueryRow(`SELECT id FROM oidc_tokens WHERE client_id='svc'`).Scan(&id); err != nil {
		t.Fatalf("read token: %v", err)
	}
	if _, err := s.activeAccessToken(t.Context(), id, "someone-else"); err == nil {
		t.Error("machine token accepted for a different subject")
	}
}
