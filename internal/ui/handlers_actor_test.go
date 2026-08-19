package ui

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func actorOfLatest(t *testing.T, u *uiHarness, event string) string {
	t.Helper()
	var actor string
	u.db.QueryRow(`SELECT COALESCE(actor_id,'') FROM audit_log WHERE event=? ORDER BY created_at DESC LIMIT 1`, event).Scan(&actor)
	return actor
}

func TestOIDCSignInRecordsTheClientName(t *testing.T) {
	ctx := context.Background()
	u := newUIHarness(t)
	id := u.addUser(t, "app-user@example.com", "correct-horse-battery-staple")

	u.db.Exec(`INSERT INTO oidc_clients (id, client_id, client_secret, redirect_uris, name, created_at)
		VALUES ('c1','immich-client','x','["https://photos.example.com/cb"]','Immich',0)`)
	req, err := u.h.oidcStorage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "immich-client",
		RedirectURI:  "https://photos.example.com/cb",
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	cookie := u.signIn(t, id)
	rec := u.get("/login?oidc_request="+req.GetID(), cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if actor := actorOfLatest(t, u, "login.success"); actor != "Immich" {
		t.Errorf("login.success actor = %q, want Immich", actor)
	}
	if detail := lmAuditDetail(t, u, "login.success"); detail != "sso" {
		t.Errorf("login.success detail = %q, want sso", detail)
	}
}

func TestForwardAuthSignInRecordsTheSiteHost(t *testing.T) {
	ctx := context.Background()
	u := newUIHarness(t)
	id := u.addUser(t, "site-user@example.com", "")
	u.db.Exec(`UPDATE users SET passwordless_enabled=1 WHERE id=?`, id)

	rec := u.postForm("/login", url.Values{
		"email":        {"site-user@example.com"},
		"login_mode":   {"passwordless"},
		"redirect_uri": {"https://radarr.example.com/movies"},
	})
	cookie := uiAuthCookie(rec, "gk_session")

	u.db.Exec(`DELETE FROM otps WHERE user_id=?`, id)
	code, _ := u.otps.Issue(ctx, id)
	u.postForm("/login/otp", url.Values{"code": {code}}, cookie)

	if actor := actorOfLatest(t, u, "login.success"); actor != "radarr.example.com" {
		t.Errorf("login.success actor = %q, want radarr.example.com", actor)
	}
}
