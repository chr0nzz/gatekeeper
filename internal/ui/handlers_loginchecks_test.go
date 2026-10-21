package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func lcAuthRequest(t *testing.T, u *uiHarness, policyID string) string {
	t.Helper()
	u.db.Exec(`INSERT INTO oidc_clients (id, client_id, client_secret, redirect_uris, name, created_at, policy_id)
		VALUES ('c1','eng-client','x','["https://eng.example.com/cb"]','Eng',0,?)`, policyID)
	req, err := u.h.oidcStorage.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:     "eng-client",
		RedirectURI:  "https://eng.example.com/cb",
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}
	return req.GetID()
}

func lcQRLogin(t *testing.T, u *uiHarness, userID, query string, beforePoll func()) string {
	t.Helper()
	begun := uiQRBegin(t, u, query)
	uiQRApprove(t, u, begun.token, userID)
	if beforePoll != nil {
		beforePoll()
	}
	body := uiQRStatus(t, uiQRPoll(u, begun.token, begun.binding))
	if body["status"] != "approved" {
		t.Fatalf("poll status = %q, want approved", body["status"])
	}
	return body["redirect"]
}

func TestSecondaryLoginEnforcesClientPolicy(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "outsider@example.com", "correct horse battery")
	reqID := lcAuthRequest(t, u, "eng-only")

	target := lcQRLogin(t, u, id, "?oidc_request="+reqID, nil)
	if !strings.HasPrefix(target, "/login/denied") {
		t.Fatalf("redirect = %q, want /login/denied", target)
	}
	var done int
	u.db.QueryRow(`SELECT done FROM oidc_auth_requests WHERE id=?`, reqID).Scan(&done)
	if done != 0 {
		t.Fatal("auth request was completed for a user outside the client policy")
	}
}

func TestSecondaryLoginAllowsPolicyMember(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "engineer@example.com", "correct horse battery")
	reqID := lcAuthRequest(t, u, "eng-only")
	u.h.policies.AddMember(context.Background(), "eng-only", id)

	if target := lcQRLogin(t, u, id, "?oidc_request="+reqID, nil); !strings.HasPrefix(target, "/authorize/callback") {
		t.Fatalf("redirect = %q, want /authorize/callback", target)
	}
}

func TestSecondaryLoginEnforcesForcedPasswordChange(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "forced@example.com", "correct horse battery")
	u.db.Exec(`UPDATE users SET force_password_change=1 WHERE id=?`, id)

	if target := lcQRLogin(t, u, id, "", nil); !strings.HasPrefix(target, "/profile/password?forced=1") {
		t.Fatalf("redirect = %q, want the forced password change page", target)
	}
}

func TestSecondaryLoginRefusesDisabledUser(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "disabled@example.com", "correct horse battery")

	before := 0
	target := lcQRLogin(t, u, id, "", func() {
		u.users.SetDisabled(context.Background(), id, true)
		before = uiQRSessionCount(t, u)
	})
	if target != "/login?social_err=account_disabled" {
		t.Fatalf("redirect = %q, want account_disabled", target)
	}
	if after := uiQRSessionCount(t, u); after != before {
		t.Fatalf("sessions = %d, want %d, a disabled user must not gain a session", after, before)
	}
}

func lcLinkCookie(t *testing.T, u *uiHarness, userID string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	link := pendingSocialLink{UserID: userID, Provider: "discord", ProviderID: "d-1", Email: "owner@example.com", Expires: time.Now().Add(time.Minute).Unix()}
	if err := u.h.setPendingSocialLink(rec, link); err != nil {
		t.Fatalf("set pending link: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == socialLinkCookie {
			return c
		}
	}
	t.Fatal("no pending link cookie was set")
	return nil
}

func TestSocialLinkCompletesOnlyAfterOwnerSignsIn(t *testing.T) {
	u := newUIHarness(t)
	owner := u.addUser(t, "owner@example.com", "correct horse battery")
	other := u.addUser(t, "other@example.com", "correct horse battery")
	link := lcLinkCookie(t, u, owner)

	u.get("/login", u.signIn(t, other), link)
	if acc, _ := u.h.socialAccounts.FindByProvider(context.Background(), "discord", "d-1"); acc != nil {
		t.Fatal("pending link was completed by a different user")
	}

	u.get("/login", u.signIn(t, owner), link)
	acc, _ := u.h.socialAccounts.FindByProvider(context.Background(), "discord", "d-1")
	if acc == nil || acc.UserID != owner {
		t.Fatal("pending link was not completed after the owner signed in")
	}
}

func TestDeleteUserRemovesCredentials(t *testing.T) {
	u := newUIHarness(t)
	ctx := context.Background()
	id := u.addUser(t, "gone@example.com", "correct horse battery")
	u.db.Exec(`INSERT INTO passkeys (id, user_id, name, credential_id, credential_data, created_at) VALUES ('p1',?,'key','abcd','{}',0)`, id)
	u.h.socialAccounts.Create(ctx, id, "discord", "d-2", "gone@example.com")

	if err := u.users.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for _, table := range []string{"passkeys", "social_accounts"} {
		var n int
		u.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE user_id=?`, id).Scan(&n)
		if n != 0 {
			t.Errorf("%s still has %d rows for the deleted user", table, n)
		}
	}
}
