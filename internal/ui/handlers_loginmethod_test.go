package ui

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func lmAuditDetail(t *testing.T, u *uiHarness, event string) string {
	t.Helper()
	var detail string
	u.db.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE event=? ORDER BY created_at DESC LIMIT 1`, event).Scan(&detail)
	return detail
}

func TestSSOReuseIsNotRecordedAsAPasswordLogin(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "sso@example.com", "correct-horse-battery-staple")
	cookie := u.signIn(t, id)

	rec := u.get("/login?oidc_request=req-from-a-client", cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if n := u.auditCount("login.success"); n != 1 {
		t.Fatalf("login.success rows = %d, want 1", n)
	}
	if detail := lmAuditDetail(t, u, "login.success"); detail != "sso" {
		t.Errorf("login.success detail = %q, want sso", detail)
	}
}

func TestPasswordlessLoginIsNotRecordedAsAPasswordLogin(t *testing.T) {
	ctx := context.Background()
	u := newUIHarness(t)
	id := u.addUser(t, "nopass@example.com", "")
	u.db.Exec(`UPDATE users SET passwordless_enabled=1 WHERE id=?`, id)

	rec := u.postForm("/login", url.Values{
		"email":      {"nopass@example.com"},
		"login_mode": {"passwordless"},
	})
	if loc := location(rec); loc != "/login/otp" {
		t.Fatalf("location = %q, want /login/otp", loc)
	}
	cookie := uiAuthCookie(rec, "gk_session")
	if data := uiAuthSessionData(t, u, cookie); data.LoginMethod != "passwordless" {
		t.Fatalf("session LoginMethod = %q, want passwordless", data.LoginMethod)
	}

	u.db.Exec(`DELETE FROM otps WHERE user_id=?`, id)
	code, err := u.otps.Issue(ctx, id)
	if err != nil {
		t.Fatalf("issue otp: %v", err)
	}
	u.postForm("/login/otp", url.Values{"code": {code}}, cookie)

	if n := u.auditCount("login.success"); n != 1 {
		t.Fatalf("login.success rows = %d, want 1", n)
	}
	if detail := lmAuditDetail(t, u, "login.success"); detail != "passwordless" {
		t.Errorf("login.success detail = %q, want passwordless", detail)
	}
}

func TestPasswordPlusOTPLoginIsRecordedAsPassword(t *testing.T) {
	ctx := context.Background()
	u := newUIHarness(t)
	id := u.addUser(t, "haspass@example.com", "correct-horse-battery-staple")

	rec := u.postForm("/login", url.Values{
		"email":    {"haspass@example.com"},
		"password": {"correct-horse-battery-staple"},
	})
	cookie := uiAuthCookie(rec, "gk_session")
	if data := uiAuthSessionData(t, u, cookie); data.LoginMethod != "password" {
		t.Fatalf("session LoginMethod = %q, want password", data.LoginMethod)
	}

	u.db.Exec(`DELETE FROM otps WHERE user_id=?`, id)
	code, _ := u.otps.Issue(ctx, id)
	u.postForm("/login/otp", url.Values{"code": {code}}, cookie)

	if detail := lmAuditDetail(t, u, "login.success"); detail != "password" {
		t.Errorf("login.success detail = %q, want password", detail)
	}
}

func TestTrustedDeviceLoginWritesExactlyOneAuditRow(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, "trusted@example.com", "correct-horse-battery-staple")

	trustRec := newRecorder()
	if err := u.h.trustedDevices.Trust(trustRec, newGetRequest("/"), id); err != nil {
		t.Fatalf("trust device: %v", err)
	}

	form := url.Values{
		"email":    {"trusted@example.com"},
		"password": {"correct-horse-battery-staple"},
	}
	rec := u.postForm("/login", form, trustRec.Result().Cookies()...)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if n := u.auditCount("login.success"); n != 1 {
		t.Errorf("login.success rows = %d, want exactly 1", n)
	}
	if detail := lmAuditDetail(t, u, "login.success"); detail != "trusted-device" {
		t.Errorf("login.success detail = %q, want trusted-device", detail)
	}
}
