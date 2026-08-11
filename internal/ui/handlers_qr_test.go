package ui

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type uiQRBegun struct {
	token   string
	qr      string
	binding *http.Cookie
}

func uiQRBegin(t *testing.T, u *uiHarness, query string) uiQRBegun {
	t.Helper()
	rec := u.postForm("/login/qr/begin"+query, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin status = %d, want 200", rec.Code)
	}
	var body struct {
		Token string `json:"token"`
		QR    string `json:"qr"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode begin body %q: %v", rec.Body.String(), err)
	}
	if body.Token == "" {
		t.Fatal("begin returned an empty token")
	}
	out := uiQRBegun{token: body.Token, qr: body.QR}
	for _, c := range rec.Result().Cookies() {
		if c.Name == qrBindingCookie {
			out.binding = c
		}
	}
	if out.binding == nil {
		t.Fatalf("begin did not set the %s binding cookie", qrBindingCookie)
	}
	return out
}

func uiQRPoll(u *uiHarness, token string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return u.get("/login/qr/poll?token="+url.QueryEscape(token), cookies...)
}

func uiQRStatus(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode poll body %q: %v", rec.Body.String(), err)
	}
	return out
}

func uiQRSessionCount(t *testing.T, u *uiHarness) int {
	t.Helper()
	var n int
	if err := u.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

func uiQRTokenStatus(t *testing.T, u *uiHarness, id string) string {
	t.Helper()
	tok, err := u.h.qrTokens.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get qr token: %v", err)
	}
	if tok == nil {
		t.Fatalf("qr token %s is gone", id)
	}
	return tok.Status
}

func uiQRHasSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gk_session" && c.Value != "" {
			return true
		}
	}
	return false
}

// uiQRApprove signs a user in on a second browser and approves the token there,
// mirroring the phone half of the flow.
func uiQRApprove(t *testing.T, u *uiHarness, token, userID string) {
	t.Helper()
	rec := u.postForm("/login/qr/approve", url.Values{"token": {token}}, u.signIn(t, userID))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want 200", rec.Code)
	}
	if got := uiQRTokenStatus(t, u, token); got != "approved" {
		t.Fatalf("token status after approve = %q, want approved", got)
	}
}

func TestQRBeginReturnsPNGAndStoresOnlyHashedBinding(t *testing.T) {
	u := newUIHarness(t)
	begun := uiQRBegin(t, u, "")

	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(begun.qr, prefix) {
		t.Fatalf("qr field = %.40q, want a %s data URI", begun.qr, prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(begun.qr, prefix))
	if err != nil {
		t.Fatalf("decode qr payload: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("qr payload is not a PNG image")
	}

	if !begun.binding.HttpOnly || !begun.binding.Secure {
		t.Fatalf("binding cookie must be HttpOnly and Secure, got %+v", begun.binding)
	}
	if begun.binding.Value == begun.token {
		t.Fatal("binding secret must not be the token itself")
	}

	var stored string
	if err := u.db.QueryRow(`SELECT binding FROM qr_login_tokens WHERE id=?`, begun.token).Scan(&stored); err != nil {
		t.Fatalf("read stored binding: %v", err)
	}
	if stored == begun.binding.Value {
		t.Fatal("binding secret is stored in clear")
	}
	if stored != qrBindingHash(begun.binding.Value) {
		t.Fatalf("stored binding = %q, want the hash of the cookie secret", stored)
	}
}

func TestQRPollBeforeApprovalIsPendingAndCreatesNoSession(t *testing.T) {
	u := newUIHarness(t)
	begun := uiQRBegin(t, u, "")
	before := uiQRSessionCount(t, u)

	rec := uiQRPoll(u, begun.token, begun.binding)
	if got := uiQRStatus(t, rec)["status"]; got != "pending" {
		t.Fatalf("status = %q, want pending", got)
	}
	if uiQRHasSessionCookie(rec) {
		t.Fatal("pending poll handed out a session cookie")
	}
	if after := uiQRSessionCount(t, u); after != before {
		t.Fatalf("sessions = %d, want %d, pending poll must not create a session", after, before)
	}
}

func TestQRPollIssuesSessionOnceOnly(t *testing.T) {
	u := newUIHarness(t)
	userID := u.addUser(t, "qr-once@example.com", "correct horse battery")
	begun := uiQRBegin(t, u, "")
	uiQRApprove(t, u, begun.token, userID)

	before := uiQRSessionCount(t, u)

	first := uiQRPoll(u, begun.token, begun.binding)
	body := uiQRStatus(t, first)
	if body["status"] != "approved" {
		t.Fatalf("first poll status = %q, want approved", body["status"])
	}
	if body["redirect"] == "" {
		t.Fatal("approved poll returned no redirect")
	}
	if !uiQRHasSessionCookie(first) {
		t.Fatal("approved poll did not set a session cookie")
	}
	afterFirst := uiQRSessionCount(t, u)
	if afterFirst != before+1 {
		t.Fatalf("sessions after first poll = %d, want %d", afterFirst, before+1)
	}

	second := uiQRPoll(u, begun.token, begun.binding)
	if got := uiQRStatus(t, second)["status"]; got != "expired" {
		t.Fatalf("second poll status = %q, want expired, the token is single use", got)
	}
	if uiQRHasSessionCookie(second) {
		t.Fatal("replayed poll handed out a second session cookie")
	}
	if afterSecond := uiQRSessionCount(t, u); afterSecond != afterFirst {
		t.Fatalf("sessions after replay = %d, want %d, a used token must not mint another session", afterSecond, afterFirst)
	}
	if u.auditCount("login.qr") != 1 {
		t.Fatalf("login.qr audit entries = %d, want exactly 1", u.auditCount("login.qr"))
	}
}

func TestQRPollRejectsExpiredToken(t *testing.T) {
	u := newUIHarness(t)
	userID := u.addUser(t, "qr-expired@example.com", "correct horse battery")
	begun := uiQRBegin(t, u, "")
	uiQRApprove(t, u, begun.token, userID)

	if _, err := u.db.Exec(`UPDATE qr_login_tokens SET expires_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), begun.token); err != nil {
		t.Fatalf("age token: %v", err)
	}
	before := uiQRSessionCount(t, u)

	rec := uiQRPoll(u, begun.token, begun.binding)
	if got := uiQRStatus(t, rec)["status"]; got != "expired" {
		t.Fatalf("status = %q, want expired", got)
	}
	if uiQRHasSessionCookie(rec) {
		t.Fatal("expired token handed out a session cookie")
	}
	if after := uiQRSessionCount(t, u); after != before {
		t.Fatalf("sessions = %d, want %d", after, before)
	}
	if got := uiQRTokenStatus(t, u, begun.token); got == "used" {
		t.Fatal("expired token was consumed instead of refused")
	}
}

func TestQRPollRejectsUnknownToken(t *testing.T) {
	u := newUIHarness(t)
	begun := uiQRBegin(t, u, "")
	before := uiQRSessionCount(t, u)

	for _, token := range []string{"", "not-a-token", "' OR 1=1 --", begun.token + "x"} {
		rec := uiQRPoll(u, token, begun.binding)
		if got := uiQRStatus(t, rec)["status"]; got != "expired" {
			t.Fatalf("status for token %q = %q, want expired", token, got)
		}
		if uiQRHasSessionCookie(rec) {
			t.Fatalf("token %q handed out a session cookie", token)
		}
	}
	if after := uiQRSessionCount(t, u); after != before {
		t.Fatalf("sessions = %d, want %d", after, before)
	}
}

func TestQRPollWithoutBindingCookieIsRefused(t *testing.T) {
	u := newUIHarness(t)
	userID := u.addUser(t, "qr-nobinding@example.com", "correct horse battery")
	begun := uiQRBegin(t, u, "")
	uiQRApprove(t, u, begun.token, userID)
	before := uiQRSessionCount(t, u)

	rec := uiQRPoll(u, begun.token)
	if got := uiQRStatus(t, rec)["status"]; got != "expired" {
		t.Fatalf("status = %q, want expired", got)
	}
	if uiQRHasSessionCookie(rec) {
		t.Fatal("poll without the binding cookie handed out a session cookie")
	}
	if after := uiQRSessionCount(t, u); after != before {
		t.Fatalf("sessions = %d, want %d", after, before)
	}

	owner := uiQRPoll(u, begun.token, begun.binding)
	if got := uiQRStatus(t, owner)["status"]; got != "approved" {
		t.Fatalf("owner poll status = %q, want approved, the refusal must not burn the token", got)
	}
}

func TestQRPollWithForeignBindingCookieIsRefused(t *testing.T) {
	u := newUIHarness(t)
	userID := u.addUser(t, "qr-foreign@example.com", "correct horse battery")
	victim := uiQRBegin(t, u, "")
	attacker := uiQRBegin(t, u, "")
	uiQRApprove(t, u, victim.token, userID)
	before := uiQRSessionCount(t, u)

	rec := uiQRPoll(u, victim.token, attacker.binding)
	if got := uiQRStatus(t, rec)["status"]; got != "expired" {
		t.Fatalf("status = %q, want expired", got)
	}
	if uiQRHasSessionCookie(rec) {
		t.Fatal("a foreign binding cookie claimed someone else's approval")
	}
	if after := uiQRSessionCount(t, u); after != before {
		t.Fatalf("sessions = %d, want %d", after, before)
	}

	owner := uiQRPoll(u, victim.token, victim.binding)
	if got := uiQRStatus(t, owner)["status"]; got != "approved" {
		t.Fatalf("owner poll status = %q, want approved", got)
	}
}

func TestQRApproveRefusesAnonymousAndBadCSRF(t *testing.T) {
	u := newUIHarness(t)
	userID := u.addUser(t, "qr-approve@example.com", "correct horse battery")
	begun := uiQRBegin(t, u, "")

	anon := u.get("/login/qr/approve?token=" + begun.token)
	if anon.Code != http.StatusFound {
		t.Fatalf("anonymous approve page status = %d, want 302", anon.Code)
	}
	if loc := location(anon); !strings.HasPrefix(loc, "/login?") {
		t.Fatalf("anonymous approve page redirect = %q, want the login page", loc)
	}

	form := url.Values{"token": {begun.token}, "csrf_token": {"wrong-token"}}
	bad := u.postForm("/login/qr/approve", form, u.signIn(t, userID))
	if bad.Code != http.StatusForbidden {
		t.Fatalf("approve with a mismatched CSRF token = %d, want 403", bad.Code)
	}
	if got := uiQRTokenStatus(t, u, begun.token); got != "pending" {
		t.Fatalf("token status = %q, want pending after a rejected approval", got)
	}

	before := uiQRSessionCount(t, u)
	poll := uiQRPoll(u, begun.token, begun.binding)
	if got := uiQRStatus(t, poll)["status"]; got != "pending" {
		t.Fatalf("poll status = %q, want pending", got)
	}
	if after := uiQRSessionCount(t, u); after != before {
		t.Fatalf("sessions = %d, want %d", after, before)
	}
}
