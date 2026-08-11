package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

func uiAcctUser(t *testing.T, h *uiHarness, userID string) *queries.User {
	t.Helper()
	u, err := h.users.GetByID(context.Background(), userID)
	if err != nil || u == nil {
		t.Fatalf("load user %s: %v", userID, err)
	}
	return u
}

// uiAcctSessionID resolves the server-side session handle behind a cookie, which
// is the identifier the revoke routes take.
func uiAcctSessionID(t *testing.T, h *uiHarness, c *http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	_, id, err := h.sessions.Get(req)
	if err != nil || id == "" {
		t.Fatalf("resolve session id: %v", err)
	}
	return id
}

func uiAcctRegisterForm(email, password string) url.Values {
	return url.Values{
		"email":            {email},
		"password":         {password},
		"confirm_password": {password},
	}
}

func uiAcctCountUsers(t *testing.T, h *uiHarness, email string) int {
	t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE email=?`, email).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func TestHomeRequiresSessionAndRendersProfile(t *testing.T) {
	h := newUIHarness(t)

	rec := h.get("/")
	if rec.Code != http.StatusFound || location(rec) != "/login" {
		t.Fatalf("anonymous home = %d %q, want 302 /login", rec.Code, location(rec))
	}

	rec = h.get("/", &http.Cookie{Name: "gk_session", Value: "not-a-real-token"})
	if rec.Code != http.StatusFound || location(rec) != "/login" {
		t.Fatalf("forged cookie home = %d %q, want 302 /login", rec.Code, location(rec))
	}

	id := h.addUser(t, "owner@example.com", "correct-horse-battery")
	rec = h.get("/", h.signIn(t, id))
	if rec.Code != http.StatusOK {
		t.Fatalf("signed-in home = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "owner@example.com") {
		t.Fatal("home page did not render the signed-in account")
	}
}

func TestProfileNameUpdatePersists(t *testing.T) {
	h := newUIHarness(t)
	id := h.addUser(t, "ada@example.com", "correct-horse-battery")

	rec := h.postForm("/profile/name", url.Values{"display_name": {"Intruder"}})
	if rec.Code != http.StatusFound || location(rec) != "/login" {
		t.Fatalf("anonymous rename = %d %q, want 302 /login", rec.Code, location(rec))
	}
	if got := uiAcctUser(t, h, id).DisplayName; got != "" {
		t.Fatalf("anonymous rename changed the name to %q", got)
	}

	cookie := h.signIn(t, id)
	rec = h.postForm("/profile/name", url.Values{"display_name": {"  Ada Lovelace  "}}, cookie)
	if rec.Code != http.StatusFound || location(rec) != "/" {
		t.Fatalf("rename = %d %q, want 302 /", rec.Code, location(rec))
	}
	if got := uiAcctUser(t, h, id).DisplayName; got != "Ada Lovelace" {
		t.Fatalf("display name = %q, want trimmed %q", got, "Ada Lovelace")
	}
	if body := h.get("/", cookie).Body.String(); !strings.Contains(body, "Ada Lovelace") {
		t.Fatal("home page did not render the new display name")
	}
}

func TestChangePasswordEnforcesConfiguredMinLength(t *testing.T) {
	h := newUIHarness(t)
	const old = "correct-horse-battery"
	id := h.addUser(t, "policy@example.com", old)
	cookie := h.signIn(t, id)
	h.set(t, "password_min_length", "16")

	short := "twelvechars1"
	rec := h.postForm("/profile/password", url.Values{
		"current_password": {old},
		"new_password":     {short},
		"confirm_password": {short},
	}, cookie)
	if !strings.Contains(rec.Body.String(), "at least 16 characters") {
		t.Fatalf("short password was not rejected by the policy: %s", rec.Body.String())
	}
	if err := auth.VerifyPassword(old, uiAcctUser(t, h, id).PasswordHash); err != nil {
		t.Fatal("a rejected change still replaced the stored password")
	}

	long := "sixteen-plus-characters"
	rec = h.postForm("/profile/password", url.Values{
		"current_password": {old},
		"new_password":     {long},
		"confirm_password": {long},
	}, cookie)
	if !strings.Contains(rec.Body.String(), "Password changed") {
		t.Fatalf("compliant password was not accepted: %s", rec.Body.String())
	}
	stored := uiAcctUser(t, h, id).PasswordHash
	if strings.Contains(stored, long) {
		t.Fatal("password stored in clear")
	}
	if err := auth.VerifyPassword(long, stored); err != nil {
		t.Fatalf("new password does not verify: %v", err)
	}
	if err := auth.VerifyPassword(old, stored); err == nil {
		t.Fatal("old password still verifies after a change")
	}
	if h.auditCount("password.changed") != 1 {
		t.Fatalf("password change audit entries = %d, want 1", h.auditCount("password.changed"))
	}
}

func TestChangePasswordRequiresCorrectCurrentPassword(t *testing.T) {
	h := newUIHarness(t)
	const old = "correct-horse-battery"
	id := h.addUser(t, "current@example.com", old)
	cookie := h.signIn(t, id)

	attacker := "attacker-chosen-password"
	rec := h.postForm("/profile/password", url.Values{
		"current_password": {"wrong-horse-battery"},
		"new_password":     {attacker},
		"confirm_password": {attacker},
	}, cookie)
	if !strings.Contains(rec.Body.String(), "Current password is incorrect") {
		t.Fatalf("wrong current password was not reported: %s", rec.Body.String())
	}
	stored := uiAcctUser(t, h, id).PasswordHash
	if err := auth.VerifyPassword(attacker, stored); err == nil {
		t.Fatal("password was replaced without the current password")
	}
	if err := auth.VerifyPassword(old, stored); err != nil {
		t.Fatal("original password no longer verifies")
	}
	if h.auditCount("password.changed") != 0 {
		t.Fatal("a failed change was audited as a password change")
	}
}

func TestChangePasswordRejectsMismatchedConfirmation(t *testing.T) {
	h := newUIHarness(t)
	const old = "correct-horse-battery"
	id := h.addUser(t, "confirm@example.com", old)
	cookie := h.signIn(t, id)

	rec := h.postForm("/profile/password", url.Values{
		"current_password": {old},
		"new_password":     {"first-choice-password"},
		"confirm_password": {"second-choice-password"},
	}, cookie)
	if !strings.Contains(rec.Body.String(), "Passwords do not match") {
		t.Fatalf("mismatched confirmation was not reported: %s", rec.Body.String())
	}
	if err := auth.VerifyPassword("first-choice-password", uiAcctUser(t, h, id).PasswordHash); err == nil {
		t.Fatal("password changed despite a mismatched confirmation")
	}
}

func TestSessionRevokeEndsOnlyTheTargetSession(t *testing.T) {
	h := newUIHarness(t)
	id := h.addUser(t, "sessions@example.com", "correct-horse-battery")
	keep := h.signIn(t, id)
	drop := h.signIn(t, id)
	dropID := uiAcctSessionID(t, h, drop)

	listed, err := h.sessions.ListUserSessions(context.Background(), id, uiAcctSessionID(t, h, keep))
	if err != nil || len(listed) != 2 {
		t.Fatalf("listed sessions = %d (%v), want 2", len(listed), err)
	}

	rec := h.postForm("/session/"+dropID+"/revoke", nil, keep)
	if rec.Code != http.StatusFound || location(rec) != "/" {
		t.Fatalf("revoke = %d %q, want 302 /", rec.Code, location(rec))
	}

	if rec := h.get("/", drop); rec.Code != http.StatusFound || location(rec) != "/login" {
		t.Fatalf("revoked session still authenticates: %d %q", rec.Code, location(rec))
	}
	if rec := h.get("/", keep); rec.Code != http.StatusOK {
		t.Fatalf("surviving session = %d, want 200", rec.Code)
	}
	if h.auditCount("session.revoked") != 1 {
		t.Fatalf("session revoke audit entries = %d, want 1", h.auditCount("session.revoked"))
	}
}

func TestSessionRevokeCannotTouchAnotherUsersSession(t *testing.T) {
	h := newUIHarness(t)
	victimID := h.addUser(t, "victim@example.com", "correct-horse-battery")
	victim := h.signIn(t, victimID)
	victimSession := uiAcctSessionID(t, h, victim)

	attacker := h.signIn(t, h.addUser(t, "attacker@example.com", "correct-horse-battery"))
	if rec := h.postForm("/session/"+victimSession+"/revoke", nil, attacker); rec.Code != http.StatusFound {
		t.Fatalf("cross-user revoke = %d, want 302", rec.Code)
	}
	if rec := h.get("/", victim); rec.Code != http.StatusOK {
		t.Fatalf("another user revoked the victim session: %d", rec.Code)
	}

	if rec := h.postForm("/session/"+victimSession+"/revoke", nil); rec.Code != http.StatusFound || location(rec) != "/login" {
		t.Fatalf("anonymous revoke = %d %q, want 302 /login", rec.Code, location(rec))
	}
	if rec := h.get("/", victim); rec.Code != http.StatusOK {
		t.Fatalf("anonymous request revoked the victim session: %d", rec.Code)
	}
}

func TestRevokeOtherSessionsKeepsCurrentOnly(t *testing.T) {
	h := newUIHarness(t)
	id := h.addUser(t, "manysessions@example.com", "correct-horse-battery")
	keep := h.signIn(t, id)
	first := h.signIn(t, id)
	second := h.signIn(t, id)

	if rec := h.postForm("/sessions/revoke-others", nil, keep); rec.Code != http.StatusFound {
		t.Fatalf("revoke others = %d, want 302", rec.Code)
	}
	for name, c := range map[string]*http.Cookie{"first": first, "second": second} {
		if rec := h.get("/", c); rec.Code != http.StatusFound || location(rec) != "/login" {
			t.Fatalf("%s session survived: %d %q", name, rec.Code, location(rec))
		}
	}
	if rec := h.get("/", keep); rec.Code != http.StatusOK {
		t.Fatalf("current session = %d, want 200", rec.Code)
	}
}

func TestRegisterDisabledRefusesSignup(t *testing.T) {
	h := newUIHarness(t)
	h.set(t, "registration_mode", "disabled")

	if rec := h.get("/register"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /register = %d, want 404", rec.Code)
	}
	rec := h.postForm("/register", uiAcctRegisterForm("nobody@example.com", "a-perfectly-fine-secret"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /register = %d, want 404", rec.Code)
	}
	if n := uiAcctCountUsers(t, h, "nobody@example.com"); n != 0 {
		t.Fatalf("disabled registration created %d users", n)
	}
}

func TestRegisterOpenModeCreatesAccount(t *testing.T) {
	h := newUIHarness(t)
	h.set(t, "registration_mode", "open")
	const password = "a-perfectly-fine-secret"

	rec := h.postForm("/register", uiAcctRegisterForm("New.User@Example.com", password))
	if rec.Code != http.StatusFound || location(rec) != "/" {
		t.Fatalf("register = %d %q, want 302 /", rec.Code, location(rec))
	}

	user, err := h.users.GetByEmail(context.Background(), "new.user@example.com")
	if err != nil || user == nil {
		t.Fatalf("registered user was not created: %v", err)
	}
	if strings.Contains(user.PasswordHash, password) {
		t.Fatal("password stored in clear")
	}
	if err := auth.VerifyPassword(password, user.PasswordHash); err != nil {
		t.Fatalf("registered password does not verify: %v", err)
	}

	signedIn := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gk_session" && c.Value != "" {
			signedIn = true
		}
	}
	if !signedIn {
		t.Fatal("registration did not sign the new user in")
	}
}

func TestRegisterRejectsPasswordBelowPolicy(t *testing.T) {
	h := newUIHarness(t)
	h.set(t, "registration_mode", "open")
	h.set(t, "password_min_length", "16")

	rec := h.postForm("/register", uiAcctRegisterForm("weak@example.com", "twelvechars1"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "at least 16 characters") {
		t.Fatalf("weak password was not rejected: %d %s", rec.Code, rec.Body.String())
	}
	if n := uiAcctCountUsers(t, h, "weak@example.com"); n != 0 {
		t.Fatalf("weak password created %d users", n)
	}
}

func TestRegisterDoesNotRevealExistingAccount(t *testing.T) {
	h := newUIHarness(t)
	h.set(t, "registration_mode", "approval")
	const original = "the-original-secret"
	existing := h.addUser(t, "taken@example.com", original)
	before := uiAcctUser(t, h, existing).PasswordHash

	fresh := h.postForm("/register", uiAcctRegisterForm("unknown@example.com", "a-perfectly-fine-secret"))
	dup := h.postForm("/register", uiAcctRegisterForm("taken@example.com", "attacker-chosen-secret"))

	if dup.Code != fresh.Code {
		t.Fatalf("existing email answered with %d, fresh email with %d", dup.Code, fresh.Code)
	}
	if dup.Body.String() != fresh.Body.String() {
		t.Fatal("the response for an existing email differs from a fresh one, which discloses the account")
	}
	if n := uiAcctCountUsers(t, h, "taken@example.com"); n != 1 {
		t.Fatalf("rows for the existing email = %d, want 1", n)
	}
	after := uiAcctUser(t, h, existing).PasswordHash
	if after != before {
		t.Fatal("re-registering an existing email replaced the stored password")
	}
	if err := auth.VerifyPassword("attacker-chosen-secret", after); err == nil {
		t.Fatal("attacker password now signs in as the existing account")
	}
	if err := auth.VerifyPassword(original, after); err != nil {
		t.Fatal("original password no longer verifies")
	}
}
