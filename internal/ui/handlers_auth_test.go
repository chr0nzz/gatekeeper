package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
)

const (
	uiAuthEmail    = "member@example.com"
	uiAuthPassword = "correct-horse-battery-42"
)

func uiAuthCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

func uiAuthSessionData(t *testing.T, u *uiHarness, c *http.Cookie) *auth.SessionData {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	data, _, err := u.sessions.Get(req)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	return data
}

func uiAuthDetails(t *testing.T, u *uiHarness, event string) []string {
	t.Helper()
	rows, err := u.db.Query(`SELECT COALESCE(detail,'') FROM audit_log WHERE event=?`, event)
	if err != nil {
		t.Fatalf("query audit details: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatalf("scan audit detail: %v", err)
		}
		out = append(out, d)
	}
	return out
}

func uiAuthAuditMentions(t *testing.T, u *uiHarness, needle string) bool {
	t.Helper()
	rows, err := u.db.Query(`SELECT id, event, COALESCE(user_id,''), COALESCE(actor_id,''), COALESCE(ip,''), COALESCE(detail,'') FROM audit_log`)
	if err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, event, userID, actorID, ip, detail string
		if err := rows.Scan(&id, &event, &userID, &actorID, &ip, &detail); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		if strings.Contains(id+event+userID+actorID+ip+detail, needle) {
			return true
		}
	}
	return false
}

func uiAuthSessionRows(t *testing.T, u *uiHarness) int {
	t.Helper()
	var n int
	if err := u.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

func TestGetLoginServesCredentialFormToAnonymousVisitor(t *testing.T) {
	u := newUIHarness(t)

	rec := u.get("/login")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`name="email"`, `name="password"`, `action="/login"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %s", want)
		}
	}
}

func TestGetLoginRedirectsSignedInUserInsteadOfShowingForm(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, uiAuthEmail, uiAuthPassword)
	cookie := u.signIn(t, id)

	rec := u.get("/login", cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := location(rec); loc != "/" {
		t.Errorf("location = %q, want /", loc)
	}
	if strings.Contains(rec.Body.String(), `name="password"`) {
		t.Error("signed-in user was served the credential form")
	}
}

func TestPostLoginRejectsWrongPasswordAndUnknownEmailWithOneMessage(t *testing.T) {
	u := newUIHarness(t)
	u.addUser(t, uiAuthEmail, uiAuthPassword)

	wrongPass := u.postForm("/login", url.Values{
		"email":    {uiAuthEmail},
		"password": {uiAuthPassword + "-nope"},
	})
	unknown := u.postForm("/login", url.Values{
		"email":    {"ghost@example.com"},
		"password": {uiAuthPassword},
	})

	for name, rec := range map[string]*httptest.ResponseRecorder{"wrong password": wrongPass, "unknown email": unknown} {
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Invalid credentials") {
			t.Errorf("%s: response did not reject the attempt", name)
		}
		if c := uiAuthCookie(rec, "gk_session"); c != nil {
			t.Errorf("%s: a session cookie was issued", name)
		}
	}
	if n := uiAuthSessionRows(t, u); n != 0 {
		t.Errorf("sessions created = %d, want 0", n)
	}
	if wrongPass.Body.String() != unknown.Body.String() {
		t.Error("rejection pages differ, which lets an attacker enumerate accounts")
	}
	if u.auditCount(audit.EventLoginSuccess) != 0 {
		t.Error("a failed sign-in was audited as a success")
	}
}

func TestPostLoginWithValidPasswordStopsAtSecondFactor(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, uiAuthEmail, uiAuthPassword)

	rec := u.postForm("/login", url.Values{
		"email":    {uiAuthEmail},
		"password": {uiAuthPassword},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := location(rec); loc != "/login/otp" {
		t.Fatalf("location = %q, want /login/otp", loc)
	}

	cookie := uiAuthCookie(rec, "gk_session")
	if cookie == nil {
		t.Fatal("no session cookie was issued")
	}
	data := uiAuthSessionData(t, u, cookie)
	if data == nil {
		t.Fatal("session cookie does not resolve to a session")
	}
	if data.UserID != id {
		t.Errorf("session user = %q, want %q", data.UserID, id)
	}
	if !data.PendingOTP {
		t.Error("session is fully authenticated before the second factor")
	}
	if u.auditCount(audit.EventOTPSent) != 1 {
		t.Errorf("otp.sent rows = %d, want 1", u.auditCount(audit.EventOTPSent))
	}
	if u.auditCount(audit.EventLoginSuccess) != 0 {
		t.Error("login.success recorded before the second factor")
	}
}

func TestFailedLoginAuditsReasonAndNeverStoresTheSubmittedPassword(t *testing.T) {
	u := newUIHarness(t)
	u.addUser(t, uiAuthEmail, uiAuthPassword)
	const typed = "hunter2-zzz-unique-secret"

	u.postForm("/login", url.Values{
		"email":    {"ghost@example.com"},
		"password": {typed},
	})
	u.postForm("/login", url.Values{
		"email":    {uiAuthEmail},
		"password": {typed},
	})

	details := uiAuthDetails(t, u, audit.EventLoginFailure)
	if len(details) != 2 {
		t.Fatalf("login.failure rows = %d, want 2", len(details))
	}
	joined := strings.Join(details, "|")
	if !strings.Contains(joined, "unknown email") {
		t.Errorf("unknown email reason not audited, got %q", joined)
	}
	if !strings.Contains(joined, "wrong password") {
		t.Errorf("wrong password reason not audited, got %q", joined)
	}
	if uiAuthAuditMentions(t, u, typed) {
		t.Error("the submitted password was written to audit_log")
	}
	if uiAuthAuditMentions(t, u, uiAuthPassword) {
		t.Error("the account password was written to audit_log")
	}
}

func TestLoginRateLimiterBlocksFurtherAttemptsFromTheSameIP(t *testing.T) {
	u := newUIHarness(t)
	u.addUser(t, uiAuthEmail, uiAuthPassword)

	for i := 0; i < loginMaxFails; i++ {
		rec := u.postForm("/login", url.Values{
			"email":    {"ghost@example.com"},
			"password": {"whatever"},
		})
		if strings.Contains(rec.Body.String(), "Too many login attempts") {
			t.Fatalf("rate limited after %d attempts, before the configured limit of %d", i, loginMaxFails)
		}
	}

	rec := u.postForm("/login", url.Values{
		"email":    {uiAuthEmail},
		"password": {uiAuthPassword},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Too many login attempts") {
		t.Fatal("valid credentials were still accepted after the failure limit")
	}
	if c := uiAuthCookie(rec, "gk_session"); c != nil {
		t.Error("a session was issued to a rate limited client")
	}
	if !strings.Contains(strings.Join(uiAuthDetails(t, u, audit.EventLoginFailure), "|"), "rate limited") {
		t.Error("the rate limited attempt was not audited")
	}
}

func TestPostLogoutDestroysSessionAndGetLogoutIsNotAllowed(t *testing.T) {
	u := newUIHarness(t)
	id := u.addUser(t, uiAuthEmail, uiAuthPassword)
	cookie := u.signIn(t, id)

	if rec := u.get("/", cookie); rec.Code != http.StatusOK {
		t.Fatalf("home before logout = %d, want 200", rec.Code)
	}
	if rec := u.get("/logout", cookie); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /logout = %d, want 405", rec.Code)
	}

	rec := u.postForm("/logout", nil, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := location(rec); loc != "/login" {
		t.Errorf("location = %q, want /login", loc)
	}
	if n := uiAuthSessionRows(t, u); n != 0 {
		t.Errorf("sessions left = %d, want 0", n)
	}
	if data := uiAuthSessionData(t, u, cookie); data != nil {
		t.Error("the old cookie still resolves to a session")
	}

	after := u.get("/", cookie)
	if after.Code != http.StatusFound || location(after) != "/login" {
		t.Errorf("home after logout = %d %q, want 302 /login", after.Code, location(after))
	}
}
