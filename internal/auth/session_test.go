package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	return NewSessionStore(testDB(t), func() time.Duration { return time.Hour }, ".example.com")
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatal("no session cookie was set")
	return nil
}

func TestSessionTokenStoredHashed(t *testing.T) {
	store := newSessionStore(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handle, err := store.Create(rec, req, SessionData{UserID: "user-1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cookie := sessionCookie(t, rec)

	if cookie.Value == handle {
		t.Fatal("cookie value equals the stored session handle")
	}
	if hashToken(cookie.Value) != handle {
		t.Fatal("stored handle is not the hash of the cookie value")
	}
}

func TestSessionRoundTripAndForgery(t *testing.T) {
	store := newSessionStore(t)
	rec := httptest.NewRecorder()
	store.Create(rec, httptest.NewRequest(http.MethodGet, "/", nil), SessionData{UserID: "user-1"})
	cookie := sessionCookie(t, rec)

	good := httptest.NewRequest(http.MethodGet, "/", nil)
	good.AddCookie(cookie)
	data, _, err := store.Get(good)
	if err != nil || data == nil || data.UserID != "user-1" {
		t.Fatalf("valid cookie not accepted: data=%v err=%v", data, err)
	}

	bad := httptest.NewRequest(http.MethodGet, "/", nil)
	bad.AddCookie(&http.Cookie{Name: sessionCookieName, Value: hashToken(cookie.Value)})
	if data, _, _ := store.Get(bad); data != nil {
		t.Fatal("stored handle used as a cookie authenticated a session")
	}
}

func TestCreateForHostOmitsCookieDomain(t *testing.T) {
	store := newSessionStore(t)

	shared := httptest.NewRecorder()
	store.Create(shared, httptest.NewRequest(http.MethodGet, "/", nil), SessionData{UserID: "u"})
	if got := sessionCookie(t, shared).Domain; got != "example.com" {
		t.Errorf("Create cookie domain = %q, want example.com", got)
	}

	scoped := httptest.NewRecorder()
	store.CreateForHost(scoped, httptest.NewRequest(http.MethodGet, "/", nil), SessionData{UserID: "u"})
	if got := sessionCookie(t, scoped).Domain; got != "" {
		t.Errorf("CreateForHost cookie domain = %q, want empty", got)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	store := newSessionStore(t)
	rec := httptest.NewRecorder()
	store.Create(rec, httptest.NewRequest(http.MethodGet, "/", nil), SessionData{UserID: "u"})
	c := sessionCookie(t, rec)

	if !c.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if !c.Secure {
		t.Error("session cookie is not Secure")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie is not SameSite=Lax")
	}
}
