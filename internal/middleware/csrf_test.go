package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFIssuesTokenAndCookie(t *testing.T) {
	var token string
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = CSRFToken(r)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if token == "" {
		t.Fatal("no CSRF token was placed in the request context")
	}

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gk_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no CSRF cookie was set")
	}
	if cookie.Value != token {
		t.Error("cookie value does not match the token given to the handler")
	}
	if !cookie.Secure {
		t.Error("CSRF cookie is not Secure")
	}
	if cookie.HttpOnly {
		t.Error("CSRF cookie must be readable by scripts to be submitted in forms")
	}
}

func TestCSRFReusesExistingCookie(t *testing.T) {
	var token string
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = CSRFToken(r)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "gk_csrf", Value: "existing-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if token != "existing-token" {
		t.Errorf("token = %q, want the existing cookie value", token)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gk_csrf" {
			t.Error("a new CSRF cookie was issued despite one already being present")
		}
	}
}

func TestCSRFTokensAreUnpredictable(t *testing.T) {
	issue := func() string {
		var token string
		CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token = CSRFToken(r)
		})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		return token
	}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		tok := issue()
		if len(tok) < 16 {
			t.Fatalf("token %q is too short to resist guessing", tok)
		}
		if seen[tok] {
			t.Fatal("CSRF token repeated across requests")
		}
		seen[tok] = true
	}
}

func TestCSRFTokenEmptyWithoutMiddleware(t *testing.T) {
	if got := CSRFToken(httptest.NewRequest(http.MethodGet, "/", nil)); got != "" {
		t.Errorf("CSRFToken without middleware = %q, want empty", got)
	}
}
