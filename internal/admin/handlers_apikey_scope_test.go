package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func apiKeyRequest(a *adminHarness, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Api-Key", key)
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	return rec
}

func issueAPIKey(t *testing.T, a *adminHarness) string {
	t.Helper()
	a.signIn(t)
	const key = "test-api-key-value-0123456789abcdef"
	if err := a.admins.SetAPIKey(context.Background(), a.adminID, key); err != nil {
		t.Fatalf("set api key: %v", err)
	}
	return key
}

func TestAPIKeyReachesJSONEndpoints(t *testing.T) {
	a := newAdminHarness(t)
	key := issueAPIKey(t, a)

	for _, path := range []string{
		"/api/dashboard-stats",
		"/api/activity",
		"/api/auth-methods",
	} {
		rec := apiKeyRequest(a, path, key)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s with an API key = %d, want 200", path, rec.Code)
		}
	}
}

func TestAPIKeyCannotReadTheAdminPanel(t *testing.T) {
	a := newAdminHarness(t)
	key := issueAPIKey(t, a)
	a.addUser(t, "someone@example.com")

	for _, path := range []string{
		"/api/search?q=someone",
		"/users",
		"/audit",
		"/audit/export.csv",
		"/settings",
		"/clients",
		"/admins",
		"/profile",
		"/policies",
		"/groups",
		"/backups",
		"/",
	} {
		rec := apiKeyRequest(a, path, key)
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s with an API key = %d, want 403", path, rec.Code)
		}
		if body := rec.Body.String(); len(body) > 0 && rec.Code == http.StatusOK {
			t.Errorf("GET %s returned a body to an API key caller", path)
		}
	}
}

func TestAPIKeyResponseLeaksNoUserData(t *testing.T) {
	a := newAdminHarness(t)
	key := issueAPIKey(t, a)
	a.addUser(t, "private-person@example.com")

	for _, path := range []string{"/users", "/audit", "/api/search?q=private"} {
		rec := apiKeyRequest(a, path, key)
		if body := rec.Body.String(); contains(body, "private-person@example.com") {
			t.Errorf("GET %s exposed a user address to an API key caller", path)
		}
	}
}

func TestSessionReachesEverything(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)

	for _, path := range []string{"/users", "/settings", "/api/dashboard-stats"} {
		rec := a.get(path, cookie)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s with a session = %d, want 200", path, rec.Code)
		}
	}
}

func TestUnknownAPIKeyIsRejected(t *testing.T) {
	a := newAdminHarness(t)
	issueAPIKey(t, a)

	rec := apiKeyRequest(a, "/api/dashboard-stats", "not-a-real-key")
	if rec.Code == http.StatusOK {
		t.Error("an unknown API key was accepted")
	}
}

func TestAPIKeyScopeIsNotPrefixConfusable(t *testing.T) {
	a := newAdminHarness(t)
	key := issueAPIKey(t, a)

	for _, path := range []string{"/users?next=/api/", "/settings#/api/"} {
		rec := apiKeyRequest(a, path, key)
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s was allowed for an API key caller", path)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		})()
}
