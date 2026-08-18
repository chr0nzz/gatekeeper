package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testUA = "Mozilla/5.0 (TestBrowser 1.0)"

func trustRequest(ua string, cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", ua)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func trustCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == trustCookieName {
			return c
		}
	}
	t.Fatal("no trust cookie was set")
	return nil
}

func TestTrustedDeviceRoundTrip(t *testing.T) {
	store := NewTrustedDeviceStore(testDB(t), "")
	rec := httptest.NewRecorder()
	if err := store.Trust(rec, trustRequest(testUA, nil), "user-1"); err != nil {
		t.Fatalf("trust: %v", err)
	}
	cookie := trustCookie(t, rec)

	if !store.IsTrusted(trustRequest(testUA, cookie), "user-1") {
		t.Fatal("device not trusted with its own cookie and user agent")
	}
	if store.IsTrusted(trustRequest(testUA, cookie), "user-2") {
		t.Fatal("trust token accepted for a different user")
	}
}

func TestTrustedDeviceBoundToUserAgent(t *testing.T) {
	store := NewTrustedDeviceStore(testDB(t), "")
	rec := httptest.NewRecorder()
	store.Trust(rec, trustRequest(testUA, nil), "user-1")
	cookie := trustCookie(t, rec)

	if store.IsTrusted(trustRequest("curl/8.0", cookie), "user-1") {
		t.Fatal("trust token accepted from a different user agent")
	}
}

func TestTrustedDeviceStoredHashed(t *testing.T) {
	conn := testDB(t)
	store := NewTrustedDeviceStore(conn, "")
	rec := httptest.NewRecorder()
	store.Trust(rec, trustRequest(testUA, nil), "user-1")
	cookie := trustCookie(t, rec)

	var count int
	conn.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE id=?`, cookie.Value).Scan(&count)
	if count != 0 {
		t.Error("raw trust token stored in the database")
	}
	conn.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE id=?`, hashToken(cookie.Value)).Scan(&count)
	if count != 1 {
		t.Error("hashed trust token not found")
	}
}

func TestUntrustedWithoutCookie(t *testing.T) {
	store := NewTrustedDeviceStore(testDB(t), "")
	if store.IsTrusted(trustRequest(testUA, nil), "user-1") {
		t.Fatal("request without a trust cookie was treated as trusted")
	}
}
