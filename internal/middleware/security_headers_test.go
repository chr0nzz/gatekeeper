package middleware

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func serve(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	SecureHeaders(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec
}

func TestCSPHasNonceAndNoUnsafeInlineScript(t *testing.T) {
	rec := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))

	csp := rec.Header().Get("Content-Security-Policy")
	scriptSrc := ""
	for _, part := range strings.Split(csp, ";") {
		if strings.Contains(part, "script-src") {
			scriptSrc = part
		}
	}
	if scriptSrc == "" {
		t.Fatalf("no script-src directive in CSP: %q", csp)
	}
	if strings.Contains(scriptSrc, "unsafe-inline") {
		t.Errorf("script-src still allows unsafe-inline: %q", scriptSrc)
	}
	if !strings.Contains(scriptSrc, "'nonce-") {
		t.Errorf("script-src has no nonce: %q", scriptSrc)
	}
}

func TestNoncePlaceholderReplacedInHTML(t *testing.T) {
	rec := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<script nonce="` + NoncePlaceholder + `">x()</script>`))
	}))

	body := rec.Body.String()
	if strings.Contains(body, NoncePlaceholder) {
		t.Fatal("nonce placeholder was left in the response body")
	}

	nonce := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(rec.Header().Get("Content-Security-Policy"))
	if len(nonce) != 2 {
		t.Fatal("could not read nonce from CSP header")
	}
	if !strings.Contains(body, `nonce="`+nonce[1]+`"`) {
		t.Fatalf("script nonce does not match the CSP header nonce\nbody: %s", body)
	}
}

func TestNonceDiffersPerResponse(t *testing.T) {
	html := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	})
	first := serve(t, html).Header().Get("Content-Security-Policy")
	second := serve(t, html).Header().Get("Content-Security-Policy")
	if first == second {
		t.Fatal("two responses shared the same CSP nonce")
	}
}

func TestNonHTMLResponsesPassThrough(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0x03, 0xff}
	rec := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(payload)
	}))
	if got := rec.Body.Bytes(); string(got) != string(payload) {
		t.Fatalf("binary body altered: got %v want %v", got, payload)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	rec := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for header, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if !strings.Contains(rec.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Error("missing HSTS header")
	}
}
