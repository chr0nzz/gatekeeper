package middleware

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
)

// NoncePlaceholder is replaced in templates with the per-response CSP nonce.
const NoncePlaceholder = "__CSP_NONCE__"

// SecureHeaders adds security headers and a per-response CSP nonce.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := newNonce()
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; script-src 'self' 'nonce-"+nonce+"'; "+
				"img-src 'self' data: https://www.gravatar.com; connect-src 'self'; object-src 'none'; "+
				"base-uri 'self'; frame-ancestors 'none'")

		nw := &nonceWriter{ResponseWriter: w, nonce: nonce}
		next.ServeHTTP(nw, r)
		nw.finish()
	})
}

func newNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

type nonceWriter struct {
	http.ResponseWriter
	nonce       string
	buf         bytes.Buffer
	status      int
	buffering   bool
	wroteHeader bool
}

func (n *nonceWriter) WriteHeader(status int) {
	if n.wroteHeader {
		return
	}
	n.wroteHeader = true
	n.status = status
	n.buffering = strings.HasPrefix(n.Header().Get("Content-Type"), "text/html")
	if !n.buffering {
		n.ResponseWriter.WriteHeader(status)
	}
}

func (n *nonceWriter) Write(b []byte) (int, error) {
	if !n.wroteHeader {
		if n.Header().Get("Content-Type") == "" {
			n.Header().Set("Content-Type", http.DetectContentType(b))
		}
		n.WriteHeader(http.StatusOK)
	}
	if n.buffering {
		return n.buf.Write(b)
	}
	return n.ResponseWriter.Write(b)
}

func (n *nonceWriter) finish() {
	if !n.wroteHeader {
		return
	}
	if !n.buffering {
		return
	}
	body := bytes.ReplaceAll(n.buf.Bytes(), []byte(NoncePlaceholder), []byte(n.nonce))
	n.Header().Set("Content-Length", strconv.Itoa(len(body)))
	n.ResponseWriter.WriteHeader(n.status)
	n.ResponseWriter.Write(body)
}
