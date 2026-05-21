package middleware

import (
	"context"
	"net/http"

	"github.com/chr0nzz/gatekeeper/internal/auth"
)

type csrfKey struct{}

// CSRF sets a cookie-based CSRF token and stores it in the request context
// so handlers can read it even on the very first request before the cookie
// has been sent back to the browser.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie("gk_csrf"); err == nil {
			token = c.Value
		} else {
			if t, err := auth.RandomTokenExport(16); err == nil {
				token = t
				http.SetCookie(w, &http.Cookie{
					Name:     "gk_csrf",
					Value:    token,
					Path:     "/",
					HttpOnly: false,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
		ctx := context.WithValue(r.Context(), csrfKey{}, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CSRFToken returns the CSRF token for the current request.
func CSRFToken(r *http.Request) string {
	token, _ := r.Context().Value(csrfKey{}).(string)
	return token
}
