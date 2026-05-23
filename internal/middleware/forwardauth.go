package middleware

import (
	"database/sql"
	"net/http"
	"net/url"
	"strings"

	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

// ForwardAuth is the Traefik ForwardAuth middleware handler.
type ForwardAuth struct {
	sessions     *auth.SessionStore
	db           *sql.DB
	baseURL      string
	secretKey    string
	cookieDomain string
	policies     *queries.PolicyStore
}

// NewForwardAuth creates a ForwardAuth handler.
func NewForwardAuth(sessions *auth.SessionStore, db *sql.DB, baseURL, secretKey, cookieDomain string, policies *queries.PolicyStore) *ForwardAuth {
	return &ForwardAuth{
		sessions:     sessions,
		db:           db,
		baseURL:      baseURL,
		secretKey:    secretKey,
		cookieDomain: cookieDomain,
		policies:     policies,
	}
}

// Verify handles GET /auth/verify for Traefik ForwardAuth.
func (f *ForwardAuth) Verify(w http.ResponseWriter, r *http.Request) {
	forwardedURI := r.Header.Get("X-Forwarded-Uri")

	// Cross-domain callback: /_gk/auth?token=XXX&redirect=YYY
	if strings.HasPrefix(forwardedURI, "/_gk/auth") {
		f.handleCallback(w, r, forwardedURI)
		return
	}

	// Normal session check.
	data, _, err := f.sessions.Get(r)
	if err != nil || data == nil || data.UserID == "" || data.PendingOTP || data.PendingTOTP {
		http.Redirect(w, r, f.loginURL(r), http.StatusFound)
		return
	}

	var email string
	f.db.QueryRowContext(r.Context(), `SELECT email FROM users WHERE id=? AND disabled=0`, data.UserID).Scan(&email)
	if email == "" {
		http.Redirect(w, r, f.loginURL(r), http.StatusFound)
		return
	}

	if policyName := r.URL.Query().Get("policy"); policyName != "" {
		ok, err := f.policies.IsUserInPolicy(r.Context(), policyName, data.UserID)
		if err != nil || !ok {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
	}

	w.Header().Set("X-Auth-User", data.UserID)
	w.Header().Set("X-Auth-Email", email)
	w.WriteHeader(http.StatusOK)
}

// handleCallback validates a cross-domain token and sets a per-host session cookie.
// Traefik passes the Set-Cookie and Location headers back to the browser, so the
// browser receives a cookie scoped to the protected app's domain.
func (f *ForwardAuth) handleCallback(w http.ResponseWriter, r *http.Request, rawURI string) {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		http.Redirect(w, r, f.loginURL(r), http.StatusFound)
		return
	}

	token := parsed.Query().Get("token")
	redirect := parsed.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}

	sessID, err := auth.ValidateCrossToken(token, f.secretKey)
	if err != nil {
		http.Redirect(w, r, f.loginURL(r), http.StatusFound)
		return
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	if proto == "" {
		proto = "https"
	}

	// Set the session cookie scoped to the protected app's host.
	// No Domain means the browser scopes it to the exact host it received it from.
	http.SetCookie(w, &http.Cookie{
		Name:     "gk_session",
		Value:    sessID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, proto+"://"+host+redirect, http.StatusFound)
}

func (f *ForwardAuth) loginURL(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")

	loginURL := f.baseURL + "/login"
	if proto != "" && host != "" {
		original := proto + "://" + host + uri
		loginURL += "?redirect_uri=" + url.QueryEscape(original)
	}
	return loginURL
}
