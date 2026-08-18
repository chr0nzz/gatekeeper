package middleware

import (
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

// ForwardAuth is the Traefik ForwardAuth middleware handler.
type ForwardAuth struct {
	sessions     *auth.SessionStore
	handoff      *auth.HandoffStore
	db           *sql.DB
	baseURL      string
	secretKey    string
	cookieDomain string
	policies     *queries.PolicyStore
	groups       *queries.GroupStore
}

// NewForwardAuth creates a ForwardAuth handler.
func NewForwardAuth(sessions *auth.SessionStore, handoff *auth.HandoffStore, db *sql.DB, baseURL, secretKey, cookieDomain string, policies *queries.PolicyStore, groups *queries.GroupStore) *ForwardAuth {
	return &ForwardAuth{
		sessions:     sessions,
		handoff:      handoff,
		db:           db,
		baseURL:      baseURL,
		secretKey:    secretKey,
		cookieDomain: cookieDomain,
		policies:     policies,
		groups:       groups,
	}
}

// Verify handles GET /auth/verify for Traefik ForwardAuth.
func (f *ForwardAuth) Verify(w http.ResponseWriter, r *http.Request) {
	forwardedURI := r.Header.Get("X-Forwarded-Uri")

	slog.Debug("forwardauth verify",
		"x_forwarded_host", r.Header.Get("X-Forwarded-Host"),
		"x_forwarded_proto", r.Header.Get("X-Forwarded-Proto"),
		"x_forwarded_path", pathOnly(forwardedURI),
		"policy", r.URL.Query().Get("policy"),
	)

	if strings.HasPrefix(forwardedURI, "/_gk/auth") {
		f.handleCallback(w, r, forwardedURI)
		return
	}

	data, _, err := f.sessions.Get(r)
	if err != nil || data == nil || data.UserID == "" || data.PendingOTP || data.PendingTOTP {
		login := f.loginURL(r)
		slog.Debug("forwardauth no session, redirecting to login", "login_url", login)
		http.Redirect(w, r, login, http.StatusFound)
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
		var injectUser, injectPass string
		f.db.QueryRowContext(r.Context(),
			`SELECT inject_username, inject_password FROM policies WHERE name=?`, policyName,
		).Scan(&injectUser, &injectPass)
		if injectUser != "" && injectPass != "" {
			if plain, err := auth.DecryptSecret(injectPass, []byte(f.secretKey)); err == nil {
				cred := base64.StdEncoding.EncodeToString([]byte(injectUser + ":" + string(plain)))
				w.Header().Set("Authorization", "Basic "+cred)
			}
		}
	}

	w.Header().Set("X-Auth-User", data.UserID)
	w.Header().Set("X-Auth-Email", email)
	if names, err := f.groups.GetUserGroups(r.Context(), data.UserID); err == nil && len(names) > 0 {
		w.Header().Set("X-Auth-Groups", strings.Join(names, ","))
	}
	w.WriteHeader(http.StatusOK)
}

func (f *ForwardAuth) handleCallback(w http.ResponseWriter, r *http.Request, rawURI string) {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		http.Redirect(w, r, f.loginURL(r), http.StatusFound)
		return
	}

	token := parsed.Query().Get("token")
	redirect := parsed.Query().Get("redirect")
	if !isLocalPath(redirect) {
		redirect = "/"
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	if proto == "" {
		proto = "https"
	}

	userID, err := f.handoff.Redeem(r.Context(), token, host)
	if err != nil {
		http.Redirect(w, r, f.loginURL(r), http.StatusFound)
		return
	}

	if _, err := f.sessions.CreateForHost(w, r, auth.SessionData{UserID: userID}); err != nil {
		http.Redirect(w, r, f.loginURL(r), http.StatusFound)
		return
	}

	http.Redirect(w, r, proto+"://"+host+redirect, http.StatusFound)
}

func isLocalPath(redirect string) bool {
	return strings.HasPrefix(redirect, "/") &&
		!strings.HasPrefix(redirect, "//") &&
		!strings.HasPrefix(redirect, "/\\")
}

func pathOnly(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
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
