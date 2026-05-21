package middleware

import (
	"database/sql"
	"net/http"

	"github.com/chr0nzz/gatekeeper/internal/auth"
)

// ForwardAuth is the Traefik ForwardAuth middleware handler.
type ForwardAuth struct {
	sessions *auth.SessionStore
	db       *sql.DB
}

// NewForwardAuth creates a ForwardAuth handler.
func NewForwardAuth(sessions *auth.SessionStore, db *sql.DB) *ForwardAuth {
	return &ForwardAuth{sessions: sessions, db: db}
}

// Verify handles GET /auth/verify for Traefik ForwardAuth.
func (f *ForwardAuth) Verify(w http.ResponseWriter, r *http.Request) {
	data, _, err := f.sessions.Get(r)
	if err != nil || data == nil || data.UserID == "" || data.PendingOTP || data.PendingTOTP {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var email string
	f.db.QueryRowContext(r.Context(), `SELECT email FROM users WHERE id=? AND disabled=0`, data.UserID).Scan(&email)
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("X-Auth-User", data.UserID)
	w.Header().Set("X-Auth-Email", email)
	w.WriteHeader(http.StatusOK)
}
