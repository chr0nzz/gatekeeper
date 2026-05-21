package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const sessionCookieName = "gk_session"

// SessionData holds the data stored server-side for a session.
type SessionData struct {
	UserID      string
	PendingOTP  bool
	PendingTOTP bool
	RedirectURI string
}

// SessionStore manages server-side sessions backed by SQLite.
type SessionStore struct {
	db     *sql.DB
	getTTL func() time.Duration
}

// NewSessionStore creates a SessionStore. getTTL is called on every session
// operation so the TTL can be changed at runtime without a restart.
func NewSessionStore(db *sql.DB, getTTL func() time.Duration) *SessionStore {
	return &SessionStore{db: db, getTTL: getTTL}
}

// Create creates a new session and sets the session cookie.
func (s *SessionStore) Create(w http.ResponseWriter, r *http.Request, data SessionData) (string, error) {
	id, err := randomToken(32)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	now := time.Now()
	expires := now.Add(s.getTTL())
	_, err = s.db.ExecContext(r.Context(),
		`INSERT INTO sessions (id, user_id, data, created_at, expires_at, last_seen) VALUES (?,?,?,?,?,?)`,
		id, data.UserID, string(raw), now.Unix(), expires.Unix(), now.Unix(),
	)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return id, nil
}

// Get retrieves and renews a session from the request cookie.
func (s *SessionStore) Get(r *http.Request) (*SessionData, string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, "", nil
	}
	id := cookie.Value
	now := time.Now()
	var raw string
	var expiresAt int64
	err = s.db.QueryRowContext(r.Context(),
		`SELECT data, expires_at FROM sessions WHERE id=? AND expires_at>?`,
		id, now.Unix(),
	).Scan(&raw, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var data SessionData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, "", err
	}
	s.db.ExecContext(r.Context(),
		`UPDATE sessions SET last_seen=?, expires_at=? WHERE id=?`,
		now.Unix(), now.Add(s.getTTL()).Unix(), id,
	)
	return &data, id, nil
}

// Update overwrites the data for an existing session.
func (s *SessionStore) Update(ctx context.Context, id string, data SessionData) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE sessions SET data=?, user_id=? WHERE id=?`,
		string(raw), data.UserID, id,
	)
	return err
}

// Destroy deletes a session and clears the cookie.
func (s *SessionStore) Destroy(w http.ResponseWriter, r *http.Request, id string) {
	s.db.ExecContext(r.Context(), `DELETE FROM sessions WHERE id=?`, id)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	})
}

// RevokeUser deletes all sessions for a user except the given one.
func (s *SessionStore) RevokeUser(ctx context.Context, userID, exceptID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id=? AND id!=?`,
		userID, exceptID,
	)
	return err
}

// RevokeAll deletes every session for a user.
func (s *SessionStore) RevokeAll(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

// CleanExpired removes expired sessions.
func (s *SessionStore) CleanExpired(ctx context.Context) {
	s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<?`, time.Now().Unix())
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomTokenExport generates a random hex token of n bytes for use by other packages.
func RandomTokenExport(n int) (string, error) {
	return randomToken(n)
}
