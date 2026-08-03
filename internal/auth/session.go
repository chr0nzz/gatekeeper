package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "gk_session"

// SessionData holds the data stored server-side for a session.
type SessionData struct {
	UserID        string
	PendingOTP    bool
	PendingTOTP   bool
	RedirectURI   string
	OIDCRequestID string
}

// SessionStore manages server-side sessions backed by SQLite.
type SessionStore struct {
	db           *sql.DB
	getTTL       func() time.Duration
	cookieDomain string
}

// NewSessionStore creates a SessionStore. getTTL is called on every session
// operation so the TTL can be changed at runtime without a restart.
// cookieDomain, when non-empty, sets the Domain attribute on the session cookie
// (e.g. ".xyzlab.dev") so it is shared across all subdomains.
func NewSessionStore(db *sql.DB, getTTL func() time.Duration, cookieDomain string) *SessionStore {
	return &SessionStore{db: db, getTTL: getTTL, cookieDomain: cookieDomain}
}

// Create creates a new session and sets the session cookie across the configured
// cookie domain. It returns the server-side session handle, never the cookie value.
func (s *SessionStore) Create(w http.ResponseWriter, r *http.Request, data SessionData) (string, error) {
	return s.create(w, r, data, s.cookieDomain)
}

// CreateForHost creates a session whose cookie is scoped to the requesting host
// only. Used when handing an identity to an app on a different domain.
func (s *SessionStore) CreateForHost(w http.ResponseWriter, r *http.Request, data SessionData) (string, error) {
	return s.create(w, r, data, "")
}

func (s *SessionStore) create(w http.ResponseWriter, r *http.Request, data SessionData, domain string) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	id := hashToken(token)
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	now := time.Now()
	expires := now.Add(s.getTTL())
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	ua := r.UserAgent()
	_, err = s.db.ExecContext(r.Context(),
		`INSERT INTO sessions (id, user_id, data, created_at, expires_at, last_seen, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)`,
		id, data.UserID, string(raw), now.Unix(), expires.Unix(), now.Unix(), ip, ua,
	)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Domain:   domain,
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
	id := hashToken(cookie.Value)
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

// SessionInfo is a summary of a single session for display purposes.
type SessionInfo struct {
	ID        string
	IP        string
	Device    string
	LastSeen  time.Time
	CreatedAt time.Time
	Current   bool
}

// parseDevice extracts a human-readable "Browser · OS" string from a UA string.
func parseDevice(ua string) string {
	browser := "Unknown"
	switch {
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "Edge/"):
		browser = "Edge"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera/"):
		browser = "Opera"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	case strings.Contains(ua, "curl/"):
		browser = "curl"
	}
	os := "Unknown"
	switch {
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}
	if ua == "" {
		return "Unknown device"
	}
	return browser + " · " + os
}

// ListUserSessions returns all active sessions for a user, marking the current one.
func (s *SessionStore) ListUserSessions(ctx context.Context, userID, currentID string) ([]SessionInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ip, user_agent, last_seen, created_at FROM sessions WHERE user_id=? AND expires_at>? ORDER BY last_seen DESC`,
		userID, time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionInfo
	for rows.Next() {
		var si SessionInfo
		var ua string
		var lastSeen, createdAt int64
		if err := rows.Scan(&si.ID, &si.IP, &ua, &lastSeen, &createdAt); err != nil {
			continue
		}
		si.Device = parseDevice(ua)
		si.LastSeen = time.Unix(lastSeen, 0)
		si.CreatedAt = time.Unix(createdAt, 0)
		si.Current = si.ID == currentID
		out = append(out, si)
	}
	return out, nil
}

// RevokeSession deletes a single session belonging to a user.
func (s *SessionStore) RevokeSession(ctx context.Context, userID, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=? AND user_id=?`, sessionID, userID)
	return err
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
