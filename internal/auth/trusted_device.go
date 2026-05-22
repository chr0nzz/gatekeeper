package auth

import (
	"context"
	"database/sql"
	"net/http"
	"time"
)

const trustCookieName = "gk_trust"
const trustTTL = 30 * 24 * time.Hour

// TrustedDeviceStore manages per-browser trust tokens that skip 2FA for 30 days.
type TrustedDeviceStore struct {
	db           *sql.DB
	cookieDomain string
}

// NewTrustedDeviceStore creates a TrustedDeviceStore.
func NewTrustedDeviceStore(db *sql.DB, cookieDomain string) *TrustedDeviceStore {
	return &TrustedDeviceStore{db: db, cookieDomain: cookieDomain}
}

// IsTrusted returns true if the request carries a valid trust token for this user.
func (t *TrustedDeviceStore) IsTrusted(r *http.Request, userID string) bool {
	cookie, err := r.Cookie(trustCookieName)
	if err != nil {
		return false
	}
	var count int
	t.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM trusted_devices WHERE id=? AND user_id=? AND expires_at>?`,
		cookie.Value, userID, time.Now().Unix(),
	).Scan(&count)
	if count > 0 {
		t.db.ExecContext(r.Context(),
			`UPDATE trusted_devices SET last_seen=? WHERE id=? AND user_id=?`,
			time.Now().Unix(), cookie.Value, userID,
		)
	}
	return count > 0
}

// Trust creates a 30-day trust token for this browser and sets the cookie.
func (t *TrustedDeviceStore) Trust(w http.ResponseWriter, r *http.Request, userID string) error {
	id, err := randomToken(32)
	if err != nil {
		return err
	}
	now := time.Now()
	expires := now.Add(trustTTL)
	ua := r.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512]
	}
	_, err = t.db.ExecContext(r.Context(),
		`INSERT INTO trusted_devices (id, user_id, user_agent, created_at, expires_at, last_seen) VALUES (?,?,?,?,?,?)`,
		id, userID, ua, now.Unix(), expires.Unix(), now.Unix(),
	)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     trustCookieName,
		Value:    id,
		Path:     "/",
		Domain:   t.cookieDomain,
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// RevokeAll deletes all trust tokens for a user.
func (t *TrustedDeviceStore) RevokeAll(ctx context.Context, userID string) error {
	_, err := t.db.ExecContext(ctx, `DELETE FROM trusted_devices WHERE user_id=?`, userID)
	return err
}

// List returns all active trusted devices for a user.
func (t *TrustedDeviceStore) List(ctx context.Context, userID string) ([]TrustedDevice, error) {
	rows, err := t.db.QueryContext(ctx,
		`SELECT id, user_agent, created_at, last_seen, expires_at FROM trusted_devices WHERE user_id=? AND expires_at>? ORDER BY last_seen DESC`,
		userID, time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustedDevice
	for rows.Next() {
		var d TrustedDevice
		rows.Scan(&d.ID, &d.UserAgent, &d.CreatedAt, &d.LastSeen, &d.ExpiresAt)
		out = append(out, d)
	}
	return out, nil
}

// TrustedDevice is a display record for a trusted browser.
type TrustedDevice struct {
	ID        string
	UserAgent string
	CreatedAt int64
	LastSeen  int64
	ExpiresAt int64
}
