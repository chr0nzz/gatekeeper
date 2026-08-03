package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

const handoffTTL = 2 * time.Minute

// ErrHandoffInvalid is returned when a handoff token is unknown, expired, already
// used, or presented to a host it was not issued for.
var ErrHandoffInvalid = errors.New("invalid handoff token")

// HandoffStore issues single-use, host-bound tokens that transfer an authenticated
// identity to another domain without ever exposing a session identifier.
type HandoffStore struct {
	db *sql.DB
}

// NewHandoffStore creates a HandoffStore.
func NewHandoffStore(db *sql.DB) *HandoffStore {
	return &HandoffStore{db: db}
}

// Create issues a handoff token for userID that only the given host may redeem.
func (h *HandoffStore) Create(ctx context.Context, userID, targetHost string) (string, error) {
	raw, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now()
	_, err = h.db.ExecContext(ctx,
		`INSERT INTO handoff_tokens (id, user_id, target_host, created_at, expires_at) VALUES (?,?,?,?,?)`,
		hashToken(raw), userID, targetHost, now.Unix(), now.Add(handoffTTL).Unix(),
	)
	if err != nil {
		return "", err
	}
	return raw, nil
}

// Redeem consumes a handoff token exactly once and returns the user it belongs to.
// The token is rejected unless host matches the host it was issued for.
func (h *HandoffStore) Redeem(ctx context.Context, raw, host string) (string, error) {
	id := hashToken(raw)
	res, err := h.db.ExecContext(ctx,
		`UPDATE handoff_tokens SET used_at=? WHERE id=? AND used_at IS NULL AND expires_at>? AND target_host=?`,
		time.Now().Unix(), id, time.Now().Unix(), host,
	)
	if err != nil {
		return "", err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return "", ErrHandoffInvalid
	}
	var userID string
	if err := h.db.QueryRowContext(ctx, `SELECT user_id FROM handoff_tokens WHERE id=?`, id).Scan(&userID); err != nil {
		return "", ErrHandoffInvalid
	}
	if userID == "" {
		return "", ErrHandoffInvalid
	}
	return userID, nil
}

// CleanExpired removes handoff tokens that are expired or already redeemed.
func (h *HandoffStore) CleanExpired(ctx context.Context) {
	h.db.ExecContext(ctx, `DELETE FROM handoff_tokens WHERE expires_at<? OR used_at IS NOT NULL`, time.Now().Unix())
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
