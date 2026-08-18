package queries

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Invite represents a one-time registration invite link.
type Invite struct {
	ID        string
	Email     string
	Note      string
	CreatedBy string
	UsedAt    *int64
	ExpiresAt int64
	CreatedAt int64
}

// IsExpired reports whether the invite has passed its expiry time.
func (i *Invite) IsExpired() bool { return time.Now().Unix() > i.ExpiresAt }

// IsUsed reports whether the invite has already been redeemed.
func (i *Invite) IsUsed() bool { return i.UsedAt != nil }

// InviteStore manages invite CRUD.
type InviteStore struct {
	db *sql.DB
}

// NewInviteStore creates an InviteStore.
func NewInviteStore(db *sql.DB) *InviteStore {
	return &InviteStore{db: db}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Create stores a new invite and returns the raw (unhashed) token.
func (s *InviteStore) Create(ctx context.Context, email, note, createdBy string, expiryDays int) (string, error) {
	token := uuid.New().String() + uuid.New().String()
	now := time.Now().Unix()
	expires := now + int64(expiryDays)*86400
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invites (id, token_hash, email, note, created_by, expires_at, created_at)
		 VALUES (?,?,?,?,?,?,?)`,
		uuid.New().String(), hashToken(token), email, note, createdBy, expires, now,
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

// GetByToken retrieves an invite by its raw token.
func (s *InviteStore) GetByToken(ctx context.Context, token string) (*Invite, error) {
	var inv Invite
	var usedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, note, created_by, used_at, expires_at, created_at
		 FROM invites WHERE token_hash=?`,
		hashToken(token),
	).Scan(&inv.ID, &inv.Email, &inv.Note, &inv.CreatedBy, &usedAt, &inv.ExpiresAt, &inv.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if usedAt.Valid {
		inv.UsedAt = &usedAt.Int64
	}
	return &inv, nil
}

// Claim marks an invite redeemed, and reports false if it was already used.
func (s *InviteStore) Claim(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE invites SET used_at=? WHERE id=? AND used_at IS NULL`,
		time.Now().Unix(), id,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// List returns all invites newest first.
func (s *InviteStore) List(ctx context.Context) ([]Invite, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, note, created_by, used_at, expires_at, created_at
		 FROM invites ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		var usedAt sql.NullInt64
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.Note, &inv.CreatedBy, &usedAt, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			return nil, err
		}
		if usedAt.Valid {
			inv.UsedAt = &usedAt.Int64
		}
		out = append(out, inv)
	}
	return out, nil
}

// Revoke deletes an invite.
func (s *InviteStore) Revoke(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM invites WHERE id=?`, id)
	return err
}
