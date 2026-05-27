package queries

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Claim is a custom OIDC claim mapping for a client.
type Claim struct {
	ID          string
	ClientID    string
	ClaimKey    string
	ValueSource string
	CreatedAt   int64
}

// ClaimStore manages custom OIDC claim mappings.
type ClaimStore struct {
	db *sql.DB
}

// NewClaimStore creates a ClaimStore.
func NewClaimStore(db *sql.DB) *ClaimStore {
	return &ClaimStore{db: db}
}

// List returns all custom claims for a client.
func (s *ClaimStore) List(ctx context.Context, clientID string) ([]Claim, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, claim_key, value_source, created_at FROM client_claims WHERE client_id=? ORDER BY claim_key`,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Claim
	for rows.Next() {
		var c Claim
		if err := rows.Scan(&c.ID, &c.ClientID, &c.ClaimKey, &c.ValueSource, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Create adds a new custom claim mapping.
func (s *ClaimStore) Create(ctx context.Context, clientID, claimKey, valueSource string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO client_claims (id, client_id, claim_key, value_source, created_at) VALUES (?,?,?,?,?)`,
		uuid.New().String(), clientID, claimKey, valueSource, time.Now().Unix(),
	)
	return err
}

// Delete removes a custom claim mapping by ID.
func (s *ClaimStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM client_claims WHERE id=?`, id)
	return err
}

// DeleteByClient removes all custom claim mappings for a client.
func (s *ClaimStore) DeleteByClient(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM client_claims WHERE client_id=?`, clientID)
	return err
}
