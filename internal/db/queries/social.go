package queries

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// SocialAccount links a GateKeeper user to an external OAuth2 provider identity.
type SocialAccount struct {
	ID             string
	UserID         string
	Provider       string
	ProviderUserID string
	ProviderEmail  string
	CreatedAt      int64
}

// SocialStore manages social account links.
type SocialStore struct {
	db *sql.DB
}

// NewSocialStore creates a SocialStore.
func NewSocialStore(db *sql.DB) *SocialStore {
	return &SocialStore{db: db}
}

// FindByProvider looks up a social account by provider name and provider-issued user ID.
func (s *SocialStore) FindByProvider(ctx context.Context, provider, providerUserID string) (*SocialAccount, error) {
	var a SocialAccount
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, provider, provider_user_id, provider_email, created_at FROM social_accounts WHERE provider=? AND provider_user_id=?`,
		provider, providerUserID,
	).Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderUserID, &a.ProviderEmail, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

// FindByUserAndProvider looks up a social account for a specific user and provider.
func (s *SocialStore) FindByUserAndProvider(ctx context.Context, userID, provider string) (*SocialAccount, error) {
	var a SocialAccount
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, provider, provider_user_id, provider_email, created_at FROM social_accounts WHERE user_id=? AND provider=?`,
		userID, provider,
	).Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderUserID, &a.ProviderEmail, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

// ListByUser returns all social accounts linked to a user.
func (s *SocialStore) ListByUser(ctx context.Context, userID string) ([]SocialAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, provider, provider_user_id, provider_email, created_at FROM social_accounts WHERE user_id=? ORDER BY provider`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SocialAccount
	for rows.Next() {
		var a SocialAccount
		rows.Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderUserID, &a.ProviderEmail, &a.CreatedAt)
		out = append(out, a)
	}
	return out, nil
}

// Create links a new social account to a user.
func (s *SocialStore) Create(ctx context.Context, userID, provider, providerUserID, providerEmail string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO social_accounts (id, user_id, provider, provider_user_id, provider_email, created_at) VALUES (?,?,?,?,?,?)`,
		uuid.New().String(), userID, provider, providerUserID, providerEmail, time.Now().Unix(),
	)
	return err
}

// Delete removes a social account link by ID.
func (s *SocialStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM social_accounts WHERE id=?`, id)
	return err
}

// CountByUser returns how many social accounts are linked to a user.
func (s *SocialStore) CountByUser(ctx context.Context, userID string) int {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM social_accounts WHERE user_id=?`, userID).Scan(&n)
	return n
}
