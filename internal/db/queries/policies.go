package queries

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Policy represents an access control policy.
type Policy struct {
	ID          string
	Name        string
	Description string
	CreatedAt   int64
	MemberCount int
}

// PolicyStore handles policy CRUD operations.
type PolicyStore struct {
	db *sql.DB
}

// NewPolicyStore creates a PolicyStore.
func NewPolicyStore(db *sql.DB) *PolicyStore {
	return &PolicyStore{db: db}
}

// List returns all policies with member counts.
func (p *PolicyStore) List(ctx context.Context) ([]Policy, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT pol.id, pol.name, pol.description, pol.created_at, COUNT(pm.user_id)
		 FROM policies pol
		 LEFT JOIN policy_members pm ON pm.policy_id = pol.id
		 GROUP BY pol.id
		 ORDER BY pol.name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []Policy
	for rows.Next() {
		var pol Policy
		if err := rows.Scan(&pol.ID, &pol.Name, &pol.Description, &pol.CreatedAt, &pol.MemberCount); err != nil {
			return nil, err
		}
		policies = append(policies, pol)
	}
	return policies, nil
}

// GetByID retrieves a policy by ID.
func (p *PolicyStore) GetByID(ctx context.Context, id string) (*Policy, error) {
	var pol Policy
	err := p.db.QueryRowContext(ctx,
		`SELECT pol.id, pol.name, pol.description, pol.created_at, COUNT(pm.user_id)
		 FROM policies pol
		 LEFT JOIN policy_members pm ON pm.policy_id = pol.id
		 WHERE pol.id=?
		 GROUP BY pol.id`,
		id,
	).Scan(&pol.ID, &pol.Name, &pol.Description, &pol.CreatedAt, &pol.MemberCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pol, nil
}

// GetByName retrieves a policy by name.
func (p *PolicyStore) GetByName(ctx context.Context, name string) (*Policy, error) {
	var pol Policy
	err := p.db.QueryRowContext(ctx,
		`SELECT pol.id, pol.name, pol.description, pol.created_at, COUNT(pm.user_id)
		 FROM policies pol
		 LEFT JOIN policy_members pm ON pm.policy_id = pol.id
		 WHERE pol.name=?
		 GROUP BY pol.id`,
		name,
	).Scan(&pol.ID, &pol.Name, &pol.Description, &pol.CreatedAt, &pol.MemberCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pol, nil
}

// Create creates a new policy.
func (p *PolicyStore) Create(ctx context.Context, name, description string) error {
	id := uuid.New().String()
	now := time.Now().Unix()
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO policies (id, name, description, created_at) VALUES (?,?,?,?)`,
		id, name, description, now,
	)
	return err
}

// Delete removes a policy and its members.
func (p *PolicyStore) Delete(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM policies WHERE id=?`, id)
	return err
}

// AddMember adds a user to a policy.
func (p *PolicyStore) AddMember(ctx context.Context, policyID, userID string) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO policy_members (policy_id, user_id) VALUES (?,?)`,
		policyID, userID,
	)
	return err
}

// RemoveMember removes a user from a policy.
func (p *PolicyStore) RemoveMember(ctx context.Context, policyID, userID string) error {
	_, err := p.db.ExecContext(ctx,
		`DELETE FROM policy_members WHERE policy_id=? AND user_id=?`,
		policyID, userID,
	)
	return err
}

// GetMembers returns all users in a policy.
func (p *PolicyStore) GetMembers(ctx context.Context, policyID string) ([]User, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT u.id, u.email, u.password_hash, u.passwordless_enabled, u.force_password_change,
		        u.totp_enabled, u.disabled, u.created_at, COALESCE(u.display_name,''),
		        (u.avatar_data IS NOT NULL AND LENGTH(u.avatar_data)>0)
		 FROM users u
		 INNER JOIN policy_members pm ON pm.user_id = u.id
		 WHERE pm.policy_id=?
		 ORDER BY u.email`,
		policyID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var ph sql.NullString
		if err := rows.Scan(&u.ID, &u.Email, &ph, &u.PasswordlessEnabled, &u.ForcePasswordChange,
			&u.TOTPEnabled, &u.Disabled, &u.CreatedAt, &u.DisplayName, &u.HasAvatar); err != nil {
			return nil, err
		}
		u.PasswordHash = ph.String
		users = append(users, u)
	}
	return users, nil
}

// IsUserInPolicy checks if a user is in a policy by policy name.
func (p *PolicyStore) IsUserInPolicy(ctx context.Context, policyName, userID string) (bool, error) {
	var count int
	err := p.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM policy_members pm
		 INNER JOIN policies pol ON pol.id = pm.policy_id
		 WHERE pol.name=? AND pm.user_id=?`,
		policyName, userID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// IsUserInPolicyByID checks if a user is in a policy by policy ID.
func (p *PolicyStore) IsUserInPolicyByID(ctx context.Context, policyID, userID string) (bool, error) {
	var count int
	err := p.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM policy_members WHERE policy_id=? AND user_id=?`,
		policyID, userID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
