package queries

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Group represents a user group used for OIDC role claims.
type Group struct {
	ID          string
	Name        string
	Description string
	CreatedAt   int64
	MemberCount int
}

// GroupStore handles group CRUD operations.
type GroupStore struct {
	db *sql.DB
}

// NewGroupStore creates a GroupStore.
func NewGroupStore(db *sql.DB) *GroupStore {
	return &GroupStore{db: db}
}

// List returns all groups with member counts.
func (g *GroupStore) List(ctx context.Context) ([]Group, error) {
	rows, err := g.db.QueryContext(ctx,
		`SELECT gr.id, gr.name, gr.description, gr.created_at, COUNT(gm.user_id)
		 FROM groups gr
		 LEFT JOIN group_members gm ON gm.group_id = gr.id
		 GROUP BY gr.id
		 ORDER BY gr.name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var gr Group
		if err := rows.Scan(&gr.ID, &gr.Name, &gr.Description, &gr.CreatedAt, &gr.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, gr)
	}
	return out, nil
}

// GetByID retrieves a group by ID.
func (g *GroupStore) GetByID(ctx context.Context, id string) (*Group, error) {
	var gr Group
	err := g.db.QueryRowContext(ctx,
		`SELECT gr.id, gr.name, gr.description, gr.created_at, COUNT(gm.user_id)
		 FROM groups gr
		 LEFT JOIN group_members gm ON gm.group_id = gr.id
		 WHERE gr.id=?
		 GROUP BY gr.id`,
		id,
	).Scan(&gr.ID, &gr.Name, &gr.Description, &gr.CreatedAt, &gr.MemberCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &gr, nil
}

// Create creates a new group.
func (g *GroupStore) Create(ctx context.Context, name, description string) error {
	_, err := g.db.ExecContext(ctx,
		`INSERT INTO groups (id, name, description, created_at) VALUES (?,?,?,?)`,
		uuid.New().String(), name, description, time.Now().Unix(),
	)
	return err
}

// Delete removes a group and its members.
func (g *GroupStore) Delete(ctx context.Context, id string) error {
	_, err := g.db.ExecContext(ctx, `DELETE FROM groups WHERE id=?`, id)
	return err
}

// AddMember adds a user to a group.
func (g *GroupStore) AddMember(ctx context.Context, groupID, userID string) error {
	_, err := g.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)`,
		groupID, userID,
	)
	return err
}

// RemoveMember removes a user from a group.
func (g *GroupStore) RemoveMember(ctx context.Context, groupID, userID string) error {
	_, err := g.db.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_id=? AND user_id=?`,
		groupID, userID,
	)
	return err
}

// GetMembers returns all users in a group.
func (g *GroupStore) GetMembers(ctx context.Context, groupID string) ([]User, error) {
	rows, err := g.db.QueryContext(ctx,
		`SELECT u.id, u.email, u.password_hash, u.passwordless_enabled, u.force_password_change,
		        u.totp_enabled, u.disabled, u.created_at, COALESCE(u.display_name,''),
		        (u.avatar_data IS NOT NULL AND LENGTH(u.avatar_data)>0)
		 FROM users u
		 INNER JOIN group_members gm ON gm.user_id = u.id
		 WHERE gm.group_id=?
		 ORDER BY u.email`,
		groupID,
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

// GetUserGroups returns group names for a user.
func (g *GroupStore) GetUserGroups(ctx context.Context, userID string) ([]string, error) {
	rows, err := g.db.QueryContext(ctx,
		`SELECT gr.name FROM groups gr
		 INNER JOIN group_members gm ON gm.group_id = gr.id
		 WHERE gm.user_id=?
		 ORDER BY gr.name`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// GetUserGroupsByID returns group IDs and names for a user (used for non-members list).
func (g *GroupStore) ListNotMember(ctx context.Context, groupID string) ([]User, error) {
	rows, err := g.db.QueryContext(ctx,
		`SELECT u.id, u.email, u.password_hash, u.passwordless_enabled, u.force_password_change,
		        u.totp_enabled, u.disabled, u.created_at, COALESCE(u.display_name,''),
		        (u.avatar_data IS NOT NULL AND LENGTH(u.avatar_data)>0)
		 FROM users u
		 WHERE u.id NOT IN (SELECT user_id FROM group_members WHERE group_id=?)
		 ORDER BY u.email`,
		groupID,
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
