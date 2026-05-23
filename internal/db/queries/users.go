package queries

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// User represents a GateKeeper user.
type User struct {
	ID                  string
	Email               string
	PasswordHash        string
	PasswordlessEnabled bool
	ForcePasswordChange bool
	TOTPEnabled         bool
	Disabled            bool
	CreatedAt           int64
	DisplayName         string
	HasAvatar           bool
}

// UserStore handles user CRUD operations.
type UserStore struct {
	db *sql.DB
}

// NewUserStore creates a UserStore.
func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

// Create creates a new user. Returns the new user's ID.
func (u *UserStore) Create(ctx context.Context, email, passwordHash string, forceChange bool) (string, error) {
	id := uuid.New().String()
	now := time.Now().Unix()
	_, err := u.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, force_password_change, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
		id, email, passwordHash, boolInt(forceChange), now, now,
	)
	if err != nil {
		return "", err
	}
	return id, nil
}

// GetByEmail retrieves a user by email.
func (u *UserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	return u.scan(u.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, passwordless_enabled, force_password_change, totp_enabled, disabled, created_at, COALESCE(display_name,''), (avatar_data IS NOT NULL AND LENGTH(avatar_data)>0)
		 FROM users WHERE email=?`,
		email,
	))
}

// GetByID retrieves a user by ID.
func (u *UserStore) GetByID(ctx context.Context, id string) (*User, error) {
	return u.scan(u.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, passwordless_enabled, force_password_change, totp_enabled, disabled, created_at, COALESCE(display_name,''), (avatar_data IS NOT NULL AND LENGTH(avatar_data)>0)
		 FROM users WHERE id=?`,
		id,
	))
}

// List returns all users.
func (u *UserStore) List(ctx context.Context) ([]User, error) {
	rows, err := u.db.QueryContext(ctx,
		`SELECT id, email, password_hash, passwordless_enabled, force_password_change, totp_enabled, disabled, created_at, COALESCE(display_name,''), (avatar_data IS NOT NULL AND LENGTH(avatar_data)>0)
		 FROM users ORDER BY email`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var usr User
		var ph sql.NullString
		if err := rows.Scan(&usr.ID, &usr.Email, &ph, &usr.PasswordlessEnabled, &usr.ForcePasswordChange, &usr.TOTPEnabled, &usr.Disabled, &usr.CreatedAt, &usr.DisplayName, &usr.HasAvatar); err != nil {
			return nil, err
		}
		usr.PasswordHash = ph.String
		users = append(users, usr)
	}
	return users, nil
}

// SetDisplayName updates a user's display name.
func (u *UserStore) SetDisplayName(ctx context.Context, userID, name string) error {
	_, err := u.db.ExecContext(ctx,
		`UPDATE users SET display_name=?, updated_at=? WHERE id=?`,
		name, time.Now().Unix(), userID,
	)
	return err
}

// SetAvatar stores a cached avatar image for a user.
func (u *UserStore) SetAvatar(ctx context.Context, userID string, data []byte, mime string) error {
	_, err := u.db.ExecContext(ctx,
		`UPDATE users SET avatar_data=?, avatar_mime=?, updated_at=? WHERE id=?`,
		data, mime, time.Now().Unix(), userID,
	)
	return err
}

// GetAvatar returns the cached avatar image for a user.
func (u *UserStore) GetAvatar(ctx context.Context, userID string) ([]byte, string) {
	var data []byte
	var mime string
	u.db.QueryRowContext(ctx, `SELECT avatar_data, avatar_mime FROM users WHERE id=?`, userID).Scan(&data, &mime)
	return data, mime
}

// SetPassword updates a user's password hash.
func (u *UserStore) SetPassword(ctx context.Context, userID, hash string, forceChange bool) error {
	_, err := u.db.ExecContext(ctx,
		`UPDATE users SET password_hash=?, force_password_change=?, updated_at=? WHERE id=?`,
		hash, boolInt(forceChange), time.Now().Unix(), userID,
	)
	return err
}

// SetDisabled enables or disables a user.
func (u *UserStore) SetDisabled(ctx context.Context, userID string, disabled bool) error {
	_, err := u.db.ExecContext(ctx,
		`UPDATE users SET disabled=?, updated_at=? WHERE id=?`,
		boolInt(disabled), time.Now().Unix(), userID,
	)
	return err
}

// SetPasswordless toggles passwordless mode for a user.
func (u *UserStore) SetPasswordless(ctx context.Context, userID string, enabled bool) error {
	_, err := u.db.ExecContext(ctx,
		`UPDATE users SET passwordless_enabled=?, updated_at=? WHERE id=?`,
		boolInt(enabled), time.Now().Unix(), userID,
	)
	return err
}

// Delete removes a user.
func (u *UserStore) Delete(ctx context.Context, userID string) error {
	_, err := u.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, userID)
	return err
}

func (u *UserStore) scan(row *sql.Row) (*User, error) {
	var usr User
	var ph sql.NullString
	err := row.Scan(&usr.ID, &usr.Email, &ph, &usr.PasswordlessEnabled, &usr.ForcePasswordChange, &usr.TOTPEnabled, &usr.Disabled, &usr.CreatedAt, &usr.DisplayName, &usr.HasAvatar)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	usr.PasswordHash = ph.String
	return &usr, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// AdminUser represents an admin account.
type AdminUser struct {
	ID           string
	Email        string
	PasswordHash string
}

// AdminStore handles admin user operations.
type AdminStore struct {
	db *sql.DB
}

// NewAdminStore creates an AdminStore.
func NewAdminStore(db *sql.DB) *AdminStore {
	return &AdminStore{db: db}
}

// Exists returns true if at least one admin account exists.
func (a *AdminStore) Exists(ctx context.Context) bool {
	var count int
	a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users`).Scan(&count)
	return count > 0
}

// Create creates a new admin account.
func (a *AdminStore) Create(ctx context.Context, email, passwordHash string) error {
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO admin_users (id, email, password_hash, created_at) VALUES (?,?,?,?)`,
		uuid.New().String(), email, passwordHash, time.Now().Unix(),
	)
	return err
}

// GetByID retrieves an admin by ID.
func (a *AdminStore) GetByID(ctx context.Context, id string) (*AdminUser, error) {
	var admin AdminUser
	err := a.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash FROM admin_users WHERE id=?`,
		id,
	).Scan(&admin.ID, &admin.Email, &admin.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &admin, err
}

// GetByEmail retrieves an admin by email.
func (a *AdminStore) GetByEmail(ctx context.Context, email string) (*AdminUser, error) {
	var admin AdminUser
	err := a.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash FROM admin_users WHERE email=?`,
		email,
	).Scan(&admin.ID, &admin.Email, &admin.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &admin, err
}

// AdminSessionStore manages admin sessions.
type AdminSessionStore struct {
	db *sql.DB
}

// NewAdminSessionStore creates an AdminSessionStore.
func NewAdminSessionStore(db *sql.DB) *AdminSessionStore {
	return &AdminSessionStore{db: db}
}

// Create creates an admin session and returns the session ID.
func (a *AdminSessionStore) Create(ctx context.Context, adminID string) (string, error) {
	id := uuid.New().String()
	now := time.Now()
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO admin_sessions (id, admin_id, created_at, expires_at) VALUES (?,?,?,?)`,
		id, adminID, now.Unix(), now.Add(8*time.Hour).Unix(),
	)
	return id, err
}

// Get retrieves an admin session.
func (a *AdminSessionStore) Get(ctx context.Context, id string) (string, error) {
	var adminID string
	err := a.db.QueryRowContext(ctx,
		`SELECT admin_id FROM admin_sessions WHERE id=? AND expires_at>?`,
		id, time.Now().Unix(),
	).Scan(&adminID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return adminID, err
}

// Destroy deletes an admin session.
func (a *AdminSessionStore) Destroy(ctx context.Context, id string) {
	a.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id=?`, id)
}
