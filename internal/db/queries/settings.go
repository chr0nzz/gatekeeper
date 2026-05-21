package queries

import (
	"context"
	"database/sql"
)

// SettingsStore reads and writes key-value application settings.
type SettingsStore struct {
	db *sql.DB
}

// NewSettingsStore creates a SettingsStore.
func NewSettingsStore(db *sql.DB) *SettingsStore {
	return &SettingsStore{db: db}
}

// Get returns the stored value for key, or fallback if not set.
func (s *SettingsStore) Get(ctx context.Context, key, fallback string) string {
	var val string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&val)
	if err != nil {
		return fallback
	}
	return val
}

// Set stores a value for key.
func (s *SettingsStore) Set(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value,
	)
	return err
}

// GetAll returns all stored settings as a map.
func (s *SettingsStore) GetAll(ctx context.Context) map[string]string {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			out[k] = v
		}
	}
	return out
}
