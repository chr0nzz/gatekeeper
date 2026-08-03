package queries

import (
	"context"
	"database/sql"
	"strings"
)

// SecretCipher encrypts and decrypts setting values that must not be readable
// from a raw database copy.
type SecretCipher interface {
	EncryptSecret(plaintext string) (string, error)
	DecryptSecret(ciphertext string) (string, error)
}

// SettingsStore reads and writes key-value application settings. Values whose
// key identifies a credential are encrypted at rest.
type SettingsStore struct {
	db     *sql.DB
	cipher SecretCipher
}

// NewSettingsStore creates a SettingsStore.
func NewSettingsStore(db *sql.DB) *SettingsStore {
	return &SettingsStore{db: db}
}

// SetCipher attaches the cipher used to protect credential settings at rest.
func (s *SettingsStore) SetCipher(c SecretCipher) {
	s.cipher = c
}

// IsSecretKey reports whether a setting holds a credential.
func IsSecretKey(key string) bool {
	return strings.HasSuffix(key, "_password") ||
		strings.HasSuffix(key, "_secret") ||
		strings.HasSuffix(key, "_token") ||
		strings.HasSuffix(key, "_access_key") ||
		strings.HasSuffix(key, "_secret_key")
}

// Get returns the stored value for key, or fallback if not set.
func (s *SettingsStore) Get(ctx context.Context, key, fallback string) string {
	var val string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&val)
	if err != nil {
		return fallback
	}
	if val == "" {
		return val
	}
	if s.cipher != nil && IsSecretKey(key) {
		if plain, err := s.cipher.DecryptSecret(val); err == nil {
			return plain
		}
	}
	return val
}

// Set stores a value for key, encrypting it when the key holds a credential.
func (s *SettingsStore) Set(ctx context.Context, key, value string) error {
	stored := value
	if s.cipher != nil && IsSecretKey(key) && value != "" {
		if enc, err := s.cipher.EncryptSecret(value); err == nil {
			stored = enc
		}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, stored,
	)
	return err
}

// GetAll returns all stored settings as a map, decrypting credential values.
func (s *SettingsStore) GetAll(ctx context.Context) map[string]string {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) != nil {
			continue
		}
		if v != "" && s.cipher != nil && IsSecretKey(k) {
			if plain, err := s.cipher.DecryptSecret(v); err == nil {
				v = plain
			}
		}
		out[k] = v
	}
	return out
}
