package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 4
	argonKeyLen      = 32
	argonSaltLen     = 16

	resetTokenBytes = 32
	resetTTL        = 30 * time.Minute
	resetPerEmail   = 3
	resetPerIP      = 10
	resetWindow     = time.Hour

	minPasswordLen = 8
)

// ErrInvalidPassword is returned when password verification fails.
var ErrInvalidPassword = errors.New("invalid password")

// ErrPasswordTooShort is returned when the password is too short.
var ErrPasswordTooShort = errors.New("password must be at least 8 characters")

// CheckPasswordPolicy validates a password against configurable policy settings.
func CheckPasswordPolicy(password string, minLen int, requireUpper, requireNumber, requireSymbol bool) error {
	if minLen < minPasswordLen {
		minLen = minPasswordLen
	}
	if len(password) < minLen {
		return fmt.Errorf("password must be at least %d characters", minLen)
	}
	if requireUpper {
		hasUpper := false
		for _, c := range password {
			if c >= 'A' && c <= 'Z' {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			return errors.New("password must contain at least one uppercase letter")
		}
	}
	if requireNumber {
		hasNum := false
		for _, c := range password {
			if c >= '0' && c <= '9' {
				hasNum = true
				break
			}
		}
		if !hasNum {
			return errors.New("password must contain at least one number")
		}
	}
	if requireSymbol {
		hasSymbol := false
		for _, c := range password {
			if (c >= '!' && c <= '/') || (c >= ':' && c <= '@') || (c >= '[' && c <= '`') || (c >= '{' && c <= '~') {
				hasSymbol = true
				break
			}
		}
		if !hasSymbol {
			return errors.New("password must contain at least one symbol")
		}
	}
	return nil
}

// HashPassword hashes a password with argon2id.
func HashPassword(password string) (string, error) {
	if len(password) < minPasswordLen {
		return "", ErrPasswordTooShort
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	return fmt.Sprintf("$argon2id$%x$%x", salt, hash), nil
}

// VerifyPassword checks a plaintext password against a stored argon2id hash.
func VerifyPassword(password, stored string) error {
	var saltHex, hashHex string
	if _, err := fmt.Sscanf(stored, "$argon2id$%s", &saltHex); err != nil || len(saltHex) < 64 {
		return ErrInvalidPassword
	}
	saltHex = saltHex[:32]
	hashHex = stored[len("$argon2id$")+32+1:]
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return ErrInvalidPassword
	}
	expected, err := hex.DecodeString(hashHex)
	if err != nil {
		return ErrInvalidPassword
	}
	got := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	if !constantEqual(got, expected) {
		return ErrInvalidPassword
	}
	return nil
}

func constantEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// PasswordResetStore manages password reset tokens.
type PasswordResetStore struct {
	db *sql.DB
}

// NewPasswordResetStore creates a PasswordResetStore.
func NewPasswordResetStore(db *sql.DB) *PasswordResetStore {
	return &PasswordResetStore{db: db}
}

// IssueToken generates and stores a reset token, returning the raw token.
func (p *PasswordResetStore) IssueToken(ctx context.Context, userID string) (string, error) {
	raw := make([]byte, resetTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	hash, err := HashPassword(token + "reset-salt-suffix")
	if err != nil {
		tokenHash := argon2IDSimple(raw)
		hash = fmt.Sprintf("$argon2id$%x", tokenHash)
	}
	_ = hash
	tokenHash := argon2IDSimple(raw)
	storedHash := hex.EncodeToString(tokenHash)

	now := time.Now()
	id, err := randomToken(16)
	if err != nil {
		return "", err
	}
	_, err = p.db.ExecContext(ctx,
		`INSERT INTO password_reset_tokens (id, user_id, token_hash, created_at, expires_at) VALUES (?,?,?,?,?)`,
		id, userID, storedHash, now.Unix(), now.Add(resetTTL).Unix(),
	)
	return token, err
}

func argon2IDSimple(data []byte) []byte {
	salt := []byte("gatekeeper-reset-token-salt-v1xx")
	return argon2.IDKey(data, salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
}

// Redeem validates a token and marks it redeemed. Returns userID on success.
func (p *PasswordResetStore) Redeem(ctx context.Context, token string) (string, error) {
	raw, err := hex.DecodeString(token)
	if err != nil {
		return "", errors.New("invalid token")
	}
	tokenHash := hex.EncodeToString(argon2IDSimple(raw))
	now := time.Now()
	var id, userID string
	err = p.db.QueryRowContext(ctx,
		`SELECT id, user_id FROM password_reset_tokens
		 WHERE token_hash=? AND expires_at>? AND redeemed_at IS NULL`,
		tokenHash, now.Unix(),
	).Scan(&id, &userID)
	if err == sql.ErrNoRows {
		return "", errors.New("invalid or expired token")
	}
	if err != nil {
		return "", err
	}
	_, err = p.db.ExecContext(ctx,
		`UPDATE password_reset_tokens SET redeemed_at=? WHERE id=?`,
		now.Unix(), id,
	)
	return userID, err
}

// ValidateToken checks a token exists and is unexpired without redeeming it.
func (p *PasswordResetStore) ValidateToken(ctx context.Context, token string) (string, error) {
	raw, err := hex.DecodeString(token)
	if err != nil {
		return "", errors.New("invalid token")
	}
	tokenHash := hex.EncodeToString(argon2IDSimple(raw))
	now := time.Now()
	var userID string
	err = p.db.QueryRowContext(ctx,
		`SELECT user_id FROM password_reset_tokens WHERE token_hash=? AND expires_at>? AND redeemed_at IS NULL`,
		tokenHash, now.Unix(),
	).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", errors.New("invalid or expired token")
	}
	return userID, err
}

// CheckResetRateLimit returns an error if the key (email or IP) has exceeded the limit.
func CheckResetRateLimit(ctx context.Context, db *sql.DB, key, keyType string, r *http.Request) error {
	now := time.Now()
	windowStart := now.Add(-resetWindow).Unix()

	var count int
	var storedWindow int64
	err := db.QueryRowContext(ctx,
		`SELECT count, window_start FROM reset_rate_limits WHERE key=? AND key_type=?`,
		key, keyType,
	).Scan(&count, &storedWindow)
	if err == sql.ErrNoRows {
		storedWindow = now.Unix()
		count = 0
	} else if err != nil {
		return err
	}

	if storedWindow < windowStart {
		count = 0
		storedWindow = now.Unix()
	}

	limit := resetPerEmail
	if keyType == "ip" {
		limit = resetPerIP
	}

	if count >= limit {
		return errors.New("too many password reset requests, try again later")
	}

	db.ExecContext(ctx,
		`INSERT INTO reset_rate_limits (key, key_type, count, window_start) VALUES (?,?,1,?)
		 ON CONFLICT(key, key_type) DO UPDATE SET count=count+1, window_start=?`,
		key, keyType, now.Unix(), storedWindow,
	)
	return nil
}

// PasswordPolicy is the configured strength requirement for new passwords.
type PasswordPolicy struct {
	MinLength     int
	RequireUpper  bool
	RequireNumber bool
	RequireSymbol bool
}

// DefaultPasswordMinLength is used when no minimum has been configured.
const DefaultPasswordMinLength = 12

// MinConfigurablePasswordLength is the shortest minimum an operator may set.
const MinConfigurablePasswordLength = 8

// LoadPasswordPolicy reads the policy from a settings lookup function.
func LoadPasswordPolicy(get func(key, fallback string) string) PasswordPolicy {
	minLen := DefaultPasswordMinLength
	if n, err := strconv.Atoi(get("password_min_length", "")); err == nil && n >= MinConfigurablePasswordLength {
		minLen = n
	}
	return PasswordPolicy{
		MinLength:     minLen,
		RequireUpper:  get("password_require_uppercase", "0") == "1",
		RequireNumber: get("password_require_number", "0") == "1",
		RequireSymbol: get("password_require_symbol", "0") == "1",
	}
}

// Check validates a password against the policy.
func (p PasswordPolicy) Check(password string) error {
	return CheckPasswordPolicy(password, p.MinLength, p.RequireUpper, p.RequireNumber, p.RequireSymbol)
}
