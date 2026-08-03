package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

const (
	totpMaxFails  = 5
	totpLockTime  = 10 * time.Minute
	recoveryLen   = 10
	recoveryCodes = 8
)

// ErrTOTPReenrollRequired is returned when a stored secret used the retired
// pre-v0.4.0 format. The enrollment is cleared and the user must set up TOTP again.
var ErrTOTPReenrollRequired = errors.New("your authenticator setup has expired for security reasons, sign in with an email code and enroll again")

// TOTPStore manages TOTP enrollment and validation.
type TOTPStore struct {
	db        *sql.DB
	secretKey []byte
}

// NewTOTPStore creates a TOTPStore. secretKey is used to encrypt TOTP secrets at rest.
func NewTOTPStore(db *sql.DB, secretKey []byte) *TOTPStore {
	return &TOTPStore{db: db, secretKey: secretKey}
}

// GenerateSecret creates a new TOTP secret for a user (not yet stored).
func GenerateSecret(issuer, email string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
}

// QRCodePNG renders the TOTP key as a PNG QR code and returns the bytes.
func QRCodePNG(key *otp.Key) ([]byte, error) {
	return qrcode.Encode(key.URL(), qrcode.Medium, 256)
}

// ConfirmEnrollment validates the live code and stores the secret + recovery codes.
// Returns the plaintext recovery codes (shown once).
func (t *TOTPStore) ConfirmEnrollment(ctx context.Context, userID, secret, code string) ([]string, error) {
	if !totp.Validate(code, secret) {
		return nil, errors.New("invalid code, try again")
	}

	stored, err := t.encryptSecret([]byte(secret))
	if err != nil {
		return nil, err
	}

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?`,
		stored, userID,
	)
	if err != nil {
		return nil, err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE user_id=?`, userID)
	if err != nil {
		return nil, err
	}

	codes := make([]string, recoveryCodes)
	for i := range codes {
		codes[i] = randomAlphanumeric(recoveryLen)
		h, err := HashPassword(codes[i])
		if err != nil {
			return nil, err
		}
		id, _ := randomToken(16)
		_, err = tx.ExecContext(ctx,
			`INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at) VALUES (?,?,?,?)`,
			id, userID, h, time.Now().Unix(),
		)
		if err != nil {
			return nil, err
		}
	}
	return codes, tx.Commit()
}

// Validate checks a TOTP code for a user (+-1 window).
func (t *TOTPStore) Validate(ctx context.Context, userID, code string) error {
	if err := t.checkTOTPLockout(ctx, userID); err != nil {
		return err
	}
	var encSecret string
	err := t.db.QueryRowContext(ctx,
		`SELECT totp_secret FROM users WHERE id=? AND totp_enabled=1`,
		userID,
	).Scan(&encSecret)
	if err == sql.ErrNoRows {
		return errors.New("TOTP not enrolled")
	}
	if err != nil {
		return err
	}

	raw, legacy, err := t.decryptSecret(encSecret)
	if err != nil {
		return err
	}

	// Secrets stored in the pre-v0.4.0 XOR format are recoverable from a database
	// read alone, so they are retired rather than re-wrapped. The user must enroll
	// a fresh secret.
	if legacy {
		t.db.ExecContext(ctx, `UPDATE users SET totp_secret='', totp_enabled=0 WHERE id=?`, userID)
		t.db.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE user_id=?`, userID)
		return ErrTOTPReenrollRequired
	}

	valid := totp.Validate(code, string(raw))
	if !valid {
		prev := time.Now().Add(-30 * time.Second)
		ok, _ := totp.ValidateCustom(code, string(raw), prev, totp.ValidateOpts{
			Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		valid = ok
	}
	if !valid {
		return t.recordTOTPFail(ctx, userID)
	}
	t.db.ExecContext(ctx, `DELETE FROM otp_lockouts WHERE user_id=? AND lockout_type='totp'`, userID)
	return nil
}

// encryptSecret encrypts a TOTP secret with AES-256-GCM and returns a versioned string.
func (t *TOTPStore) encryptSecret(plaintext []byte) (string, error) {
	ct, err := aesGCMEncrypt(plaintext, t.secretKey)
	if err != nil {
		return "", err
	}
	return "v2:" + base64.StdEncoding.EncodeToString(ct), nil
}

// decryptSecret decodes both v2 (AES-GCM) and legacy (XOR) formats.
// Returns the plaintext, a boolean indicating whether the value was in legacy format, and any error.
func (t *TOTPStore) decryptSecret(stored string) ([]byte, bool, error) {
	if strings.HasPrefix(stored, "v2:") {
		enc, err := base64.StdEncoding.DecodeString(stored[3:])
		if err != nil {
			return nil, false, err
		}
		pt, err := aesGCMDecrypt(enc, t.secretKey)
		return pt, false, err
	}
	// Legacy XOR format is never decrypted. The caller retires the secret and
	// requires the user to enroll again.
	return nil, true, nil
}

// UseRecoveryCode consumes a recovery code. Returns nil on success.
func (t *TOTPStore) UseRecoveryCode(ctx context.Context, userID, code string) error {
	rows, err := t.db.QueryContext(ctx,
		`SELECT id, code_hash FROM totp_recovery_codes WHERE user_id=? AND used=0`,
		userID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, hash string
		if err := rows.Scan(&id, &hash); err != nil {
			continue
		}
		if VerifyPassword(code, hash) == nil {
			_, err = t.db.ExecContext(ctx,
				`UPDATE totp_recovery_codes SET used=1, used_at=? WHERE id=?`,
				time.Now().Unix(), id,
			)
			return err
		}
	}
	return errors.New("invalid recovery code")
}

// Revoke removes TOTP enrollment for a user.
func (t *TOTPStore) Revoke(ctx context.Context, userID string) error {
	_, err := t.db.ExecContext(ctx,
		`UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?`,
		userID,
	)
	if err != nil {
		return err
	}
	_, err = t.db.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE user_id=?`, userID)
	return err
}

// RecoveryCodeCount returns the number of unused recovery codes for a user.
func (t *TOTPStore) RecoveryCodeCount(ctx context.Context, userID string) (int, error) {
	var n int
	err := t.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id=? AND used=0`,
		userID,
	).Scan(&n)
	return n, err
}

func (t *TOTPStore) checkTOTPLockout(ctx context.Context, userID string) error {
	var lockedUntil sql.NullInt64
	err := t.db.QueryRowContext(ctx,
		`SELECT locked_until FROM otp_lockouts WHERE user_id=? AND lockout_type='totp'`,
		userID,
	).Scan(&lockedUntil)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if lockedUntil.Valid && time.Now().Unix() < lockedUntil.Int64 {
		return errors.New("too many failed attempts, try again later")
	}
	return nil
}

func (t *TOTPStore) recordTOTPFail(ctx context.Context, userID string) error {
	now := time.Now()
	windowStart := now.Add(-totpLockTime).Unix()
	t.db.ExecContext(ctx,
		`INSERT INTO otp_lockouts (user_id, lockout_type, attempts, window_start) VALUES (?,'totp',1,?)
		 ON CONFLICT(user_id, lockout_type) DO UPDATE SET
		   attempts = CASE WHEN window_start < ? THEN 1 ELSE attempts+1 END,
		   window_start = CASE WHEN window_start < ? THEN ? ELSE window_start END`,
		userID, now.Unix(), windowStart, windowStart, now.Unix(),
	)
	var attempts int
	t.db.QueryRowContext(ctx,
		`SELECT attempts FROM otp_lockouts WHERE user_id=? AND lockout_type='totp'`,
		userID,
	).Scan(&attempts)
	if attempts >= totpMaxFails {
		t.db.ExecContext(ctx,
			`UPDATE otp_lockouts SET locked_until=? WHERE user_id=? AND lockout_type='totp'`,
			now.Add(totpLockTime).Unix(), userID,
		)
		return errors.New("too many failed attempts, account locked for 10 minutes")
	}
	return errors.New("invalid code")
}

// aesGCMEncrypt encrypts plaintext with AES-256-GCM using a key derived from the provided secret.
func aesGCMEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(key))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// aesGCMDecrypt decrypts AES-256-GCM ciphertext.
func aesGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(key))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, nil)
}

// deriveKey derives a 32-byte AES key from an arbitrary-length secret using SHA-256.
func deriveKey(key []byte) []byte {
	h := sha256.Sum256(key)
	return h[:]
}

const alphanumChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomAlphanumeric(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphanumChars)))
	for i := range b {
		idx, _ := rand.Int(rand.Reader, max)
		b[i] = alphanumChars[idx.Int64()]
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		string(b[0:2]), string(b[2:4]), string(b[4:6]), string(b[6:8]), string(b[8:10]))
}
