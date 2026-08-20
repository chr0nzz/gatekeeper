package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	otpTTL               = 10 * time.Minute
	otpMaxFails          = 5
	otpLockTime          = 10 * time.Minute
	otpMaxIssuePerWindow = 3
)

// OTPStore manages email one-time passwords.
type OTPStore struct {
	db        *sql.DB
	secretKey []byte
}

// NewOTPStore creates an OTPStore. secretKey is used to HMAC OTP codes before storage.
func NewOTPStore(db *sql.DB, secretKey []byte) *OTPStore {
	return &OTPStore{db: db, secretKey: secretKey}
}

// Issue generates a 6-digit OTP, stores its HMAC, and returns the plaintext code.
func (o *OTPStore) Issue(ctx context.Context, userID string) (string, error) {
	if err := o.checkLockout(ctx, userID); err != nil {
		return "", err
	}
	var issued int
	o.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM otps WHERE user_id=? AND created_at>? AND used=0`,
		userID, time.Now().Add(-otpTTL).Unix(),
	).Scan(&issued)
	if issued >= otpMaxIssuePerWindow {
		return "", errors.New("too many code requests, please wait before requesting another")
	}

	code := fmt.Sprintf("%06d", cryptoRandIntn(1000000))
	now := time.Now()
	_, err := o.db.ExecContext(ctx,
		`INSERT INTO otps (id, user_id, code, created_at, expires_at) VALUES (?,?,?,?,?)`,
		uuid.New().String(), userID, o.hmacCode(code), now.Unix(), now.Add(otpTTL).Unix(),
	)
	return code, err
}

// Verify validates a code for a user. Returns nil on success.
func (o *OTPStore) Verify(ctx context.Context, userID, code string) error {
	if err := o.checkLockout(ctx, userID); err != nil {
		return err
	}
	now := time.Now()
	var id, stored string
	err := o.db.QueryRowContext(ctx,
		`SELECT id, code FROM otps WHERE user_id=? AND expires_at>? AND used=0 ORDER BY created_at DESC LIMIT 1`,
		userID, now.Unix(),
	).Scan(&id, &stored)
	if err == sql.ErrNoRows {
		return o.recordFail(ctx, userID)
	}
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(stored), []byte(o.hmacCode(code))) {
		return o.recordFail(ctx, userID)
	}
	res, err := o.db.ExecContext(ctx, `UPDATE otps SET used=1 WHERE id=? AND used=0`, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.New("invalid or expired code")
	}
	o.db.ExecContext(ctx, `DELETE FROM otp_lockouts WHERE user_id=? AND lockout_type='otp'`, userID)
	return nil
}

func (o *OTPStore) hmacCode(code string) string {
	mac := hmac.New(sha256.New, o.secretKey)
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func (o *OTPStore) checkLockout(ctx context.Context, userID string) error {
	var lockedUntil sql.NullInt64
	err := o.db.QueryRowContext(ctx,
		`SELECT locked_until FROM otp_lockouts WHERE user_id=? AND lockout_type='otp'`,
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

func (o *OTPStore) recordFail(ctx context.Context, userID string) error {
	now := time.Now()
	windowStart := now.Add(-otpLockTime).Unix()
	o.db.ExecContext(ctx,
		`INSERT INTO otp_lockouts (user_id, lockout_type, attempts, window_start) VALUES (?,'otp',1,?)
		 ON CONFLICT(user_id, lockout_type) DO UPDATE SET
		   attempts = CASE WHEN window_start < ? THEN 1 ELSE attempts+1 END,
		   window_start = CASE WHEN window_start < ? THEN ? ELSE window_start END`,
		userID, now.Unix(), windowStart, windowStart, now.Unix(),
	)

	var attempts int
	o.db.QueryRowContext(ctx,
		`SELECT attempts FROM otp_lockouts WHERE user_id=? AND lockout_type='otp'`,
		userID,
	).Scan(&attempts)

	if attempts >= otpMaxFails {
		o.db.ExecContext(ctx,
			`UPDATE otp_lockouts SET locked_until=? WHERE user_id=? AND lockout_type='otp'`,
			now.Add(otpLockTime).Unix(), userID,
		)
		return errors.New("too many failed attempts, account locked for 10 minutes")
	}
	return errors.New("invalid code")
}

func cryptoRandIntn(n int) int {
	b := make([]byte, 4)
	rand.Read(b)
	v := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if v < 0 {
		v = -v
	}
	return v % n
}
