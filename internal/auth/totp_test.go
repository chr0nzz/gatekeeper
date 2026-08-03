package auth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func totpStoreWithUser(t *testing.T) (*TOTPStore, *sql.DB) {
	t.Helper()
	conn := testDB(t)
	insertUser(t, conn, "u1", "u@example.com")
	return NewTOTPStore(conn, []byte("a-test-secret-key-that-is-long-enough")), conn
}

func enroll(t *testing.T, store *TOTPStore, conn *sql.DB) string {
	t.Helper()
	key, err := GenerateSecret("GateKeeper", "u@example.com")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if _, err := store.ConfirmEnrollment(context.Background(), "u1", key.Secret(), code); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	return key.Secret()
}

func TestTOTPEnrollAndValidate(t *testing.T) {
	ctx := context.Background()
	store, conn := totpStoreWithUser(t)
	secret := enroll(t, store, conn)

	code, _ := totp.GenerateCode(secret, time.Now())
	if err := store.Validate(ctx, "u1", code); err != nil {
		t.Errorf("valid code rejected: %v", err)
	}
	if err := store.Validate(ctx, "u1", "000000"); err == nil {
		t.Error("invalid code accepted")
	}
}

// Secrets are encrypted with AES-GCM, marked by the v2 prefix.
func TestTOTPSecretEncryptedAtRest(t *testing.T) {
	store, conn := totpStoreWithUser(t)
	secret := enroll(t, store, conn)

	var stored string
	conn.QueryRow(`SELECT totp_secret FROM users WHERE id='u1'`).Scan(&stored)
	if stored == secret {
		t.Fatal("TOTP secret stored in clear text")
	}
	if len(stored) < 3 || stored[:3] != "v2:" {
		t.Errorf("stored secret is not in the v2 format: %q", stored)
	}
}

// M2: secrets written before v0.4.0 used a scheme recoverable from a database
// read. They must be retired, not silently reused.
func TestLegacyTOTPSecretForcesReenrollment(t *testing.T) {
	ctx := context.Background()
	store, conn := totpStoreWithUser(t)
	enroll(t, store, conn)

	// Simulate a row still holding the retired format (no v2: prefix).
	legacy := base64.StdEncoding.EncodeToString([]byte("legacy-xor-ciphertext"))
	conn.Exec(`UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id='u1'`, legacy)

	err := store.Validate(ctx, "u1", "123456")
	if !errors.Is(err, ErrTOTPReenrollRequired) {
		t.Fatalf("Validate on a legacy secret = %v, want ErrTOTPReenrollRequired", err)
	}

	var enabled int
	var secret string
	conn.QueryRow(`SELECT totp_enabled, totp_secret FROM users WHERE id='u1'`).Scan(&enabled, &secret)
	if enabled != 0 {
		t.Error("legacy enrollment was not disabled")
	}
	if secret != "" {
		t.Error("legacy secret was not cleared")
	}

	var codes int
	conn.QueryRow(`SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id='u1'`).Scan(&codes)
	if codes != 0 {
		t.Error("recovery codes tied to the retired secret were kept")
	}
}

func TestTOTPRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	store, conn := totpStoreWithUser(t)

	key, _ := GenerateSecret("GateKeeper", "u@example.com")
	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	codes, err := store.ConfirmEnrollment(ctx, "u1", key.Secret(), code)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if len(codes) != recoveryCodes {
		t.Fatalf("got %d recovery codes, want %d", len(codes), recoveryCodes)
	}

	var stored string
	conn.QueryRow(`SELECT code_hash FROM totp_recovery_codes WHERE user_id='u1' LIMIT 1`).Scan(&stored)
	for _, c := range codes {
		if stored == c {
			t.Fatal("recovery code stored in clear text")
		}
	}

	if err := store.UseRecoveryCode(ctx, "u1", codes[0]); err != nil {
		t.Errorf("valid recovery code rejected: %v", err)
	}
	if err := store.UseRecoveryCode(ctx, "u1", codes[0]); err == nil {
		t.Error("recovery code reused")
	}
	if err := store.UseRecoveryCode(ctx, "u1", "not-a-code"); err == nil {
		t.Error("invalid recovery code accepted")
	}

	n, _ := store.RecoveryCodeCount(ctx, "u1")
	if n != recoveryCodes-1 {
		t.Errorf("remaining recovery codes = %d, want %d", n, recoveryCodes-1)
	}
}

func TestTOTPLockoutAfterRepeatedFailures(t *testing.T) {
	ctx := context.Background()
	store, conn := totpStoreWithUser(t)
	secret := enroll(t, store, conn)

	for i := 0; i < 6; i++ {
		store.Validate(ctx, "u1", "000000")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if err := store.Validate(ctx, "u1", code); err == nil {
		t.Error("valid code accepted while the account should be locked out")
	}
}

func TestTOTPRevoke(t *testing.T) {
	ctx := context.Background()
	store, conn := totpStoreWithUser(t)
	enroll(t, store, conn)

	if err := store.Revoke(ctx, "u1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := store.Validate(ctx, "u1", "123456"); err == nil {
		t.Error("validation succeeded after revoking enrollment")
	}
	n, _ := store.RecoveryCodeCount(ctx, "u1")
	if n != 0 {
		t.Errorf("recovery codes remain after revoke: %d", n)
	}
}

func TestTOTPEnrollmentRejectsWrongCode(t *testing.T) {
	store, _ := totpStoreWithUser(t)
	key, _ := GenerateSecret("GateKeeper", "u@example.com")
	if _, err := store.ConfirmEnrollment(context.Background(), "u1", key.Secret(), "000000"); err == nil {
		t.Error("enrollment confirmed with an incorrect code")
	}
}
