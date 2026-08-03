package auth

import (
	"context"
	"database/sql"
	"testing"
)

func otpStoreWithUser(t *testing.T) (*OTPStore, *sql.DB) {
	t.Helper()
	conn := testDB(t)
	insertUser(t, conn, "u1", "u@example.com")
	return NewOTPStore(conn, []byte("a-test-secret-key-that-is-long-enough")), conn
}

func TestOTPIssueAndVerify(t *testing.T) {
	ctx := context.Background()
	store, _ := otpStoreWithUser(t)

	code, err := store.Issue(ctx, "u1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("code %q is not 6 digits", code)
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Fatalf("code %q contains a non-digit", code)
		}
	}

	if err := store.Verify(ctx, "u1", code); err != nil {
		t.Errorf("correct code rejected: %v", err)
	}
	// A code is consumed once verified.
	if err := store.Verify(ctx, "u1", code); err == nil {
		t.Error("code accepted twice")
	}
}

// Codes are stored as a keyed digest, so a database read cannot reveal the
// active code.
func TestOTPCodeStoredHashed(t *testing.T) {
	ctx := context.Background()
	store, conn := otpStoreWithUser(t)

	code, _ := store.Issue(ctx, "u1")

	var count int
	conn.QueryRow(`SELECT COUNT(*) FROM otps WHERE code=?`, code).Scan(&count)
	if count != 0 {
		t.Error("OTP code stored in clear text")
	}
	conn.QueryRow(`SELECT COUNT(*) FROM otps WHERE code=?`, store.hmacCode(code)).Scan(&count)
	if count != 1 {
		t.Error("keyed digest of the OTP code not found")
	}
}

func TestOTPRejectsWrongCode(t *testing.T) {
	ctx := context.Background()
	store, _ := otpStoreWithUser(t)
	store.Issue(ctx, "u1")

	if err := store.Verify(ctx, "u1", "000000"); err == nil {
		t.Error("wrong code accepted")
	}
	if err := store.Verify(ctx, "u1", ""); err == nil {
		t.Error("empty code accepted")
	}
}

func TestOTPVerifyWithoutIssuedCode(t *testing.T) {
	store, _ := otpStoreWithUser(t)
	if err := store.Verify(context.Background(), "u1", "123456"); err == nil {
		t.Error("verification succeeded with no issued code")
	}
}

// Repeated wrong guesses must lock the account rather than allowing unlimited
// attempts against a six digit code.
func TestOTPLockoutAfterRepeatedFailures(t *testing.T) {
	ctx := context.Background()
	store, _ := otpStoreWithUser(t)
	code, _ := store.Issue(ctx, "u1")

	for i := 0; i < 6; i++ {
		store.Verify(ctx, "u1", "000000")
	}
	if err := store.Verify(ctx, "u1", code); err == nil {
		t.Error("correct code accepted while the account should be locked out")
	}
}

func TestOTPIsolatedPerUser(t *testing.T) {
	ctx := context.Background()
	store, conn := otpStoreWithUser(t)
	insertUser(t, conn, "u2", "b@example.com")

	code1, _ := store.Issue(ctx, "u1")
	if err := store.Verify(ctx, "u2", code1); err == nil {
		t.Error("one user's code verified for another user")
	}
}
