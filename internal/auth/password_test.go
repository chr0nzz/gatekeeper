package auth

import (
	"context"
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if strings.Contains(hash, "correct horse") {
		t.Fatal("hash contains the password")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash is not argon2id: %q", hash)
	}
	if err := VerifyPassword("correct horse battery staple", hash); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := VerifyPassword("wrong password", hash); err == nil {
		t.Error("wrong password accepted")
	}
}

// The salt must differ per hash, so two users with the same password do not
// share a hash.
func TestPasswordHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same-password")
	b, _ := HashPassword("same-password")
	if a == b {
		t.Error("identical passwords produced identical hashes")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	for _, stored := range []string{"", "plaintext", "$argon2id$broken", "$argon2id$v=19$m=1,t=1,p=1$bad$bad"} {
		if err := VerifyPassword("anything", stored); err == nil {
			t.Errorf("malformed stored hash %q was accepted", stored)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	cases := []struct {
		name     string
		password string
		minLen   int
		upper    bool
		number   bool
		symbol   bool
		wantErr  bool
	}{
		{"meets minimum", "abcdefgh", 8, false, false, false, false},
		{"too short", "abc", 8, false, false, false, true},
		{"needs uppercase", "abcdefgh", 8, true, false, false, true},
		{"has uppercase", "Abcdefgh", 8, true, false, false, false},
		{"needs number", "Abcdefgh", 8, true, true, false, true},
		{"has number", "Abcdefg1", 8, true, true, false, false},
		{"needs symbol", "Abcdefg1", 8, true, true, true, true},
		{"has symbol", "Abcdefg1!", 8, true, true, true, false},
		{"empty", "", 8, false, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPasswordPolicy(tc.password, tc.minLen, tc.upper, tc.number, tc.symbol)
			if tc.wantErr && err == nil {
				t.Errorf("CheckPasswordPolicy(%q) = nil, want error", tc.password)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("CheckPasswordPolicy(%q) = %v, want nil", tc.password, err)
			}
		})
	}
}

// Reset tokens are bearer credentials: they must be single use and stored hashed.
func TestPasswordResetTokenSingleUse(t *testing.T) {
	ctx := context.Background()
	conn := testDB(t)
	insertUser(t, conn, "u1", "u@example.com")
	store := NewPasswordResetStore(conn)

	token, err := store.IssueToken(ctx, "u1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var raw int
	conn.QueryRow(`SELECT COUNT(*) FROM password_resets WHERE token_hash=?`, token).Scan(&raw)
	if raw != 0 {
		t.Error("reset token stored unhashed")
	}

	userID, err := store.Redeem(ctx, token)
	if err != nil || userID != "u1" {
		t.Fatalf("redeem = %q, %v; want u1, nil", userID, err)
	}
	if _, err := store.Redeem(ctx, token); err == nil {
		t.Error("reset token redeemed twice")
	}
}

func TestPasswordResetRejectsUnknownToken(t *testing.T) {
	store := NewPasswordResetStore(testDB(t))
	if _, err := store.Redeem(context.Background(), "not-a-token"); err == nil {
		t.Error("unknown reset token was accepted")
	}
}
