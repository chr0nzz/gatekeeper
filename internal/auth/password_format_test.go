package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func legacyHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("salt: %v", err)
	}
	h := argon2.IDKey([]byte(password), salt, legacyArgonIterations, legacyArgonMemory, legacyArgonParallelism, argonKeyLen)
	return fmt.Sprintf("$argon2id$%x$%x", salt, h)
}

func TestLegacyHashesStillVerify(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	stored := legacyHash(t, pw)

	if err := VerifyPassword(pw, stored); err != nil {
		t.Fatalf("a hash written by an older version no longer verifies: %v", err)
	}
	if err := VerifyPassword("wrong-password-entirely", stored); err == nil {
		t.Error("a wrong password verified against a legacy hash")
	}
}

func TestNewHashesCarryTheirParameters(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	stored, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if !strings.Contains(stored, "v=") || !strings.Contains(stored, "m=") {
		t.Errorf("stored hash carries no parameters: %q", stored)
	}
	if err := VerifyPassword(pw, stored); err != nil {
		t.Errorf("a freshly written hash does not verify: %v", err)
	}
	if err := VerifyPassword("wrong-password-entirely", stored); err == nil {
		t.Error("a wrong password verified")
	}
}

func TestParametersAreReadFromTheHashNotTheConstants(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	salt := make([]byte, argonSaltLen)
	rand.Read(salt)
	h := argon2.IDKey([]byte(pw), salt, 1, 8*1024, 1, argonKeyLen)
	stored := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%x$%x", argon2.Version, 8*1024, 1, 1, salt, h)

	if err := VerifyPassword(pw, stored); err != nil {
		t.Fatalf("a hash with non-default parameters did not verify: %v", err)
	}
	if !NeedsRehash(stored) {
		t.Error("a hash with weaker parameters was not flagged for rehashing")
	}
	current, _ := HashPassword(pw)
	if NeedsRehash(current) {
		t.Error("a current-parameter hash was flagged for rehashing")
	}
}

func TestMalformedHashesAreRejected(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2id$",
		"$argon2id$zz$zz",
		"$argon2id$v=19$m=0,t=0,p=0$aa$bb",
		"$bcrypt$abc$def",
		"$argon2id$v=19$garbage$aa$bb",
	} {
		if err := VerifyPassword("anything", bad); err == nil {
			t.Errorf("malformed hash %q was accepted", bad)
		}
	}
}

func TestLegacyAndNewHashesOfSamePasswordBothWork(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	legacy := legacyHash(t, pw)
	modern, _ := HashPassword(pw)

	if legacy == modern {
		t.Fatal("formats are indistinguishable")
	}
	for name, stored := range map[string]string{"legacy": legacy, "modern": modern} {
		if err := VerifyPassword(pw, stored); err != nil {
			t.Errorf("%s hash failed to verify: %v", name, err)
		}
	}
	if _, err := hex.DecodeString(strings.Split(legacy, "$")[2]); err != nil {
		t.Errorf("legacy salt is not hex: %v", err)
	}
}
