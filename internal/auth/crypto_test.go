package auth

import (
	"strings"
	"testing"
)

var cryptoKey = []byte("a-test-secret-key-that-is-long-enough")

func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, plain := range []string{"", "short", strings.Repeat("long secret ", 100), "unicode: café 🔐"} {
		enc, err := EncryptSecret([]byte(plain), cryptoKey)
		if err != nil {
			t.Fatalf("encrypt %q: %v", plain, err)
		}
		got, err := DecryptSecret(enc, cryptoKey)
		if err != nil {
			t.Fatalf("decrypt %q: %v", plain, err)
		}
		if string(got) != plain {
			t.Errorf("round trip = %q, want %q", got, plain)
		}
	}
}

func TestCiphertextHidesPlaintext(t *testing.T) {
	plain := "super-secret-value"
	enc, _ := EncryptSecret([]byte(plain), cryptoKey)
	if strings.Contains(enc, plain) {
		t.Error("ciphertext contains the plaintext")
	}
}

// AES-GCM must use a fresh nonce per encryption, so identical inputs never
// produce identical ciphertext.
func TestEncryptionIsNonDeterministic(t *testing.T) {
	a, _ := EncryptSecret([]byte("same"), cryptoKey)
	b, _ := EncryptSecret([]byte("same"), cryptoKey)
	if a == b {
		t.Error("encrypting the same value twice produced identical ciphertext")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	enc, _ := EncryptSecret([]byte("secret"), cryptoKey)
	if _, err := DecryptSecret(enc, []byte("a-different-key-of-sufficient-length")); err == nil {
		t.Error("decrypted with the wrong key")
	}
}

// GCM is authenticated, so any modification must be detected rather than
// returning corrupted plaintext.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	enc, _ := EncryptSecret([]byte("secret"), cryptoKey)

	tampered := []byte(enc)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := DecryptSecret(string(tampered), cryptoKey); err == nil {
		t.Error("tampered ciphertext was accepted")
	}

	for _, bad := range []string{"", "not-base64!!", "AAAA"} {
		if _, err := DecryptSecret(bad, cryptoKey); err == nil {
			t.Errorf("malformed input %q was accepted", bad)
		}
	}
}

func TestSettingsCipherRoundTrip(t *testing.T) {
	c := NewSettingsCipher(cryptoKey)
	enc, err := c.EncryptSecret("smtp-password")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := c.DecryptSecret(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != "smtp-password" {
		t.Errorf("got %q, want smtp-password", got)
	}
	if _, err := c.DecryptSecret("garbage"); err == nil {
		t.Error("cipher accepted garbage input")
	}
}
