package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// EncryptSecret encrypts plaintext with AES-256-GCM using key and returns a hex string.
func EncryptSecret(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(deriveKeyBytes(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ct), nil
}

// DecryptSecret decrypts a hex-encoded AES-256-GCM ciphertext produced by EncryptSecret.
func DecryptSecret(stored string, key []byte) ([]byte, error) {
	data, err := hex.DecodeString(stored)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveKeyBytes(key))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func deriveKeyBytes(key []byte) []byte {
	h := sha256.Sum256(key)
	return h[:]
}

// SettingsCipher adapts the secret encryption helpers to the settings store.
type SettingsCipher struct {
	key []byte
}

// NewSettingsCipher creates a cipher bound to the deployment secret key.
func NewSettingsCipher(key []byte) *SettingsCipher {
	return &SettingsCipher{key: key}
}

// EncryptSecret encrypts a setting value for storage.
func (c *SettingsCipher) EncryptSecret(plaintext string) (string, error) {
	return EncryptSecret([]byte(plaintext), c.key)
}

// DecryptSecret decrypts a stored setting value.
func (c *SettingsCipher) DecryptSecret(ciphertext string) (string, error) {
	pt, err := DecryptSecret(ciphertext, c.key)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
