package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	gkdb "github.com/chr0nzz/gatekeeper/internal/db"
)

// Create takes an encrypted snapshot of the database and returns it with its name.
func Create(ctx context.Context, db *sql.DB, dbPath string, secretKey []byte) (data []byte, name string, err error) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("gk-backup-%d.db", time.Now().UnixNano()))
	defer os.Remove(tmp)

	snap, err := gkdb.OpenSnapshot(dbPath)
	if err != nil {
		return nil, "", fmt.Errorf("open snapshot connection: %w", err)
	}
	defer snap.Close()

	if _, err = snap.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		return nil, "", fmt.Errorf("vacuum into: %w", err)
	}

	raw, err := os.ReadFile(tmp)
	if err != nil {
		return nil, "", fmt.Errorf("read snapshot: %w", err)
	}

	enc, err := encrypt(raw, secretKey)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt: %w", err)
	}

	name = fmt.Sprintf("gatekeeper-%s.db.enc", time.Now().UTC().Format("2006-01-02T15-04-05Z"))
	return enc, name, nil
}

// Decrypt decrypts a backup blob produced by Create and returns the raw SQLite bytes.
func Decrypt(data []byte, secretKey []byte) ([]byte, error) {
	return decrypt(data, secretKey)
}

func deriveKey(secretKey []byte) []byte {
	sum := sha256.Sum256(secretKey)
	return sum[:]
}

func encrypt(plaintext, secretKey []byte) ([]byte, error) {
	key := deriveKey(secretKey)
	block, err := aes.NewCipher(key)
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

func decrypt(ciphertext, secretKey []byte) ([]byte, error) {
	key := deriveKey(secretKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
