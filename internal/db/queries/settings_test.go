package queries

import (
	"context"
	"strings"
	"testing"

	"github.com/chr0nzz/gatekeeper/internal/auth"
)

func TestSecretSettingsEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	store := NewSettingsStore(conn)
	store.SetCipher(auth.NewSettingsCipher([]byte("a-test-secret-key-that-is-long-enough")))

	secrets := map[string]string{
		"smtp_password":               "hunter2-smtp",
		"backup_s3_secret_key":        "s3-secret-value",
		"social_github_client_secret": "github-oauth-secret",
		"webhook_telegram_token":      "telegram-bot-token",
	}
	for key, value := range secrets {
		if err := store.Set(ctx, key, value); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}

	for key, value := range secrets {
		var stored string
		if err := conn.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&stored); err != nil {
			t.Fatalf("read raw %s: %v", key, err)
		}
		if stored == value {
			t.Errorf("%s is stored in clear text", key)
		}
		if strings.Contains(stored, value) {
			t.Errorf("%s ciphertext contains the plaintext", key)
		}
		if got := store.Get(ctx, key, ""); got != value {
			t.Errorf("Get(%s) = %q, want %q", key, got, value)
		}
	}

	all := store.GetAll(ctx)
	for key, value := range secrets {
		if all[key] != value {
			t.Errorf("GetAll[%s] = %q, want decrypted %q", key, all[key], value)
		}
	}
}

func TestNonSecretSettingsStoredPlainly(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	store := NewSettingsStore(conn)
	store.SetCipher(auth.NewSettingsCipher([]byte("a-test-secret-key-that-is-long-enough")))

	store.Set(ctx, "smtp_host", "smtp.example.com")

	var stored string
	conn.QueryRow(`SELECT value FROM settings WHERE key=?`, "smtp_host").Scan(&stored)
	if stored != "smtp.example.com" {
		t.Errorf("non-secret setting was transformed: %q", stored)
	}
}

func TestIsSecretKey(t *testing.T) {
	secret := []string{
		"smtp_password", "social_google_client_secret", "webhook_bot_token",
		"backup_s3_secret_key", "backup_s3_access_key",
	}
	for _, k := range secret {
		if !IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"smtp_host", "smtp_port", "session_ttl_hours", "login_app_name"} {
		if IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = true, want false", k)
		}
	}
}

func TestSettingsWithoutCipher(t *testing.T) {
	ctx := context.Background()
	store := NewSettingsStore(queriesTestDB(t))
	store.Set(ctx, "smtp_password", "plain")
	if got := store.Get(ctx, "smtp_password", ""); got != "plain" {
		t.Errorf("Get = %q, want plain", got)
	}
}
