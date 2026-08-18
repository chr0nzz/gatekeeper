package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRunsMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	conn, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	tables := []string{
		"users", "sessions", "otps", "totp_recovery_codes", "trusted_devices",
		"oidc_clients", "oidc_tokens", "policies", "groups", "invites",
		"webhooks", "backups", "admin_users", "qr_login_tokens", "handoff_tokens",
		"settings", "audit_log",
	}
	for _, table := range tables {
		var name string
		err := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %s missing after migration: %v", table, err)
		}
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	var applied int
	first.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied)
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer second.Close()

	var appliedAgain int
	second.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&appliedAgain)
	if applied != appliedAgain {
		t.Errorf("migration count changed on reopen: %d then %d", applied, appliedAgain)
	}
	if applied == 0 {
		t.Error("no migrations were recorded")
	}
}

func TestPendingRestoreIsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gatekeeper.db")

	conn, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	conn.Exec(`INSERT INTO settings (key, value) VALUES ('marker','original')`)
	conn.Close()

	restoreSrc := filepath.Join(dir, "restore-source.db")
	src, err := Open(restoreSrc)
	if err != nil {
		t.Fatalf("open restore source: %v", err)
	}
	src.Exec(`INSERT INTO settings (key, value) VALUES ('marker','restored')`)
	src.Close()

	restoreBytes, err := os.ReadFile(restoreSrc)
	if err != nil {
		t.Fatalf("read restore source: %v", err)
	}
	if err := os.WriteFile(path+".restore", restoreBytes, 0600); err != nil {
		t.Fatalf("stage restore: %v", err)
	}
	os.WriteFile(path+"-wal", []byte("stale"), 0600)
	os.WriteFile(path+"-shm", []byte("stale"), 0600)

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("open after staging restore: %v", err)
	}
	defer reopened.Close()

	var marker string
	if err := reopened.QueryRow(`SELECT value FROM settings WHERE key='marker'`).Scan(&marker); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if marker != "restored" {
		t.Errorf("marker = %q, want restored", marker)
	}
	if _, err := os.Stat(path + ".restore"); !os.IsNotExist(err) {
		t.Error("staged restore file was left behind")
	}
}

func TestNoRestoreLeavesDatabaseAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gatekeeper.db")
	conn, _ := Open(path)
	conn.Exec(`INSERT INTO settings (key, value) VALUES ('marker','kept')`)
	conn.Close()

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	var marker string
	reopened.QueryRow(`SELECT value FROM settings WHERE key='marker'`).Scan(&marker)
	if marker != "kept" {
		t.Errorf("marker = %q, want kept", marker)
	}
}
