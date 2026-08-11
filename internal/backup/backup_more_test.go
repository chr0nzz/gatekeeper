package backup

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

var bkp2Key = []byte("another-test-secret-key-long-enough")

const bkp2SQLiteMagic = "SQLite format 3\x00"

func bkp2DB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backup.db")
	conn, err := db.Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, path
}

func TestCreateProducesEncryptedSqliteSnapshot(t *testing.T) {
	ctx := context.Background()
	conn, path := bkp2DB(t)

	settings := queries.NewSettingsStore(conn)
	if err := settings.Set(ctx, "site_name", "canary-value-in-snapshot"); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	data, name, err := Create(ctx, conn, path, bkp2Key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("backup blob is empty")
	}

	namePattern := regexp.MustCompile(`^gatekeeper-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\.db\.enc$`)
	if !namePattern.MatchString(name) {
		t.Errorf("backup name %q is not a UTC timestamped .db.enc name", name)
	}

	if bytes.Contains(data, []byte(bkp2SQLiteMagic)) {
		t.Error("backup blob leaks the SQLite header, so it is not encrypted")
	}
	if bytes.Contains(data, []byte("canary-value-in-snapshot")) {
		t.Error("backup blob leaks database contents in clear text")
	}

	plain, err := Decrypt(data, bkp2Key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.HasPrefix(plain, []byte(bkp2SQLiteMagic)) {
		t.Fatalf("decrypted snapshot starts with %q, want the SQLite magic header", plain[:min(16, len(plain))])
	}
	if !bytes.Contains(plain, []byte("canary-value-in-snapshot")) {
		t.Error("snapshot does not contain data written before the backup")
	}
}

// A restore must be able to open the snapshot as a database, otherwise the
// backup is only decorative.
func TestCreateSnapshotIsAnOpenableDatabase(t *testing.T) {
	ctx := context.Background()
	conn, path := bkp2DB(t)

	users := queries.NewUserStore(conn)
	if _, err := users.Create(ctx, "restored@example.com", "hash", true); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	data, _, err := Create(ctx, conn, path, bkp2Key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	plain, err := Decrypt(data, bkp2Key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restored, plain, 0600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	rconn, err := db.Open(restored)
	if err != nil {
		t.Fatalf("open restored snapshot: %v", err)
	}
	defer rconn.Close()

	var email string
	if err := rconn.QueryRow(`SELECT email FROM users`).Scan(&email); err != nil {
		t.Fatalf("read restored user: %v", err)
	}
	if email != "restored@example.com" {
		t.Errorf("restored user email = %q", email)
	}
}

// Restoring a real snapshot with the wrong key or a damaged file must fail,
// never panic and never hand back partial plaintext.
func TestDecryptOfRealSnapshotRejectsWrongKeyAndDamage(t *testing.T) {
	ctx := context.Background()
	conn, path := bkp2DB(t)

	data, _, err := Create(ctx, conn, path, bkp2Key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if plain, err := Decrypt(data, []byte("a-totally-unrelated-secret-key-42")); err == nil {
		t.Errorf("wrong key decrypted %d bytes", len(plain))
	}

	for _, cut := range []int{0, 1, 11, 12, 13, len(data) / 2, len(data) - 1} {
		if plain, err := Decrypt(data[:cut], bkp2Key); err == nil {
			t.Errorf("truncation to %d bytes was accepted, returned %d bytes", cut, len(plain))
		}
	}

	flipped := bytes.Clone(data)
	flipped[len(flipped)/2] ^= 0x01
	if _, err := Decrypt(flipped, bkp2Key); err == nil {
		t.Error("a single flipped ciphertext bit was accepted")
	}

	nonceFlipped := bytes.Clone(data)
	nonceFlipped[0] ^= 0x01
	if _, err := Decrypt(nonceFlipped, bkp2Key); err == nil {
		t.Error("a tampered nonce was accepted")
	}
}

func TestLocalStorageRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "backups")

	store, err := NewLocalStorage(dir)
	if err != nil {
		t.Fatalf("new local storage: %v", err)
	}
	if store.StorageType() != "local" {
		t.Errorf("StorageType() = %q, want local", store.StorageType())
	}

	blobs := map[string][]byte{
		"gatekeeper-2026-01-01T00-00-00Z.db.enc": []byte("first-backup-bytes"),
		"gatekeeper-2026-01-02T00-00-00Z.db.enc": []byte("second-backup-bytes"),
	}
	for name, data := range blobs {
		if err := store.Upload(ctx, name, data); err != nil {
			t.Fatalf("upload %s: %v", name, err)
		}
	}

	for name, want := range blobs {
		got, err := store.Download(ctx, name)
		if err != nil {
			t.Fatalf("download %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("download %s = %q, want %q", name, got, want)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != len(blobs) {
		t.Fatalf("directory holds %d files, want %d", len(entries), len(blobs))
	}
	for _, e := range entries {
		if _, ok := blobs[e.Name()]; !ok {
			t.Errorf("unexpected file %q in backup directory", e.Name())
		}
	}

	for name := range blobs {
		if err := store.Delete(ctx, name); err != nil {
			t.Fatalf("delete %s: %v", name, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files left after deleting every backup", len(entries))
	}
}

func TestLocalStorageDownloadOfMissingNameErrors(t *testing.T) {
	ctx := context.Background()
	store, err := NewLocalStorage(filepath.Join(t.TempDir(), "backups"))
	if err != nil {
		t.Fatalf("new local storage: %v", err)
	}

	if data, err := store.Download(ctx, "gatekeeper-never-written.db.enc"); err == nil {
		t.Errorf("download of a missing backup returned %d bytes and no error", len(data))
	}

	// Delete is idempotent so retention pruning does not fail on an already
	// removed object.
	if err := store.Delete(ctx, "gatekeeper-never-written.db.enc"); err != nil {
		t.Errorf("delete of a missing backup returned %v, want nil", err)
	}
}

// A backup file is a full copy of the user database, so it must not be readable
// by other accounts on the host.
func TestLocalStorageFilesAreNotWorldReadable(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "backups")
	store, err := NewLocalStorage(dir)
	if err != nil {
		t.Fatalf("new local storage: %v", err)
	}
	if err := store.Upload(ctx, "secret.db.enc", []byte("ciphertext")); err != nil {
		t.Fatalf("upload: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm&0077 != 0 {
		t.Errorf("backup directory mode %04o is accessible to group or others", perm)
	}

	fileInfo, err := os.Stat(filepath.Join(dir, "secret.db.enc"))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm&0077 != 0 {
		t.Errorf("backup file mode %04o is readable by group or others", perm)
	}
}

func TestBuildStorageReturnsNilUntilConfigured(t *testing.T) {
	ctx := context.Background()
	conn, _ := bkp2DB(t)
	settings := queries.NewSettingsStore(conn)

	if s := BuildStorage(settings); s != nil {
		t.Errorf("BuildStorage with no settings = %T, want nil", s)
	}

	for _, val := range []string{"", "none", "ftp"} {
		settings.Set(ctx, "backup_storage", val)
		if s := BuildStorage(settings); s != nil {
			t.Errorf("BuildStorage with backup_storage=%q = %T, want nil", val, s)
		}
	}

	settings.Set(ctx, "backup_storage", "local")
	if s := BuildStorage(settings); s != nil {
		t.Errorf("BuildStorage with local storage and no path = %T, want nil", s)
	}
}

func TestBuildStorageLocalUsesConfiguredDirectory(t *testing.T) {
	ctx := context.Background()
	conn, _ := bkp2DB(t)
	settings := queries.NewSettingsStore(conn)

	dir := filepath.Join(t.TempDir(), "configured")
	settings.Set(ctx, "backup_storage", "local")
	settings.Set(ctx, "backup_local_path", dir)

	store := BuildStorage(settings)
	if store == nil {
		t.Fatal("BuildStorage returned nil for a configured local backend")
	}
	if store.StorageType() != "local" {
		t.Fatalf("StorageType() = %q, want local", store.StorageType())
	}
	if _, ok := store.(*LocalStorage); !ok {
		t.Fatalf("BuildStorage returned %T, want *LocalStorage", store)
	}

	if err := store.Upload(ctx, "check.db.enc", []byte("payload")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	written, err := os.ReadFile(filepath.Join(dir, "check.db.enc"))
	if err != nil {
		t.Fatalf("backup was not written to the configured directory: %v", err)
	}
	if string(written) != "payload" {
		t.Errorf("written backup = %q, want payload", written)
	}
}

// Half configured object storage must not produce an uploader that silently
// fails every scheduled backup.
func TestBuildStorageS3RequiresCompleteCredentials(t *testing.T) {
	ctx := context.Background()
	conn, _ := bkp2DB(t)
	settings := queries.NewSettingsStore(conn)
	settings.SetCipher(auth.NewSettingsCipher(bkp2Key))

	complete := map[string]string{
		"backup_storage":          "s3",
		"backup_s3_endpoint":      "https://s3.example.com",
		"backup_s3_bucket":        "gk-backups",
		"backup_s3_access_key":    "AKIAEXAMPLE",
		"backup_s3_secret_key":    "s3-secret-value",
		"backup_s3_region":        "eu-central-1",
		"backup_s3_path_style":    "true",
		"backup_local_path":       "",
		"backup_s3_prefix":        "gatekeeper",
		"backup_retention_count":  "5",
		"backup_schedule_setting": "daily",
	}

	for _, missing := range []string{"backup_s3_endpoint", "backup_s3_bucket", "backup_s3_access_key", "backup_s3_secret_key"} {
		for k, v := range complete {
			settings.Set(ctx, k, v)
		}
		settings.Set(ctx, missing, "")
		if s := BuildStorage(settings); s != nil {
			t.Errorf("BuildStorage without %s = %T, want nil", missing, s)
		}
	}

	for k, v := range complete {
		settings.Set(ctx, k, v)
	}
	store := BuildStorage(settings)
	if store == nil {
		t.Fatal("BuildStorage returned nil for fully configured s3")
	}
	if store.StorageType() != "s3" {
		t.Errorf("StorageType() = %q, want s3", store.StorageType())
	}
	s3, ok := store.(*S3Storage)
	if !ok {
		t.Fatalf("BuildStorage returned %T, want *S3Storage", store)
	}
	if s3.prefix != "gatekeeper/" {
		t.Errorf("prefix = %q, want gatekeeper/", s3.prefix)
	}
	if s3.client.secretKey != "s3-secret-value" {
		t.Errorf("secret key = %q, want the decrypted value", s3.client.secretKey)
	}
}

func TestScheduleIntervalExactDurations(t *testing.T) {
	want := map[string]time.Duration{
		"hourly": time.Hour,
		"daily":  24 * time.Hour,
		"weekly": 7 * 24 * time.Hour,
	}
	for schedule, d := range want {
		if got := ScheduleInterval(schedule); got != d {
			t.Errorf("ScheduleInterval(%q) = %v, want %v", schedule, got, d)
		}
	}

	// Anything the scheduler does not understand must disable automatic
	// backups rather than pick an arbitrary interval.
	for _, unknown := range []string{"", "manual", "Daily", "HOURLY", "monthly", "1h", "never", " daily "} {
		if got := ScheduleInterval(unknown); got != 0 {
			t.Errorf("ScheduleInterval(%q) = %v, want 0", unknown, got)
		}
	}
}
