package backup

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

// RunFunc is called by the Scheduler to perform a backup.
type RunFunc func(ctx context.Context) error

// Scheduler runs automatic backups on a configurable interval.
type Scheduler struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

// Start launches the backup scheduler, re-reading its interval before each tick.
func (s *Scheduler) Start(intervalFn func() time.Duration, run RunFunc) {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.mu.Unlock()

	go func() {
		for {
			d := intervalFn()
			if d <= 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Minute):
					continue
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
				if err := run(ctx); err != nil {
					slog.Error("scheduled backup failed", "err", err)
				}
			}
		}
	}()
}

// Stop cancels the background scheduler goroutine.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}

// ScheduleInterval converts a settings value ("hourly", "daily", "weekly") to a duration.
func ScheduleInterval(val string) time.Duration {
	switch val {
	case "hourly":
		return time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	}
	return 0
}

// BuildStorage constructs the active Storage from settings. Returns nil if backups are not configured.
func BuildStorage(settings *queries.SettingsStore) Storage {
	ctx := context.Background()
	get := func(k string) string { return settings.Get(ctx, k, "") }

	storageType := get("backup_storage")
	switch storageType {
	case "local":
		dir := get("backup_local_path")
		if dir == "" {
			return nil
		}
		s, err := NewLocalStorage(dir)
		if err != nil {
			slog.Error("backup: local storage init failed", "err", err)
			return nil
		}
		return s
	case "s3":
		endpoint := get("backup_s3_endpoint")
		bucket := get("backup_s3_bucket")
		accessKey := get("backup_s3_access_key")
		secretKey := get("backup_s3_secret_key")
		if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
			return nil
		}
		region := get("backup_s3_region")
		prefix := get("backup_s3_prefix")
		pathStyle := get("backup_s3_path_style") == "true"
		return NewS3Storage(endpoint, bucket, accessKey, secretKey, region, prefix, pathStyle)
	}
	return nil
}

// RunBackup performs a single backup: creates snapshot, uploads to storage, records in DB, prunes old entries.
func RunBackup(ctx context.Context, db *sql.DB, dbPath string, secretKey []byte, storage Storage, backupStore *queries.BackupStore, retention int) error {
	data, name, err := Create(ctx, db, dbPath, secretKey)
	if err != nil {
		return err
	}

	if err := storage.Upload(ctx, name, data); err != nil {
		return err
	}

	now := time.Now().Unix()
	if _, err := backupStore.Create(ctx, name, storage.StorageType(), int64(len(data)), now); err != nil {
		return err
	}

	if retention > 0 {
		oldNames, _ := backupStore.PruneOldest(ctx, storage.StorageType(), retention)
		for _, n := range oldNames {
			if delErr := storage.Delete(ctx, n); delErr != nil {
				slog.Warn("backup: failed to delete old object", "name", n, "err", delErr)
			}
		}
	}

	slog.Info("backup completed", "name", name, "storage", storage.StorageType(), "size", len(data))
	return nil
}
