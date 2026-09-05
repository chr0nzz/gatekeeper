package db

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

const sqliteParams = "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(on)"

//go:embed migrations/*.sql
var migrations embed.FS

// Open opens the SQLite database and runs all pending migrations.
func Open(path string) (*sql.DB, error) {
	if err := applyPendingRestore(path); err != nil {
		return nil, fmt.Errorf("apply restore: %w", err)
	}
	db, err := sql.Open("sqlite", path+sqliteParams)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := verifyConnection(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func OpenSnapshot(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+sqliteParams)
	if err != nil {
		return nil, fmt.Errorf("open sqlite snapshot: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := verifyConnection(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func verifyConnection(db *sql.DB) error {
	var busy int
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		return fmt.Errorf("read busy_timeout: %w", err)
	}
	if busy < 1000 {
		return fmt.Errorf("busy_timeout is %dms, expected at least 1000ms: the connection settings in %q were not applied by the driver", busy, sqliteParams)
	}

	var journal string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		return fmt.Errorf("read journal_mode: %w", err)
	}
	if !strings.EqualFold(journal, "wal") {
		slog.Warn("sqlite is not in WAL mode, concurrent reads and writes will contend",
			"journal_mode", journal, "hint", "WAL needs a filesystem supporting shared memory, not NFS or similar")
	}

	slog.Info("sqlite ready", "journal_mode", journal, "busy_timeout_ms", busy)
	return nil
}

func applyPendingRestore(path string) error {
	restorePath := path + ".restore"
	if _, err := os.Stat(restorePath); err != nil {
		return nil
	}
	for _, sidecar := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Rename(restorePath, path)
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		var count int
		db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name=?`, e.Name()).Scan(&count)
		if count > 0 {
			continue
		}
		data, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		if _, err := db.Exec(string(data)); err != nil {
			return fmt.Errorf("migration %s: %w", e.Name(), err)
		}
		db.Exec(`INSERT INTO schema_migrations (name) VALUES (?)`, e.Name())
	}
	return nil
}
