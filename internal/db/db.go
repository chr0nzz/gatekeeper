package db

import (
	"database/sql"
	"embed"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open opens the SQLite database and runs all pending migrations.
func Open(path string) (*sql.DB, error) {
	if err := applyPendingRestore(path); err != nil {
		return nil, fmt.Errorf("apply restore: %w", err)
	}
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000&_fk=true")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// applyPendingRestore swaps in a restored database written by the backup restore handler.
// If <path>.restore exists, it replaces the live database and clears stale WAL sidecar files.
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
