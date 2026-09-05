package db

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectionAppliesWALAndBusyTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pragma.db")
	conn, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	var journal string
	if err := conn.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if journal != "wal" {
		t.Errorf("journal_mode = %q, want wal; DSN pragmas are not being applied", journal)
	}

	var busy int
	if err := conn.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if busy < 1000 {
		t.Errorf("busy_timeout = %d, want at least 1000; writes will fail instantly under contention", busy)
	}
}

func TestSnapshotConnectionDoesNotBlockWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.db")
	conn, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 200; i++ {
		if _, err := conn.Exec(`INSERT INTO t (v) VALUES (?)`, "row"); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	snap, err := OpenSnapshot(path)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer snap.Close()

	tmp := filepath.Join(t.TempDir(), "copy.db")
	done := make(chan error, 1)
	go func() {
		_, err := snap.Exec(`VACUUM INTO ?`, tmp)
		done <- err
	}()

	for i := 0; i < 50; i++ {
		if _, err := conn.Exec(`INSERT INTO t (v) VALUES (?)`, "during-backup"); err != nil {
			t.Fatalf("write during backup failed: %v", err)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("vacuum into: %v", err)
	}
}

func TestSnapshotConnectionHasItsOwnBusyTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.db")
	conn, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	snap, err := OpenSnapshot(path)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer snap.Close()

	var busy int
	if err := snap.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if busy < 1000 {
		t.Errorf("snapshot busy_timeout = %d, want at least 1000", busy)
	}
}

func TestOpenRefusesAConnectionWithoutABusyTimeout(t *testing.T) {
	if !strings.Contains(sqliteParams, "busy_timeout") {
		t.Fatal("the DSN no longer sets busy_timeout")
	}
	if !strings.Contains(sqliteParams, "_pragma=") {
		t.Fatal("the DSN uses parameters this driver ignores; modernc.org/sqlite reads only _pragma=")
	}
	for _, ignored := range []string{"_journal=", "_timeout=", "_fk=", "mode=ro"} {
		if strings.Contains(sqliteParams, ignored) {
			t.Errorf("DSN contains %q, which modernc.org/sqlite silently ignores", ignored)
		}
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "fk.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	var on int
	if err := conn.QueryRow(`PRAGMA foreign_keys`).Scan(&on); err != nil {
		t.Fatalf("foreign_keys: %v", err)
	}
	if on != 1 {
		t.Errorf("foreign_keys = %d, want 1", on)
	}
}
