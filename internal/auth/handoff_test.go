package auth

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/db"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func insertUser(t *testing.T, conn *sql.DB, id, email string) {
	t.Helper()
	_, err := conn.Exec(
		`INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES (?,?,'',0,0)`,
		id, email,
	)
	if err != nil {
		t.Fatalf("insert user %s: %v", id, err)
	}
}

func TestHandoffTokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	store := NewHandoffStore(testDB(t))

	token, err := store.Create(ctx, "user-1", "app.example.com")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	userID, err := store.Redeem(ctx, token, "app.example.com")
	if err != nil {
		t.Fatalf("first redeem failed: %v", err)
	}
	if userID != "user-1" {
		t.Fatalf("got user %q, want user-1", userID)
	}

	if _, err := store.Redeem(ctx, token, "app.example.com"); err == nil {
		t.Fatal("second redeem succeeded, token must be single-use")
	}
}

func TestHandoffTokenIsHostBound(t *testing.T) {
	ctx := context.Background()
	store := NewHandoffStore(testDB(t))

	token, _ := store.Create(ctx, "user-1", "app.example.com")

	if _, err := store.Redeem(ctx, token, "evil.com"); err == nil {
		t.Fatal("token redeemed by the wrong host")
	}
	if _, err := store.Redeem(ctx, token, "app.example.com"); err != nil {
		t.Fatalf("legitimate redeem failed after wrong-host attempt: %v", err)
	}
}

func TestHandoffTokenRejectsUnknownAndExpired(t *testing.T) {
	ctx := context.Background()
	conn := testDB(t)
	store := NewHandoffStore(conn)

	if _, err := store.Redeem(ctx, "not-a-real-token", "app.example.com"); err == nil {
		t.Error("unknown token was accepted")
	}

	token, _ := store.Create(ctx, "user-1", "app.example.com")
	conn.Exec(`UPDATE handoff_tokens SET expires_at=? WHERE user_id='user-1'`, time.Now().Add(-time.Minute).Unix())
	if _, err := store.Redeem(ctx, token, "app.example.com"); err == nil {
		t.Error("expired token was accepted")
	}
}

func TestHandoffTokenStoredHashed(t *testing.T) {
	ctx := context.Background()
	conn := testDB(t)
	store := NewHandoffStore(conn)

	token, _ := store.Create(ctx, "user-1", "app.example.com")

	var count int
	conn.QueryRow(`SELECT COUNT(*) FROM handoff_tokens WHERE id=?`, token).Scan(&count)
	if count != 0 {
		t.Error("raw handoff token is stored in the database")
	}
	conn.QueryRow(`SELECT COUNT(*) FROM handoff_tokens WHERE id=?`, hashToken(token)).Scan(&count)
	if count != 1 {
		t.Error("hashed handoff token not found")
	}
}
