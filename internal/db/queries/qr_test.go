package queries

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	"github.com/chr0nzz/gatekeeper/internal/db"
)

func queriesTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

const (
	goodBinding = "browser-that-started-the-flow"
	evilBinding = "someone-elses-browser"
)

func TestQRTokenConsumedOnce(t *testing.T) {
	ctx := context.Background()
	store := NewQRTokenStore(queriesTestDB(t))

	id, err := store.Create(ctx, "", "", goodBinding)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Approve(ctx, id, "user-1"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	first, err := store.Consume(ctx, id, goodBinding)
	if err != nil || first == nil {
		t.Fatalf("first consume failed: tok=%v err=%v", first, err)
	}
	if first.UserID != "user-1" {
		t.Fatalf("got user %q, want user-1", first.UserID)
	}

	second, err := store.Consume(ctx, id, goodBinding)
	if err != nil {
		t.Fatalf("second consume errored: %v", err)
	}
	if second != nil {
		t.Fatal("token consumed twice, every poll would mint a session")
	}
}

func TestQRTokenRequiresMatchingBinding(t *testing.T) {
	ctx := context.Background()
	store := NewQRTokenStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "", "", goodBinding)
	store.Approve(ctx, id, "user-1")

	if tok, _ := store.Consume(ctx, id, evilBinding); tok != nil {
		t.Fatal("token claimed by a browser that did not start the flow")
	}
	if tok, _ := store.Consume(ctx, id, ""); tok != nil {
		t.Fatal("token claimed with an empty binding")
	}
	if tok, _ := store.Consume(ctx, id, goodBinding); tok == nil {
		t.Fatal("legitimate browser could not claim the token afterwards")
	}
}

func TestQRTokenNotConsumableBeforeApproval(t *testing.T) {
	ctx := context.Background()
	store := NewQRTokenStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "", "", goodBinding)
	if tok, _ := store.Consume(ctx, id, goodBinding); tok != nil {
		t.Fatal("pending token was consumed before approval")
	}
}

func TestQRTokenConcurrentConsumeYieldsOneWinner(t *testing.T) {
	ctx := context.Background()
	store := NewQRTokenStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "", "", goodBinding)
	store.Approve(ctx, id, "user-1")

	var mu sync.Mutex
	wins := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, _ := store.Consume(ctx, id, goodBinding); tok != nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d concurrent consumers succeeded, want exactly 1", wins)
	}
}
