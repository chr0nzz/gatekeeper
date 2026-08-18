package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/db"
)

func audTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

type audRow struct {
	event     sql.NullString
	userID    sql.NullString
	actorID   sql.NullString
	ip        sql.NullString
	detail    sql.NullString
	createdAt int64
}

func audOnlyRow(t *testing.T, conn *sql.DB) audRow {
	t.Helper()
	var count int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 audit row, got %d", count)
	}
	var r audRow
	err := conn.QueryRow(
		`SELECT event, user_id, actor_id, ip, detail, created_at FROM audit_log`,
	).Scan(&r.event, &r.userID, &r.actorID, &r.ip, &r.detail, &r.createdAt)
	if err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	return r
}

type audHookCall struct {
	event   string
	userID  string
	actorID string
	ip      string
	detail  string
}

func TestLogPersistsEventFields(t *testing.T) {
	conn := audTestDB(t)
	before := time.Now().Unix()

	New(conn).Log(context.Background(), EventLoginSuccess, "user-1", "admin-9", "203.0.113.7", "password login")

	r := audOnlyRow(t, conn)
	if r.event.String != EventLoginSuccess {
		t.Errorf("event = %q, want %q", r.event.String, EventLoginSuccess)
	}
	if r.userID.String != "user-1" {
		t.Errorf("user_id = %q, want %q", r.userID.String, "user-1")
	}
	if r.actorID.String != "admin-9" {
		t.Errorf("actor_id = %q, want %q", r.actorID.String, "admin-9")
	}
	if r.ip.String != "203.0.113.7" {
		t.Errorf("ip = %q, want %q", r.ip.String, "203.0.113.7")
	}
	if r.detail.String != "password login" {
		t.Errorf("detail = %q, want %q", r.detail.String, "password login")
	}
	if r.createdAt < before || r.createdAt > time.Now().Unix()+1 {
		t.Errorf("created_at %d outside the window of the call", r.createdAt)
	}
}

func TestLogGivesEachEventAnIdentifier(t *testing.T) {
	conn := audTestDB(t)
	logger := New(conn)
	ctx := context.Background()

	logger.Log(ctx, EventLoginFailure, "user-1", "", "198.51.100.1", "bad password")
	logger.Log(ctx, EventLoginFailure, "user-1", "", "198.51.100.1", "bad password")

	var rows, ids int
	conn.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT id) FROM audit_log`).Scan(&rows, &ids)
	if rows != 2 {
		t.Fatalf("rows = %d, want 2", rows)
	}
	if ids != 2 {
		t.Errorf("distinct ids = %d, want 2", ids)
	}
}

func TestLogStoresBlankFieldsAsNull(t *testing.T) {
	conn := audTestDB(t)

	New(conn).Log(context.Background(), EventAdminLoginFailed, "", "", "", "")

	r := audOnlyRow(t, conn)
	if r.userID.Valid {
		t.Errorf("user_id = %q, want NULL", r.userID.String)
	}
	if r.actorID.Valid {
		t.Errorf("actor_id = %q, want NULL", r.actorID.String)
	}
	if r.ip.Valid {
		t.Errorf("ip = %q, want NULL", r.ip.String)
	}
	if r.detail.Valid {
		t.Errorf("detail = %q, want NULL", r.detail.String)
	}
	if !r.event.Valid || r.event.String != EventAdminLoginFailed {
		t.Errorf("event = %+v, want %q", r.event, EventAdminLoginFailed)
	}
}

func TestLogTreatsDetailAsDataNotSQL(t *testing.T) {
	conn := audTestDB(t)
	hostile := `x'); DROP TABLE audit_log; --`

	New(conn).Log(context.Background(), EventLoginFailure, "", "", "", hostile)

	r := audOnlyRow(t, conn)
	if r.detail.String != hostile {
		t.Errorf("detail = %q, want it stored verbatim as %q", r.detail.String, hostile)
	}
}

func TestLogInvokesEveryRegisteredHook(t *testing.T) {
	conn := audTestDB(t)
	logger := New(conn)

	first := make(chan audHookCall, 1)
	second := make(chan audHookCall, 1)
	logger.AddHook(func(event, userID, actorID, ip, detail string) {
		first <- audHookCall{event, userID, actorID, ip, detail}
	})
	logger.AddHook(func(event, userID, actorID, ip, detail string) {
		second <- audHookCall{event, userID, actorID, ip, detail}
	})

	logger.Log(context.Background(), EventPasskeyRevoked, "user-2", "admin-1", "192.0.2.5", "key removed")

	want := audHookCall{EventPasskeyRevoked, "user-2", "admin-1", "192.0.2.5", "key removed"}
	for name, ch := range map[string]chan audHookCall{"first": first, "second": second} {
		select {
		case got := <-ch:
			if got != want {
				t.Errorf("%s hook got %+v, want %+v", name, got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s hook was never called", name)
		}
	}
}

func TestHooksReceiveBlankFieldsUnchanged(t *testing.T) {
	conn := audTestDB(t)
	logger := New(conn)

	calls := make(chan audHookCall, 1)
	logger.AddHook(func(event, userID, actorID, ip, detail string) {
		calls <- audHookCall{event, userID, actorID, ip, detail}
	})

	logger.Log(context.Background(), EventOTPFailed, "", "", "", "")

	select {
	case got := <-calls:
		if got != (audHookCall{event: EventOTPFailed}) {
			t.Errorf("hook got %+v, want only the event set", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hook was never called")
	}
}

func TestLogWithoutHooksStillWritesRow(t *testing.T) {
	conn := audTestDB(t)

	New(conn).Log(context.Background(), EventUserCreated, "user-3", "", "", "")

	if r := audOnlyRow(t, conn); r.userID.String != "user-3" {
		t.Errorf("user_id = %q, want %q", r.userID.String, "user-3")
	}
}

func TestLogWithCancelledContextDoesNotPanic(t *testing.T) {
	conn := audTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	logger := New(conn)
	logger.Log(ctx, EventSessionRevoked, "user-4", "", "", "")
	logger.Log(context.Background(), EventSessionRevoked, "user-5", "", "", "")

	var count int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE user_id='user-5'`).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 1 {
		t.Errorf("rows for the event logged after the cancellation = %d, want 1", count)
	}
}
