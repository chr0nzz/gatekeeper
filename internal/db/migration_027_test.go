package db

import (
	"path/filepath"
	"testing"
)

func TestMigration027KeepsTokensAndAllowsMachineTokens(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`INSERT INTO oidc_tokens (id, auth_request_id, client_id, user_id, access_token, refresh_token, scopes, created_at, access_expires, refresh_expires)
		VALUES ('t1','ar','c1','u1','at','rt','[]',1,2,3)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sqlText, err := migrations.ReadFile("migrations/027_oidc_tokens_nullable_user.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := conn.Exec(string(sqlText)); err != nil {
		t.Fatalf("run on populated table: %v", err)
	}
	var user, refresh string
	var refreshExpires int
	if err := conn.QueryRow(`SELECT user_id, refresh_token, refresh_expires FROM oidc_tokens WHERE id='t1'`).Scan(&user, &refresh, &refreshExpires); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if user != "u1" || refresh != "rt" || refreshExpires != 3 {
		t.Errorf("row = %q/%q/%d", user, refresh, refreshExpires)
	}
	if _, err := conn.Exec(`INSERT INTO oidc_tokens (id, auth_request_id, client_id, user_id, access_token, scopes, created_at, access_expires)
		VALUES ('t2','ar2','c1',NULL,'at2','[]',1,2)`); err != nil {
		t.Errorf("machine token rejected: %v", err)
	}
	var indexes int
	conn.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('oidc_tokens_refresh','oidc_tokens_access')`).Scan(&indexes)
	if indexes != 2 {
		t.Errorf("indexes = %d, want 2", indexes)
	}
}
