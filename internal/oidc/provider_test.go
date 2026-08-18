package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/db"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func oidcTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func seedUserAndToken(t *testing.T, conn *sql.DB, verified int, scopes interface{}) string {
	t.Helper()
	now := time.Now()
	_, err := conn.Exec(
		`INSERT INTO users (id, email, password_hash, created_at, updated_at, email_verified) VALUES ('u1','alice@example.com','',?,?,?)`,
		now.Unix(), now.Unix(), verified,
	)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	scopeRaw := "null"
	if v, ok := scopes.([]string); ok {
		b, _ := json.Marshal(v)
		scopeRaw = string(b)
	}
	_, err = conn.Exec(
		`INSERT INTO oidc_tokens (id, auth_request_id, client_id, user_id, access_token, scopes, created_at, access_expires)
		 VALUES ('tok1','ar1','client1','u1','at-value',?,?,?)`,
		scopeRaw, now.Unix(), now.Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}
	return "tok1"
}

func TestUserinfoReturnsClaimsWhenScopesUnknown(t *testing.T) {
	conn := oidcTestDB(t)
	tokenID := seedUserAndToken(t, conn, 1, nil)
	s := NewStorage(conn, "https://auth.example.com")

	var info oidc.UserInfo
	if err := s.SetUserinfoFromToken(context.Background(), &info, tokenID, "u1", ""); err != nil {
		t.Fatalf("SetUserinfoFromToken: %v", err)
	}
	if info.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", info.Email)
	}
	if info.PreferredUsername != "alice@example.com" {
		t.Errorf("preferred_username = %q, want alice@example.com", info.PreferredUsername)
	}
	if info.Subject != "u1" {
		t.Errorf("sub = %q, want u1", info.Subject)
	}
}

func TestUserinfoHonoursRecordedScopes(t *testing.T) {
	conn := oidcTestDB(t)
	tokenID := seedUserAndToken(t, conn, 1, []string{"openid", "email", "profile"})
	s := NewStorage(conn, "https://auth.example.com")

	var info oidc.UserInfo
	if err := s.SetUserinfoFromToken(context.Background(), &info, tokenID, "u1", ""); err != nil {
		t.Fatalf("SetUserinfoFromToken: %v", err)
	}
	if info.Email != "alice@example.com" {
		t.Errorf("email withheld despite the email scope being granted")
	}
}

func TestUserinfoOmitsEmailWithoutEmailScope(t *testing.T) {
	conn := oidcTestDB(t)
	tokenID := seedUserAndToken(t, conn, 1, []string{"openid"})
	s := NewStorage(conn, "https://auth.example.com")

	var info oidc.UserInfo
	if err := s.SetUserinfoFromToken(context.Background(), &info, tokenID, "u1", ""); err != nil {
		t.Fatalf("SetUserinfoFromToken: %v", err)
	}
	if info.Email != "" {
		t.Errorf("email = %q, want empty when only openid was granted", info.Email)
	}
	if info.Subject != "u1" {
		t.Errorf("sub = %q, want u1", info.Subject)
	}
}

func TestEmailVerifiedReflectsStoredState(t *testing.T) {
	for _, verified := range []int{0, 1} {
		conn := oidcTestDB(t)
		tokenID := seedUserAndToken(t, conn, verified, nil)
		s := NewStorage(conn, "https://auth.example.com")

		var info oidc.UserInfo
		if err := s.SetUserinfoFromToken(context.Background(), &info, tokenID, "u1", ""); err != nil {
			t.Fatalf("SetUserinfoFromToken: %v", err)
		}
		if bool(info.EmailVerified) != (verified == 1) {
			t.Errorf("email_verified = %v for stored value %d", bool(info.EmailVerified), verified)
		}
	}
}

func TestIsRegisteredRedirect(t *testing.T) {
	ctx := context.Background()
	conn := oidcTestDB(t)
	uris, _ := json.Marshal([]string{"https://app.example.com/callback", "https://app.example.com/logged-out"})
	conn.Exec(
		`INSERT INTO oidc_clients (id, client_id, client_secret, redirect_uris, name, created_at) VALUES ('c1','client1','secret',?,'App',?)`,
		string(uris), time.Now().Unix(),
	)
	s := NewStorage(conn, "https://auth.example.com")

	for _, ok := range []string{"https://app.example.com/callback", "https://app.example.com/logged-out"} {
		if !s.IsRegisteredRedirect(ctx, ok) {
			t.Errorf("registered URI %q was rejected", ok)
		}
	}
	for _, bad := range []string{
		"https://evil.com/callback",
		"https://app.example.com/callback/../../evil",
		"https://app.example.com",
		"",
	} {
		if s.IsRegisteredRedirect(ctx, bad) {
			t.Errorf("unregistered URI %q was accepted", bad)
		}
	}
}

func TestHasScope(t *testing.T) {
	scopes := []string{"openid", "email"}
	if !hasScope(scopes, "email") {
		t.Error("hasScope missed a granted scope")
	}
	if hasScope(scopes, "profile") {
		t.Error("hasScope reported a scope that was not granted")
	}
	if hasScope(nil, "email") {
		t.Error("hasScope reported a scope on an empty list")
	}
}

func activeKeyID(t *testing.T, conn *sql.DB) string {
	t.Helper()
	var id string
	if err := conn.QueryRow(
		`SELECT id FROM oidc_signing_keys WHERE rotated_at IS NULL ORDER BY created_at DESC LIMIT 1`,
	).Scan(&id); err != nil {
		t.Fatalf("no active signing key: %v", err)
	}
	return id
}

func TestSigningKeyStatusReportsSchedule(t *testing.T) {
	ctx := context.Background()
	conn := oidcTestDB(t)
	s := NewStorage(conn, "https://auth.example.com")
	if err := s.EnsureSigningKey(ctx); err != nil {
		t.Fatalf("ensure key: %v", err)
	}

	status, err := s.SigningKeyStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Algorithm != "RS256" {
		t.Errorf("algorithm = %q, want RS256", status.Algorithm)
	}
	if got := status.RotatesAt.Sub(status.CreatedAt); got != signingKeyTTL {
		t.Errorf("rotation window = %v, want %v", got, signingKeyTTL)
	}
	if time.Until(status.RotatesAt) <= 0 {
		t.Error("a freshly created key is already due for rotation")
	}
}

func TestSigningKeyNotRotatedBeforeDue(t *testing.T) {
	ctx := context.Background()
	conn := oidcTestDB(t)
	s := NewStorage(conn, "https://auth.example.com")
	s.EnsureSigningKey(ctx)
	before := activeKeyID(t, conn)

	rotated, err := s.RotateSigningKeyIfDue(ctx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated {
		t.Error("rotated a key that is not yet due")
	}
	if activeKeyID(t, conn) != before {
		t.Error("active key changed unexpectedly")
	}
}

func TestSigningKeyRotatesWhenDue(t *testing.T) {
	ctx := context.Background()
	conn := oidcTestDB(t)
	s := NewStorage(conn, "https://auth.example.com")
	s.EnsureSigningKey(ctx)
	old := activeKeyID(t, conn)

	aged := time.Now().Add(-signingKeyTTL - time.Hour).Unix()
	conn.Exec(`UPDATE oidc_signing_keys SET created_at=? WHERE id=?`, aged, old)

	rotated, err := s.RotateSigningKeyIfDue(ctx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !rotated {
		t.Fatal("key past its maximum age was not rotated")
	}

	current := activeKeyID(t, conn)
	if current == old {
		t.Fatal("active key did not change")
	}

	var active int
	conn.QueryRow(`SELECT COUNT(*) FROM oidc_signing_keys WHERE rotated_at IS NULL`).Scan(&active)
	if active != 1 {
		t.Errorf("%d active keys, want exactly 1", active)
	}

	var retiredAt sql.NullInt64
	conn.QueryRow(`SELECT rotated_at FROM oidc_signing_keys WHERE id=?`, old).Scan(&retiredAt)
	if !retiredAt.Valid {
		t.Error("previous key was not marked as retired")
	}

	keys, err := s.KeySet(ctx)
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	published := map[string]bool{}
	for _, k := range keys {
		published[k.ID()] = true
	}
	if !published[old] {
		t.Error("retired key is no longer published, tokens it signed can no longer be verified")
	}
	if !published[current] {
		t.Error("active key is not published")
	}
}

func TestRetiredSigningKeysArePrunedAfterGrace(t *testing.T) {
	ctx := context.Background()
	conn := oidcTestDB(t)
	s := NewStorage(conn, "https://auth.example.com")
	s.EnsureSigningKey(ctx)
	old := activeKeyID(t, conn)

	conn.Exec(`UPDATE oidc_signing_keys SET created_at=? WHERE id=?`,
		time.Now().Add(-signingKeyTTL-time.Hour).Unix(), old)
	if _, err := s.RotateSigningKeyIfDue(ctx); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	s.RotateSigningKeyIfDue(ctx)
	var count int
	conn.QueryRow(`SELECT COUNT(*) FROM oidc_signing_keys WHERE id=?`, old).Scan(&count)
	if count != 1 {
		t.Fatal("retired key was pruned while tokens it signed could still be valid")
	}

	conn.Exec(`UPDATE oidc_signing_keys SET rotated_at=? WHERE id=?`,
		time.Now().Add(-retiredKeyRetention-time.Hour).Unix(), old)
	s.RotateSigningKeyIfDue(ctx)

	conn.QueryRow(`SELECT COUNT(*) FROM oidc_signing_keys WHERE id=?`, old).Scan(&count)
	if count != 0 {
		t.Error("retired key was kept past its retention window")
	}
}

func TestRepeatedRotationKeepsExactlyOneActiveKey(t *testing.T) {
	ctx := context.Background()
	conn := oidcTestDB(t)
	s := NewStorage(conn, "https://auth.example.com")
	s.EnsureSigningKey(ctx)

	for i := 0; i < 3; i++ {
		conn.Exec(`UPDATE oidc_signing_keys SET created_at=? WHERE rotated_at IS NULL`,
			time.Now().Add(-signingKeyTTL-time.Hour).Unix())
		if _, err := s.RotateSigningKeyIfDue(ctx); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		var active int
		conn.QueryRow(`SELECT COUNT(*) FROM oidc_signing_keys WHERE rotated_at IS NULL`).Scan(&active)
		if active != 1 {
			t.Fatalf("after rotation %d there are %d active keys, want 1", i, active)
		}
		if _, _, err := s.loadCurrentKey(ctx); err != nil {
			t.Fatalf("after rotation %d the current key could not be loaded: %v", i, err)
		}
	}
}
