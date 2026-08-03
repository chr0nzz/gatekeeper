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
	// A token created without resolvable scopes stores the JSON literal "null",
	// which is what production rows contain.
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

// A token whose granted scopes were never recorded must still return the
// standard claims. Relying parties identify users by email, so withholding it
// breaks sign-in for every connected app.
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

// L4: the claim used to be hard-coded true, which let an unverified address be
// trusted by a relying party that links accounts by email.
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

// M5: post-logout redirects must match a URI a client actually registered.
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
