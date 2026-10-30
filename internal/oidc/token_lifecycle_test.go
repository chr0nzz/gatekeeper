package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestUserinfoRejectsTokensThatAreNoLongerValid(t *testing.T) {
	cases := []struct {
		name    string
		mutate  string
		subject string
	}{
		{"expired", `UPDATE oidc_tokens SET access_expires=1 WHERE id='tok1'`, "u1"},
		{"revoked", `DELETE FROM oidc_tokens WHERE id='tok1'`, "u1"},
		{"disabled user", `UPDATE users SET disabled=1 WHERE id='u1'`, "u1"},
		{"deleted user", `DELETE FROM users WHERE id='u1'`, "u1"},
		{"other subject", ``, "u2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := oidcTestDB(t)
			tokenID := seedUserAndToken(t, conn, 1, []string{"openid", "email"})
			if tc.mutate != "" {
				if _, err := conn.Exec(tc.mutate); err != nil {
					t.Fatalf("mutate: %v", err)
				}
			}
			s := NewStorage(conn, "https://auth.example.com")

			var info oidc.UserInfo
			if err := s.SetUserinfoFromToken(context.Background(), &info, tokenID, tc.subject, ""); err == nil {
				t.Fatalf("SetUserinfoFromToken succeeded, want error (email=%q)", info.Email)
			}
		})
	}
}

func TestUserinfoAcceptsRawAccessTokenValue(t *testing.T) {
	conn := oidcTestDB(t)
	seedUserAndToken(t, conn, 1, nil)
	s := NewStorage(conn, "https://auth.example.com")

	var info oidc.UserInfo
	if err := s.SetUserinfoFromToken(context.Background(), &info, "at-value", "u1", ""); err != nil {
		t.Fatalf("SetUserinfoFromToken: %v", err)
	}
	if info.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", info.Email)
	}
}

func TestGetUserinfoRefusesDisabledUser(t *testing.T) {
	conn := oidcTestDB(t)
	seedUserAndToken(t, conn, 1, nil)
	s := NewStorage(conn, "https://auth.example.com")

	if _, err := s.GetUserinfo(context.Background(), "u1", "client1", []string{"email"}); err != nil {
		t.Fatalf("GetUserinfo for active user: %v", err)
	}
	conn.Exec(`UPDATE users SET disabled=1 WHERE id='u1'`)
	if _, err := s.GetUserinfo(context.Background(), "u1", "client1", []string{"email"}); err == nil {
		t.Error("GetUserinfo succeeded for a disabled user")
	}
}

func seedRefreshToken(t *testing.T, s *Storage, refresh string) {
	t.Helper()
	if _, err := s.db.Exec(
		`UPDATE oidc_tokens SET refresh_token=?, refresh_expires=? WHERE id='tok1'`,
		refresh, time.Now().Add(time.Hour).Unix(),
	); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
}

func TestRefreshRefusedForDisabledOrDeletedUser(t *testing.T) {
	for _, mutate := range []string{
		`UPDATE users SET disabled=1 WHERE id='u1'`,
		`DELETE FROM users WHERE id='u1'`,
	} {
		conn := oidcTestDB(t)
		seedUserAndToken(t, conn, 1, []string{"openid"})
		s := NewStorage(conn, "https://auth.example.com")
		seedRefreshToken(t, s, "rt-value")

		if _, err := s.TokenRequestByRefreshToken(context.Background(), "rt-value"); err != nil {
			t.Fatalf("refresh for active user: %v", err)
		}
		conn.Exec(mutate)
		if _, err := s.TokenRequestByRefreshToken(context.Background(), "rt-value"); err == nil {
			t.Errorf("refresh succeeded after %q", mutate)
		}
	}
}

func TestRefreshTokenCanOnlyBeRedeemedOnce(t *testing.T) {
	ctx := context.Background()
	conn := oidcTestDB(t)
	seedUserAndToken(t, conn, 1, []string{"openid"})
	s := NewStorage(conn, "https://auth.example.com")
	seedRefreshToken(t, s, "rt-old")

	req, err := s.TokenRequestByRefreshToken(ctx, "rt-old")
	if err != nil {
		t.Fatalf("TokenRequestByRefreshToken: %v", err)
	}
	access, refresh, _, err := s.CreateAccessAndRefreshTokens(ctx, req, "rt-old")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if refresh == "" || refresh == "rt-old" {
		t.Fatalf("new refresh token = %q", refresh)
	}

	if _, err := s.TokenRequestByRefreshToken(ctx, "rt-old"); err == nil {
		t.Error("old refresh token still valid after rotation")
	}
	if _, _, _, err := s.CreateAccessAndRefreshTokens(ctx, req, "rt-old"); err == nil {
		t.Error("second rotation with the old refresh token succeeded")
	}
	var info oidc.UserInfo
	if err := s.SetUserinfoFromToken(ctx, &info, "at-value", "u1", ""); err == nil {
		t.Error("access token issued with the old refresh token still works")
	}

	if _, err := s.TokenRequestByRefreshToken(ctx, refresh); err != nil {
		t.Errorf("new refresh token rejected: %v", err)
	}
	if err := s.SetUserinfoFromToken(ctx, &info, access, "u1", ""); err != nil {
		t.Errorf("new access token rejected: %v", err)
	}
	var rows int
	conn.QueryRow(`SELECT COUNT(*) FROM oidc_tokens WHERE user_id='u1'`).Scan(&rows)
	if rows != 1 {
		t.Errorf("token rows after rotation = %d, want 1", rows)
	}
}

func TestIntrospectionReportsActiveToken(t *testing.T) {
	conn := oidcTestDB(t)
	tokenID := seedUserAndToken(t, conn, 1, []string{"openid", "email"})
	s := NewStorage(conn, "https://auth.example.com")

	var resp oidc.IntrospectionResponse
	if err := s.SetIntrospectionFromToken(context.Background(), &resp, tokenID, "u1", "rs1"); err != nil {
		t.Fatalf("SetIntrospectionFromToken: %v", err)
	}
	if !resp.Active {
		t.Fatal("active = false for a valid token")
	}
	if resp.Subject != "u1" || resp.ClientID != "client1" || resp.Email != "alice@example.com" {
		t.Errorf("sub/client_id/email = %q/%q/%q", resp.Subject, resp.ClientID, resp.Email)
	}
	if len(resp.Scope) != 2 || resp.Scope[1] != "email" {
		t.Errorf("scope = %v, want [openid email]", resp.Scope)
	}
	if resp.Expiration.AsTime().Before(time.Now()) {
		t.Errorf("exp = %v, want in the future", resp.Expiration.AsTime())
	}
	if resp.Issuer != "https://auth.example.com" || len(resp.Audience) != 1 || resp.Audience[0] != "client1" {
		t.Errorf("iss/aud = %q/%v", resp.Issuer, resp.Audience)
	}
}

func TestIntrospectionReportsInactiveToken(t *testing.T) {
	for _, mutate := range []string{
		`UPDATE oidc_tokens SET access_expires=1 WHERE id='tok1'`,
		`DELETE FROM oidc_tokens WHERE id='tok1'`,
		`UPDATE users SET disabled=1 WHERE id='u1'`,
	} {
		conn := oidcTestDB(t)
		tokenID := seedUserAndToken(t, conn, 1, nil)
		conn.Exec(mutate)
		s := NewStorage(conn, "https://auth.example.com")

		var resp oidc.IntrospectionResponse
		if err := s.SetIntrospectionFromToken(context.Background(), &resp, tokenID, "u1", "rs1"); err == nil {
			t.Errorf("after %q: no error, the library would report the token as active", mutate)
		}
		if resp.Active || resp.Subject != "" || resp.Email != "" {
			t.Errorf("after %q: active=%v sub=%q email=%q, want an empty inactive response", mutate, resp.Active, resp.Subject, resp.Email)
		}
	}
}
