package ui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/chr0nzz/gatekeeper/internal/auth"
)

const uiRedirAllowedHost = "app.partner.net"

func uiRedirEnableCrossDomain(t *testing.T, u *uiHarness, cookieDomain, allowedHosts string) {
	t.Helper()
	u.set(t, "redirect_allowed_hosts", allowedHosts)
	u.h.cookieDomain = cookieDomain
	u.h.redirects.SetExtraHosts(func() []string {
		return auth.ParseHostList(u.settings.Get(context.Background(), "redirect_allowed_hosts", ""))
	})
}

func uiRedirHandoff(t *testing.T, loc string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", loc, err)
	}
	if parsed.Path != "/_gk/auth" {
		t.Fatalf("redirect path = %q, want /_gk/auth (loc %q)", parsed.Path, loc)
	}
	if parsed.Query().Get("token") == "" {
		t.Fatalf("handoff URL carries no token: %q", loc)
	}
	return parsed
}

func uiRedirSignedInLogin(t *testing.T, u *uiHarness, target string) (*http.Cookie, string) {
	t.Helper()
	userID := u.addUser(t, "redir@example.com", "correct-horse-battery")
	cookie := u.signIn(t, userID)
	rec := u.get("/login?redirect_uri="+url.QueryEscape(target), cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /login status = %d, want %d", rec.Code, http.StatusFound)
	}
	return cookie, location(rec)
}

func TestLoginSendsSignedInUserToRelativeTarget(t *testing.T) {
	for _, target := range []string{"/profile", "/dashboard?tab=apps"} {
		_, loc := uiRedirSignedInLogin(t, newUIHarness(t), target)
		if loc != target {
			t.Errorf("Location = %q, want %q", loc, target)
		}
	}
}

func TestLoginRefusesUntrustedAbsoluteRedirect(t *testing.T) {
	hostile := []string{
		"https://evil.example.net/",
		"http://evil.example.net/steal?a=b",
		"//evil.example.net/",
		"/\\evil.example.net",
		"https://auth.example.com.evil.example.net/",
	}
	for _, target := range hostile {
		u := newUIHarness(t)
		_, loc := uiRedirSignedInLogin(t, u, target)
		if loc != "/" {
			t.Errorf("Location for %q = %q, want \"/\"", target, loc)
		}
		if strings.Contains(loc, "evil.example.net") {
			t.Errorf("Location for %q leaked the attacker host: %q", target, loc)
		}
	}
}

func TestLoginHonoursHostAllowedBySettings(t *testing.T) {
	u := newUIHarness(t)
	uiRedirEnableCrossDomain(t, u, "example.com", uiRedirAllowedHost)

	_, loc := uiRedirSignedInLogin(t, u, "https://"+uiRedirAllowedHost+"/dash?tab=1")
	handoff := uiRedirHandoff(t, loc)

	if handoff.Scheme != "https" || handoff.Host != uiRedirAllowedHost {
		t.Fatalf("handoff URL = %q, want https://%s/_gk/auth", loc, uiRedirAllowedHost)
	}
	if got := handoff.Query().Get("redirect"); got != "/dash?tab=1" {
		t.Errorf("redirect param = %q, want /dash?tab=1", got)
	}
}

func TestHandoffURLNeverCarriesSessionCookie(t *testing.T) {
	u := newUIHarness(t)
	uiRedirEnableCrossDomain(t, u, "example.com", uiRedirAllowedHost)

	cookie, loc := uiRedirSignedInLogin(t, u, "https://"+uiRedirAllowedHost+"/dash")
	handoff := uiRedirHandoff(t, loc)

	if cookie.Value == "" {
		t.Fatal("session cookie has no value")
	}
	for _, form := range []string{cookie.Value, url.QueryEscape(cookie.Value), cookie.Name} {
		if strings.Contains(loc, form) {
			t.Fatalf("handoff URL %q exposes session material %q", loc, form)
		}
	}
	if handoff.Query().Get("token") == cookie.Value {
		t.Fatal("handoff token is the session identifier")
	}
}

func TestHandoffTokenIsSingleUse(t *testing.T) {
	u := newUIHarness(t)
	uiRedirEnableCrossDomain(t, u, "example.com", uiRedirAllowedHost)

	_, loc := uiRedirSignedInLogin(t, u, "https://"+uiRedirAllowedHost+"/dash")
	token := uiRedirHandoff(t, loc).Query().Get("token")

	ctx := context.Background()
	userID, err := u.handoff.Redeem(ctx, token, uiRedirAllowedHost)
	if err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if userID == "" {
		t.Fatal("first redeem returned an empty user id")
	}
	if _, err := u.handoff.Redeem(ctx, token, uiRedirAllowedHost); !errors.Is(err, auth.ErrHandoffInvalid) {
		t.Fatalf("second redeem err = %v, want %v", err, auth.ErrHandoffInvalid)
	}
}

func TestHandoffTokenRejectedFromForeignHost(t *testing.T) {
	u := newUIHarness(t)
	uiRedirEnableCrossDomain(t, u, "example.com", uiRedirAllowedHost)

	_, loc := uiRedirSignedInLogin(t, u, "https://"+uiRedirAllowedHost+"/dash")
	token := uiRedirHandoff(t, loc).Query().Get("token")

	ctx := context.Background()
	if _, err := u.handoff.Redeem(ctx, token, "evil.example.net"); !errors.Is(err, auth.ErrHandoffInvalid) {
		t.Fatalf("foreign host redeem err = %v, want %v", err, auth.ErrHandoffInvalid)
	}
	if _, err := u.handoff.Redeem(ctx, token, uiRedirAllowedHost); err != nil {
		t.Fatalf("a rejected foreign redemption must not burn the token: %v", err)
	}
}

func TestHandoffTokenStoredHashed(t *testing.T) {
	u := newUIHarness(t)
	uiRedirEnableCrossDomain(t, u, "example.com", uiRedirAllowedHost)

	_, loc := uiRedirSignedInLogin(t, u, "https://"+uiRedirAllowedHost+"/dash")
	token := uiRedirHandoff(t, loc).Query().Get("token")

	var clear int
	if err := u.db.QueryRow(`SELECT COUNT(*) FROM handoff_tokens WHERE id=?`, token).Scan(&clear); err != nil {
		t.Fatalf("count clear tokens: %v", err)
	}
	if clear != 0 {
		t.Fatal("handoff token is stored in clear")
	}

	sum := sha256.Sum256([]byte(token))
	var hashed int
	if err := u.db.QueryRow(`SELECT COUNT(*) FROM handoff_tokens WHERE id=?`, hex.EncodeToString(sum[:])).Scan(&hashed); err != nil {
		t.Fatalf("count hashed tokens: %v", err)
	}
	if hashed != 1 {
		t.Fatalf("hashed token rows = %d, want 1", hashed)
	}
}
