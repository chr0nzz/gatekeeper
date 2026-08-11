package social

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func socParse(t *testing.T, raw string) (*url.URL, url.Values) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u, u.Query()
}

func TestAuthURLPointsAtTheProviderAndCarriesTheRequestedGrant(t *testing.T) {
	const (
		clientID    = "client-id-123"
		redirectURI = "https://auth.example.test/auth/social/x/callback"
		state       = "state-token-abc"
	)
	cases := []struct {
		provider     string
		host         string
		path         string
		scope        string
		responseType string
	}{
		{"github", "github.com", "/login/oauth/authorize", "user:email", ""},
		{"google", "accounts.google.com", "/o/oauth2/v2/auth", "openid email profile", "code"},
		{"discord", "discord.com", "/api/oauth2/authorize", "identify email", "code"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			raw, err := AuthURL(tc.provider, clientID, redirectURI, state)
			if err != nil {
				t.Fatalf("AuthURL: %v", err)
			}
			u, q := socParse(t, raw)
			if u.Scheme != "https" {
				t.Errorf("scheme = %q, want https", u.Scheme)
			}
			if u.Host != tc.host {
				t.Errorf("host = %q, want %q", u.Host, tc.host)
			}
			if u.Path != tc.path {
				t.Errorf("path = %q, want %q", u.Path, tc.path)
			}
			if got := q.Get("client_id"); got != clientID {
				t.Errorf("client_id = %q, want %q", got, clientID)
			}
			if got := q.Get("redirect_uri"); got != redirectURI {
				t.Errorf("redirect_uri = %q, want %q", got, redirectURI)
			}
			if got := q.Get("state"); got != state {
				t.Errorf("state = %q, want %q", got, state)
			}
			if got := q.Get("scope"); got != tc.scope {
				t.Errorf("scope = %q, want %q", got, tc.scope)
			}
			if got := q.Get("response_type"); got != tc.responseType {
				t.Errorf("response_type = %q, want %q", got, tc.responseType)
			}
			if len(q["scope"]) != 1 {
				t.Errorf("scope appears %d times, want exactly one", len(q["scope"]))
			}
		})
	}
}

// A missing state parameter would leave the callback open to CSRF, so an empty
// state must not silently collapse into an absent one.
func TestAuthURLAlwaysEmitsAStateParameter(t *testing.T) {
	for _, provider := range []string{"github", "google", "discord"} {
		raw, err := AuthURL(provider, "cid", "https://auth.example.test/cb", "")
		if err != nil {
			t.Fatalf("%s: AuthURL: %v", provider, err)
		}
		_, q := socParse(t, raw)
		if _, ok := q["state"]; !ok {
			t.Errorf("%s: state parameter missing from %q", provider, raw)
		}
	}
}

// Values that reach AuthURL come from configuration and from the request, so a
// value containing query syntax must stay a single opaque value.
func TestAuthURLEscapesValuesInsteadOfLettingThemInjectParameters(t *testing.T) {
	const (
		clientID    = "cid&scope=admin"
		redirectURI = "https://evil.example.test/cb?next=/#frag"
		state       = "st&client_id=attacker&redirect_uri=https://evil.example.test"
	)
	raw, err := AuthURL("google", clientID, redirectURI, state)
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	u, q := socParse(t, raw)
	if u.Host != "accounts.google.com" {
		t.Fatalf("host = %q, want accounts.google.com", u.Host)
	}
	if u.Fragment != "" {
		t.Errorf("fragment = %q, want none", u.Fragment)
	}
	if got := q.Get("scope"); got != "openid email profile" {
		t.Errorf("scope = %q, want the fixed google scope", got)
	}
	if len(q["client_id"]) != 1 || q.Get("client_id") != clientID {
		t.Errorf("client_id = %v, want exactly [%q]", q["client_id"], clientID)
	}
	if len(q["redirect_uri"]) != 1 || q.Get("redirect_uri") != redirectURI {
		t.Errorf("redirect_uri = %v, want exactly [%q]", q["redirect_uri"], redirectURI)
	}
	if len(q["state"]) != 1 || q.Get("state") != state {
		t.Errorf("state = %v, want exactly [%q]", q["state"], state)
	}
	if len(q) != 5 {
		t.Errorf("query has %d parameters (%v), want 5", len(q), q)
	}
}

func TestAuthURLRejectsUnknownProvider(t *testing.T) {
	for _, provider := range []string{"", "gitlab", "GitHub", "google ", "github\n", "../github"} {
		raw, err := AuthURL(provider, "cid", "https://auth.example.test/cb", "st")
		if err == nil {
			t.Errorf("provider %q: got URL %q, want error", provider, raw)
		}
		if raw != "" {
			t.Errorf("provider %q: got non-empty URL %q alongside error", provider, raw)
		}
	}
}

func TestExchangeTokenRejectsUnknownProviderWithoutCallingOut(t *testing.T) {
	for _, provider := range []string{"", "gitlab", "GitHub"} {
		token, err := ExchangeToken(context.Background(), provider, "cid", "secret", "code", "https://auth.example.test/cb")
		if err == nil {
			t.Errorf("provider %q: got token %q, want error", provider, token)
		}
		if token != "" {
			t.Errorf("provider %q: got non-empty token %q alongside error", provider, token)
		}
	}
}

// The client secret must never travel back to the caller in an error string
// that could be logged or rendered.
func TestExchangeTokenErrorsDoNotLeakTheClientSecret(t *testing.T) {
	const secret = "super-secret-value"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, provider := range []string{"unknown-provider", "github", "google", "discord"} {
		token, err := ExchangeToken(ctx, provider, "cid", secret, "code", "https://auth.example.test/cb")
		if err == nil {
			t.Fatalf("provider %q: got token %q, want error", provider, token)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("provider %q: error leaks the client secret: %v", provider, err)
		}
		if token != "" {
			t.Errorf("provider %q: got non-empty token %q alongside error", provider, token)
		}
	}
}

func TestFetchProfileRejectsUnknownProvider(t *testing.T) {
	for _, provider := range []string{"", "gitlab", "Google", "github "} {
		profile, err := FetchProfile(context.Background(), provider, "token")
		if err == nil {
			t.Errorf("provider %q: got profile %+v, want error", provider, profile)
		}
		if profile != nil {
			t.Errorf("provider %q: got profile %+v alongside error", provider, profile)
		}
	}
}

// A transport failure must not be mistaken for a successful lookup that yields
// an anonymous profile, since the caller trusts ProviderID to identify a user.
func TestFetchProfileReturnsNoProfileWhenTheCallFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, provider := range []string{"github", "google", "discord"} {
		profile, err := FetchProfile(ctx, provider, "token")
		if err == nil {
			t.Errorf("provider %q: got profile %+v, want error", provider, profile)
		}
		if profile != nil {
			t.Errorf("provider %q: got profile %+v alongside error", provider, profile)
		}
	}
}
