package oidc

import (
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func clientWithRedirects(uris ...string) *OIDCClient {
	raw := "["
	for i, u := range uris {
		if i > 0 {
			raw += ","
		}
		raw += `"` + u + `"`
	}
	raw += "]"
	return &OIDCClient{redirectURIsRaw: raw}
}

// A mobile application receives its code on a custom scheme, which the library
// only accepts for native clients.
func TestClientWithCustomSchemeIsNative(t *testing.T) {
	cases := map[string][]string{
		"immich mobile":     {"app.immich:///oauth-callback"},
		"alongside https":   {"https://immich.example.com/auth/login", "app.immich:///oauth-callback"},
		"reverse dns style": {"com.example.app:/callback"},
	}
	for name, uris := range cases {
		t.Run(name, func(t *testing.T) {
			if got := clientWithRedirects(uris...).ApplicationType(); got != op.ApplicationTypeNative {
				t.Errorf("ApplicationType = %v, want native", got)
			}
		})
	}
}

// Ordinary web clients must not be reclassified, because native clients are held
// to different transport rules.
func TestWebOnlyClientStaysWeb(t *testing.T) {
	cases := map[string][]string{
		"https":            {"https://grafana.example.com/login/generic_oauth"},
		"http":             {"http://grafana.lan:3000/login/generic_oauth"},
		"mixed http https": {"https://a.example.com/cb", "http://b.lan:8080/cb"},
		"none":             {},
	}
	for name, uris := range cases {
		t.Run(name, func(t *testing.T) {
			if got := clientWithRedirects(uris...).ApplicationType(); got != op.ApplicationTypeWeb {
				t.Errorf("ApplicationType = %v, want web", got)
			}
		})
	}
}

// Under native rules a plain HTTP address that is not loopback is refused unless
// the transport rules are relaxed. Immich is commonly reached over plain HTTP on
// a local network while its mobile app uses a custom scheme, so both have to work
// for the same client.
func TestNativeClientOnPlainHTTPRelaxesTransportRules(t *testing.T) {
	c := clientWithRedirects("http://immich.lan:2283/auth/login", "app.immich:///oauth-callback")
	if c.ApplicationType() != op.ApplicationTypeNative {
		t.Fatal("client with a custom scheme should be native")
	}
	if !c.DevMode() {
		t.Error("a native client reached over plain HTTP must relax its transport rules or web sign-in breaks")
	}
}

// Relaxation is not handed out to clients that do not need it.
func TestTransportRulesStayStrictWithoutPlainHTTP(t *testing.T) {
	cases := map[string][]string{
		"https only":          {"https://app.example.com/cb"},
		"https plus custom":   {"https://immich.example.com/auth/login", "app.immich:///oauth-callback"},
		"loopback is exempt":  {"http://127.0.0.1:8080/cb", "app.example:///cb"},
		"localhost is exempt": {"http://localhost:2283/auth/login"},
	}
	for name, uris := range cases {
		t.Run(name, func(t *testing.T) {
			if clientWithRedirects(uris...).DevMode() {
				t.Error("transport rules were relaxed for a client that does not need it")
			}
		})
	}
}

func TestCustomSchemeDetection(t *testing.T) {
	custom := []string{"app.immich:///oauth-callback", "myapp://callback", "com.example:/path"}
	notCustom := []string{"https://example.com/cb", "http://example.com/cb", "", "/relative/path"}

	for _, uri := range custom {
		if !hasCustomScheme(uri) {
			t.Errorf("hasCustomScheme(%q) = false, want true", uri)
		}
	}
	for _, uri := range notCustom {
		if hasCustomScheme(uri) {
			t.Errorf("hasCustomScheme(%q) = true, want false", uri)
		}
	}
}
