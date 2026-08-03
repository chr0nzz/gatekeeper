package httpguard

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// M4/L5: operator-supplied URLs (client icons, webhooks) must not be able to
// reach the cloud metadata service or anything else on the internal network.
func TestBlockedAddresses(t *testing.T) {
	blocked := []string{
		"169.254.169.254", // cloud instance metadata
		"127.0.0.1",
		"::1",
		"10.1.2.3",
		"192.168.1.1",
		"172.16.0.1",
		"0.0.0.0",
		"100.64.0.1", // carrier-grade NAT
		"fd00::1",    // IPv6 unique local
		"fe80::1",    // IPv6 link-local
		"224.0.0.1",  // multicast
	}
	for _, ip := range blocked {
		if !IsBlockedIP(net.ParseIP(ip)) {
			t.Errorf("IsBlockedIP(%s) = false, want true", ip)
		}
	}
	if !IsBlockedIP(nil) {
		t.Error("IsBlockedIP(nil) = false, want true")
	}
}

func TestPublicAddressesAllowed(t *testing.T) {
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"} {
		if IsBlockedIP(net.ParseIP(ip)) {
			t.Errorf("IsBlockedIP(%s) = true, want false", ip)
		}
	}
}

func TestValidateURLRejectsNonHTTPSchemes(t *testing.T) {
	bad := []string{
		"file:///etc/passwd",
		"gopher://internal:70/",
		"ftp://internal/",
		"javascript:alert(1)",
		"https://",
		"::not a url::",
	}
	for _, raw := range bad {
		if err := ValidateURL(raw); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error", raw)
		}
	}
	for _, raw := range []string{"http://example.com", "https://example.com/path?q=1"} {
		if err := ValidateURL(raw); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", raw, err)
		}
	}
}

// A real connection attempt to a loopback server must be refused by the dialer,
// which is what stops DNS names that resolve to internal addresses.
func TestClientRefusesLoopbackConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	}))
	defer srv.Close()

	if _, err := Get(context.Background(), srv.URL, 5*time.Second); err == nil {
		t.Fatal("request to a loopback address succeeded, want blocked")
	} else if !strings.Contains(err.Error(), ErrBlockedAddress.Error()) {
		t.Logf("blocked with: %v", err)
	}
}
