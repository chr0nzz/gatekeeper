package auth

import "testing"

func policy() *RedirectPolicy {
	return NewRedirectPolicy(
		"https://auth.example.com",
		"https://admin.auth.example.com",
		".example.com",
		[]string{"app.other.com", ".trusted.net"},
	)
}

// CRITICAL-1: an unvalidated redirect_uri let an attacker receive a session-bearing
// handoff token. Every off-allowlist destination must be refused.
func TestRedirectPolicyRejectsUntrustedHosts(t *testing.T) {
	p := policy()
	blocked := []string{
		"https://evil.com/",
		"https://evil.com/path?a=b",
		"http://evil.com",
		"https://auth.example.com.evil.com/",
		"https://notexample.com/",
		"//evil.com",
		"//evil.com/path",
		"/\\evil.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"https://evil.com\\@auth.example.com/",
		"",
	}
	for _, target := range blocked {
		if p.Allowed(target) {
			t.Errorf("Allowed(%q) = true, want false", target)
		}
		if got := p.Sanitize(target); got != "/" {
			t.Errorf("Sanitize(%q) = %q, want \"/\"", target, got)
		}
	}
}

func TestRedirectPolicyAllowsKnownDestinations(t *testing.T) {
	p := policy()
	allowed := []string{
		"/",
		"/profile",
		"/login?redirect_uri=%2Fdash",
		"https://auth.example.com/anything",
		"https://admin.auth.example.com/users",
		"https://app.example.com/",
		"https://deep.sub.example.com/x",
		"https://app.other.com/media",
		"https://anything.trusted.net/",
		"https://trusted.net/",
	}
	for _, target := range allowed {
		if !p.Allowed(target) {
			t.Errorf("Allowed(%q) = false, want true", target)
		}
		if got := p.Sanitize(target); got != target {
			t.Errorf("Sanitize(%q) = %q, want unchanged", target, got)
		}
	}
}

// With no cookie domain and no allowlist, only relative paths may be used.
func TestRedirectPolicyDefaultsClosed(t *testing.T) {
	p := NewRedirectPolicy("https://auth.example.com", "", "", nil)
	if p.Allowed("https://app.example.com/") {
		t.Error("sibling host allowed without cookie domain or allowlist")
	}
	if !p.Allowed("/dashboard") {
		t.Error("relative path should always be allowed")
	}
	if !p.Allowed("https://auth.example.com/x") {
		t.Error("own base URL host should be allowed")
	}
}

// Hosts added in the admin UI must take effect without a restart, so the policy
// consults the loader on every check.
func TestExtraHostsFromSettings(t *testing.T) {
	p := NewRedirectPolicy("https://auth.example.com", "", "", nil)
	configured := []string{}
	p.SetExtraHosts(func() []string { return configured })

	if p.Allowed("https://jellyfin.example.net/") {
		t.Fatal("host allowed before it was configured")
	}

	configured = []string{".example.net"}
	if !p.Allowed("https://jellyfin.example.net/") {
		t.Error("host not allowed after being added to the settings list")
	}

	// The same domain written without a leading dot must behave the same way.
	configured = []string{"example.net"}
	if !p.Allowed("https://jellyfin.example.net/") {
		t.Error("a domain written without a leading dot did not cover its subdomains")
	}
	if !p.Allowed("https://example.net/") {
		t.Error("suffix entry should cover the bare domain")
	}
	if p.Allowed("https://evil.com/") {
		t.Error("unrelated host allowed")
	}

	configured = []string{}
	if p.Allowed("https://jellyfin.example.net/") {
		t.Error("host still allowed after being removed from settings")
	}
}

// Every accepted entry form must behave identically. Writing a domain without a
// leading dot used to match only that exact host, which silently failed to allow
// the app subdomains it was meant to cover.
func TestExtraHostEntryForms(t *testing.T) {
	p := NewRedirectPolicy("https://auth.example.com", "", "", nil)
	p.SetExtraHosts(func() []string {
		return []string{"bare.example.net", ".dotted.example.net", "*.wild.example.net", "https://url.example.net/path"}
	})

	allowed := []string{
		"https://bare.example.net/x",
		"https://sub.bare.example.net/x",
		"https://dotted.example.net/x",
		"https://deep.dotted.example.net/x",
		"https://any.wild.example.net/x",
		"https://url.example.net/other",
		"https://sub.url.example.net/other",
	}
	for _, target := range allowed {
		if !p.Allowed(target) {
			t.Errorf("Allowed(%q) = false, want true", target)
		}
	}

	for _, target := range []string{"https://notbare.example.net/", "https://evil.com/", "https://bare.example.net.evil.com/", "https://example.net/"} {
		if p.Allowed(target) {
			t.Errorf("Allowed(%q) = true, want false", target)
		}
	}
}

func TestParseHostList(t *testing.T) {
	got := ParseHostList("app.example.net, .example.org\n  *.example.com \n\n")
	want := []string{"app.example.net", ".example.org", "*.example.com"}
	if len(got) != len(want) {
		t.Fatalf("ParseHostList returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
	if len(ParseHostList("")) != 0 {
		t.Error("empty input should produce no entries")
	}
}
