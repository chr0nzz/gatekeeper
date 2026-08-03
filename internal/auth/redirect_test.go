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
