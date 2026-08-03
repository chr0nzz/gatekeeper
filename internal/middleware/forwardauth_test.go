package middleware

import "testing"

// The redirect carried through the handoff must stay on the protected app, so a
// crafted /_gk/auth link cannot bounce the user to an attacker's site.
func TestIsLocalPath(t *testing.T) {
	local := []string{"/", "/dashboard", "/a/b?c=d", "/path#frag"}
	for _, p := range local {
		if !isLocalPath(p) {
			t.Errorf("isLocalPath(%q) = false, want true", p)
		}
	}

	external := []string{
		"//evil.com",
		"//evil.com/path",
		"/\\evil.com",
		"https://evil.com",
		"http://evil.com/x",
		"javascript:alert(1)",
		"evil.com",
		"",
	}
	for _, p := range external {
		if isLocalPath(p) {
			t.Errorf("isLocalPath(%q) = true, want false", p)
		}
	}
}

// M3: the ForwardAuth debug log must never include the handoff token, which
// travels in the query string.
func TestPathOnlyStripsQuery(t *testing.T) {
	cases := map[string]string{
		"/_gk/auth?token=SECRETVALUE&redirect=%2F": "/_gk/auth",
		"/dashboard?a=b": "/dashboard",
		"/plain":         "/plain",
		"":               "",
	}
	for in, want := range cases {
		if got := pathOnly(in); got != want {
			t.Errorf("pathOnly(%q) = %q, want %q", in, got, want)
		}
	}
	if got := pathOnly("/_gk/auth?token=SECRETVALUE"); got == "/_gk/auth?token=SECRETVALUE" {
		t.Error("token was not stripped from the logged path")
	}
}
