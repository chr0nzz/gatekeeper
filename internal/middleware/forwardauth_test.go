package middleware

import "testing"

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
