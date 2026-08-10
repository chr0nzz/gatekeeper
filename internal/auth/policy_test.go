package auth

import "testing"

func settingsFrom(m map[string]string) func(string, string) string {
	return func(key, fallback string) string {
		if v, ok := m[key]; ok {
			return v
		}
		return fallback
	}
}

// The configured minimum must be what gets enforced. A stale default would let
// passwords through that the operator intended to reject.
func TestLoadPasswordPolicyUsesConfiguredMinimum(t *testing.T) {
	p := LoadPasswordPolicy(settingsFrom(map[string]string{"password_min_length": "20"}))
	if p.MinLength != 20 {
		t.Fatalf("MinLength = %d, want 20", p.MinLength)
	}
	if err := p.Check("Short1!aaaaa"); err == nil {
		t.Error("a 12 character password was accepted under a 20 character policy")
	}
	if err := p.Check("aaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Errorf("a 20 character password was rejected: %v", err)
	}
}

func TestLoadPasswordPolicyDefaults(t *testing.T) {
	p := LoadPasswordPolicy(settingsFrom(nil))
	if p.MinLength != DefaultPasswordMinLength {
		t.Errorf("MinLength = %d, want %d", p.MinLength, DefaultPasswordMinLength)
	}
	if p.RequireUpper || p.RequireNumber || p.RequireSymbol {
		t.Error("character requirements should be off by default")
	}
}

// A value below the configurable floor, or an unparseable one, must fall back to
// the default rather than silently weakening the policy.
func TestLoadPasswordPolicyIgnoresInvalidMinimum(t *testing.T) {
	for _, v := range []string{"", "0", "3", "abc", "-5"} {
		p := LoadPasswordPolicy(settingsFrom(map[string]string{"password_min_length": v}))
		if p.MinLength != DefaultPasswordMinLength {
			t.Errorf("min_length %q gave MinLength %d, want %d", v, p.MinLength, DefaultPasswordMinLength)
		}
	}
}

func TestLoadPasswordPolicyCharacterRequirements(t *testing.T) {
	p := LoadPasswordPolicy(settingsFrom(map[string]string{
		"password_min_length":        "10",
		"password_require_uppercase": "1",
		"password_require_number":    "1",
		"password_require_symbol":    "1",
	}))
	if err := p.Check("alllowercase"); err == nil {
		t.Error("password missing uppercase, number and symbol was accepted")
	}
	if err := p.Check("Passw0rd!xx"); err != nil {
		t.Errorf("compliant password rejected: %v", err)
	}
}
