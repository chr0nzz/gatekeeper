package admin

import "testing"

func TestLoginMethodLabelsFollowTheDetailColumn(t *testing.T) {
	cases := []struct {
		event, detail, label, class string
	}{
		{"login.success", "", "Password", "method-password"},
		{"login.success", "password", "Password", "method-password"},
		{"login.success", "sso", "SSO", "method-sso"},
		{"login.success", "passwordless", "Email OTP", "method-emailotp"},
		{"login.success", "trusted-device", "Trusted device", "method-trusted"},
		{"login.passkey", "", "Passkey", "method-passkey"},
		{"login.social", "", "Social", "method-social"},
		{"login.qr", "", "QR code", "method-qr"},
		{"admin.login", "password", "Password", "method-password"},
		{"user.created", "", "", ""},
	}
	for _, c := range cases {
		label, class := loginMethod(c.event, c.detail)
		if label != c.label || class != c.class {
			t.Errorf("loginMethod(%q, %q) = %q/%q, want %q/%q", c.event, c.detail, label, class, c.label, c.class)
		}
	}
}
