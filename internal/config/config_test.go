package config

import (
	"os"
	"strings"
	"testing"
)

const validSecret = "0123456789abcdef0123456789abcdef"

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("BASE_URL", "https://auth.example.com")
	t.Setenv("SECRET_KEY", validSecret)
}

func TestLoadDefaults(t *testing.T) {
	setRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Port != 8282 {
		t.Errorf("Port = %d, want 8282", cfg.Port)
	}
	if cfg.AdminPort != 8283 {
		t.Errorf("AdminPort = %d, want 8283", cfg.AdminPort)
	}
	if cfg.DBPath != "/data/gatekeeper.db" {
		t.Errorf("DBPath = %q", cfg.DBPath)
	}
	if cfg.SMTPTLS != "starttls" {
		t.Errorf("SMTPTLS = %q, want starttls", cfg.SMTPTLS)
	}
	if cfg.RegistrationMode != "disabled" {
		t.Errorf("RegistrationMode = %q, want disabled", cfg.RegistrationMode)
	}
}

func TestLoadRejectsShortSecretKey(t *testing.T) {
	t.Setenv("BASE_URL", "https://auth.example.com")
	t.Setenv("SECRET_KEY", "too-short")
	_, err := Load()
	if err == nil {
		t.Fatal("short SECRET_KEY accepted")
	}
	if !strings.Contains(err.Error(), "SECRET_KEY") {
		t.Errorf("error should name SECRET_KEY: %v", err)
	}
}

func TestLoadRequiresBaseURL(t *testing.T) {
	t.Setenv("BASE_URL", "placeholder")
	t.Setenv("SECRET_KEY", validSecret)
	if err := os.Unsetenv("BASE_URL"); err != nil {
		t.Fatalf("unset BASE_URL: %v", err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("missing BASE_URL accepted")
	}
}

func TestLoadValidatesSMTPTLS(t *testing.T) {
	for _, mode := range []string{"starttls", "tls", "none"} {
		setRequired(t)
		t.Setenv("SMTP_TLS", mode)
		if _, err := Load(); err != nil {
			t.Errorf("SMTP_TLS=%s rejected: %v", mode, err)
		}
	}
	setRequired(t)
	t.Setenv("SMTP_TLS", "sslv3")
	if _, err := Load(); err == nil {
		t.Error("invalid SMTP_TLS accepted")
	}
}

func TestLoadParsesRedirectAllowedHosts(t *testing.T) {
	setRequired(t)
	t.Setenv("REDIRECT_ALLOWED_HOSTS", ".example.net,app.example.org")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.RedirectAllowedHosts) != 2 {
		t.Fatalf("got %d hosts, want 2: %v", len(cfg.RedirectAllowedHosts), cfg.RedirectAllowedHosts)
	}
	if cfg.RedirectAllowedHosts[0] != ".example.net" || cfg.RedirectAllowedHosts[1] != "app.example.org" {
		t.Errorf("parsed hosts = %v", cfg.RedirectAllowedHosts)
	}
}

func TestLoadReadsAdminSettings(t *testing.T) {
	setRequired(t)
	t.Setenv("ADMIN_PORT", "9000")
	t.Setenv("ADMIN_URL", "https://admin.auth.example.com")
	t.Setenv("ADMIN_BASE_PATH", "/admin")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AdminPort != 9000 {
		t.Errorf("AdminPort = %d, want 9000", cfg.AdminPort)
	}
	if cfg.AdminURL != "https://admin.auth.example.com" {
		t.Errorf("AdminURL = %q", cfg.AdminURL)
	}
	if cfg.AdminBasePath != "/admin" {
		t.Errorf("AdminBasePath = %q", cfg.AdminBasePath)
	}
}
