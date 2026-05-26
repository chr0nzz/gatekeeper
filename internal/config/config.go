package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
)

// Config holds infrastructure-level configuration that cannot change without a restart.
// Runtime settings (SMTP, session TTL, allowed domains) are managed in the admin UI.
type Config struct {
	Port    int    `env:"PORT" envDefault:"8080"`
	BaseURL string `env:"BASE_URL,required"`

	SecretKey string `env:"SECRET_KEY,required"`

	DBPath string `env:"DB_PATH" envDefault:"/data/gatekeeper.db"`

	// SMTP env vars serve as fallback defaults; the admin UI values take precedence.
	SMTPHost     string `env:"SMTP_HOST"`
	SMTPPort     int    `env:"SMTP_PORT" envDefault:"587"`
	SMTPUsername string `env:"SMTP_USERNAME"`
	SMTPPassword string `env:"SMTP_PASSWORD"`
	SMTPFrom     string `env:"SMTP_FROM"`
	SMTPTLS      string `env:"SMTP_TLS" envDefault:"starttls"`

	// SessionTTLHours and AllowedEmailDomains are fallback defaults; admin UI values take precedence.
	SessionTTLHours     int    `env:"SESSION_TTL_HOURS" envDefault:"8"`
	AllowedEmailDomains string `env:"ALLOWED_EMAIL_DOMAINS"`
	CookieDomain        string `env:"COOKIE_DOMAIN"`

	// RegistrationMode and RegistrationAllowedDomains are fallback defaults; admin UI values take precedence.
	RegistrationMode           string `env:"REGISTRATION_MODE" envDefault:"disabled"`
	RegistrationAllowedDomains string `env:"REGISTRATION_ALLOWED_DOMAINS"`

	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
}

// Load parses and validates configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(cfg.SecretKey) < 32 {
		return nil, fmt.Errorf("SECRET_KEY must be at least 32 characters")
	}
	switch cfg.SMTPTLS {
	case "starttls", "tls", "none":
	default:
		return nil, fmt.Errorf("SMTP_TLS must be starttls, tls, or none")
	}
	return cfg, nil
}
