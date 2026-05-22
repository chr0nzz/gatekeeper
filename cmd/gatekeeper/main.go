package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gatekeeper "github.com/chr0nzz/gatekeeper"
	"github.com/chr0nzz/gatekeeper/internal/admin"
	gktemplates "github.com/chr0nzz/gatekeeper/internal/templates"
	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/config"
	"github.com/chr0nzz/gatekeeper/internal/db"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
	"github.com/chr0nzz/gatekeeper/internal/mailer"
	gkmiddleware "github.com/chr0nzz/gatekeeper/internal/middleware"
	oidcstore "github.com/chr0nzz/gatekeeper/internal/oidc"
	"github.com/chr0nzz/gatekeeper/internal/ui"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var version = "dev"

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		slog.Error("database error", "err", err)
		os.Exit(1)
	}
	defer database.Close()

	auditLog := audit.New(database)
	userStore := queries.NewUserStore(database)
	adminStore := queries.NewAdminStore(database)
	adminSessStore := queries.NewAdminSessionStore(database)
	settingsStore := queries.NewSettingsStore(database)
	otpStore := auth.NewOTPStore(database)
	totpStore := auth.NewTOTPStore(database, []byte(cfg.SecretKey))
	resetStore := auth.NewPasswordResetStore(database)
	trustedDeviceStore := auth.NewTrustedDeviceStore(database, cfg.CookieDomain)
	sessionStore := auth.NewSessionStore(database, func() time.Duration {
		v := settingsStore.Get(context.Background(), "session_ttl_hours", "")
		if v != "" {
			if n := mailer.PortFromString(v); n > 0 {
				return time.Duration(n) * time.Hour
			}
		}
		return time.Duration(cfg.SessionTTLHours) * time.Hour
	}, cfg.CookieDomain)

	envSMTP := mailer.Settings{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort,
		Username: cfg.SMTPUsername, Password: cfg.SMTPPassword,
		From: cfg.SMTPFrom, TLS: cfg.SMTPTLS,
	}
	m := mailer.New(func(ctx context.Context) mailer.Settings {
		get := func(key, fallback string) string {
			return settingsStore.Get(ctx, key, fallback)
		}
		port := mailer.PortFromString(get("smtp_port", ""))
		if port == 587 && cfg.SMTPPort != 0 {
			port = cfg.SMTPPort
		}
		return mailer.Settings{
			Host:     get("smtp_host", cfg.SMTPHost),
			Port:     port,
			Username: get("smtp_username", cfg.SMTPUsername),
			Password: get("smtp_password", cfg.SMTPPassword),
			From:     get("smtp_from", cfg.SMTPFrom),
			TLS:      get("smtp_tls", cfg.SMTPTLS),
		}
	})

	parsedBase, err := url.Parse(cfg.BaseURL)
	if err != nil {
		slog.Error("invalid BASE_URL", "err", err)
		os.Exit(1)
	}
	rpID := parsedBase.Hostname()
	passkeyStore, err := auth.NewPasskeyStore(database, rpID, "GateKeeper", cfg.BaseURL)
	if err != nil {
		slog.Error("passkey store error", "err", err)
		os.Exit(1)
	}

	oidcStorage := oidcstore.NewStorage(database, cfg.BaseURL)
	if err := oidcStorage.EnsureSigningKey(context.Background()); err != nil {
		slog.Error("oidc signing key error", "err", err)
		os.Exit(1)
	}

	renderer, err := gktemplates.New(gatekeeper.Assets, "web/templates")
	if err != nil {
		slog.Error("template renderer error", "err", err)
		os.Exit(1)
	}

	staticSub, _ := fs.Sub(gatekeeper.Assets, "web/static")

	fwAuth := gkmiddleware.NewForwardAuth(sessionStore, database, cfg.BaseURL, cfg.SecretKey, cfg.CookieDomain)

	uiHandlers := ui.New(database, userStore, sessionStore, otpStore, totpStore, passkeyStore, resetStore, settingsStore, trustedDeviceStore, m, auditLog, renderer, oidcStorage, cfg.BaseURL, rpID, cfg.SecretKey, cfg.CookieDomain)
	adminHandlers := admin.New(database, userStore, adminStore, adminSessStore, sessionStore, totpStore, passkeyStore, trustedDeviceStore, oidcStorage, m, resetStore, settingsStore, auditLog, renderer, cfg.BaseURL, version, envSMTP,
		admin.EnvDefaults{AllowedDomains: cfg.AllowedEmailDomains, SessionTTLHours: cfg.SessionTTLHours})

	secretKey := [32]byte{}
	copy(secretKey[:], []byte(cfg.SecretKey))
	oidcProvider, err := op.NewProvider(
		&op.Config{
			CryptoKey: secretKey,
		},
		oidcStorage,
		op.StaticIssuer(cfg.BaseURL),
		op.WithAllowInsecure(),
	)
	if err != nil {
		slog.Error("oidc provider error", "err", err)
		os.Exit(1)
	}

	r := chi.NewRouter()
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(gkmiddleware.SecureHeaders)
	r.Use(gkmiddleware.CSRF)

	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	r.Get("/auth/verify", fwAuth.Verify)
	r.Get("/oidc/icon/{id}", func(w http.ResponseWriter, r *http.Request) {
		oidcStorage.ServeIcon(w, r, chi.URLParam(r, "id"))
	})

	oidc := func(w http.ResponseWriter, r *http.Request) { oidcProvider.ServeHTTP(w, r) }
	r.Get("/.well-known/openid-configuration", oidc)
	r.Get("/.well-known/jwks.json", oidc)
	for _, p := range []string{"/authorize", "/authorize/callback", "/userinfo", "/revoke", "/end_session", "/device_authorization", "/keys"} {
		r.Get(p, oidc)
		r.Post(p, oidc)
	}
	r.Post("/oauth/token", oidc)
	r.Post("/oauth/introspect", oidc)
	r.Handle("/oauth/*", http.HandlerFunc(oidc))

	r.Group(func(r chi.Router) {
		uiHandlers.Mount(r)
	})

	r.Route("/admin", func(r chi.Router) {
		adminHandlers.Mount(r)
	})

	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		for range ticker.C {
			sessionStore.CleanExpired(context.Background())
		}
	}()

	addr := fmt.Sprintf(":%d", cfg.Port)
	slog.Info("gatekeeper starting", "addr", addr, "base_url", cfg.BaseURL, "version", version)
	if err := http.ListenAndServe(addr, r); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

