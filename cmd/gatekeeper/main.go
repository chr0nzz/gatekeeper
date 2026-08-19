package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	gatekeeper "github.com/chr0nzz/gatekeeper"
	"github.com/chr0nzz/gatekeeper/internal/admin"
	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	gkbackup "github.com/chr0nzz/gatekeeper/internal/backup"
	"github.com/chr0nzz/gatekeeper/internal/config"
	"github.com/chr0nzz/gatekeeper/internal/db"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
	"github.com/chr0nzz/gatekeeper/internal/mailer"
	gkmiddleware "github.com/chr0nzz/gatekeeper/internal/middleware"
	"github.com/chr0nzz/gatekeeper/internal/notify"
	oidcstore "github.com/chr0nzz/gatekeeper/internal/oidc"
	gktemplates "github.com/chr0nzz/gatekeeper/internal/templates"
	"github.com/chr0nzz/gatekeeper/internal/ui"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var version = "0.9.5"

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
	webhookStore := queries.NewWebhookStore(database)
	userStore := queries.NewUserStore(database)
	adminStore := queries.NewAdminStore(database)
	adminSessStore := queries.NewAdminSessionStore(database)
	groupStore := queries.NewGroupStore(database)
	inviteStore := queries.NewInviteStore(database)
	claimStore := queries.NewClaimStore(database)
	socialStore := queries.NewSocialStore(database)
	qrTokenStore := queries.NewQRTokenStore(database)
	settingsStore := queries.NewSettingsStore(database)
	settingsStore.SetCipher(auth.NewSettingsCipher([]byte(cfg.SecretKey)))
	backupStore := queries.NewBackupStore(database)
	{
		ctx := context.Background()
		seed := func(key, val string) {
			if val != "" && settingsStore.Get(ctx, key, "") == "" {
				settingsStore.Set(ctx, key, val)
			}
		}
		seed("social_github_client_id", cfg.GitHubClientID)
		seed("social_github_client_secret", cfg.GitHubClientSecret)
		seed("social_google_client_id", cfg.GoogleClientID)
		seed("social_google_client_secret", cfg.GoogleClientSecret)
		seed("social_discord_client_id", cfg.DiscordClientID)
		seed("social_discord_client_secret", cfg.DiscordClientSecret)
	}
	otpStore := auth.NewOTPStore(database, []byte(cfg.SecretKey))
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

	m.SetBrandingLoader(func(ctx context.Context) mailer.Branding {
		return mailer.Branding{
			LogoURL:     settingsStore.Get(ctx, "email_logo_url", ""),
			SenderName:  settingsStore.Get(ctx, "email_sender_name", ""),
			AccentColor: settingsStore.Get(ctx, "email_accent_color", ""),
		}
	})

	notifyService := notify.New(database, webhookStore, m)
	auditLog.AddHook(notifyService.Dispatch)

	parsedBase, err := url.Parse(cfg.BaseURL)
	if err != nil {
		slog.Error("invalid BASE_URL", "err", err)
		os.Exit(1)
	}
	rpID := parsedBase.Hostname()
	var waOrigins []string
	if cfg.AdminURL != "" {
		waOrigins = append(waOrigins, cfg.AdminURL)
	}
	passkeyStore, err := auth.NewPasskeyStore(database, rpID, "GateKeeper", cfg.BaseURL, waOrigins)
	if err != nil {
		slog.Error("passkey store error", "err", err)
		os.Exit(1)
	}

	policyStore := queries.NewPolicyStore(database)
	handoffStore := auth.NewHandoffStore(database)
	redirectPolicy := auth.NewRedirectPolicy(cfg.BaseURL, cfg.AdminURL, cfg.CookieDomain, cfg.RedirectAllowedHosts)
	redirectPolicy.SetExtraHosts(func() []string {
		return auth.ParseHostList(settingsStore.Get(context.Background(), "redirect_allowed_hosts", ""))
	})

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

	staticETags := map[string]string{}
	fs.WalkDir(staticSub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, readErr := fs.ReadFile(staticSub, p)
		if readErr != nil {
			return nil
		}
		sum := sha256.Sum256(body)
		staticETags["/"+p] = `"` + hex.EncodeToString(sum[:12]) + `"`
		return nil
	})
	staticFiles := http.StripPrefix("/static/", http.FileServer(http.FS(staticSub)))
	staticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tag, ok := staticETags[strings.TrimPrefix(r.URL.Path, "/static")]; ok {
			w.Header().Set("ETag", tag)
			w.Header().Set("Cache-Control", "no-cache")
			if r.Header.Get("If-None-Match") == tag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		staticFiles.ServeHTTP(w, r)
	})

	fwAuth := gkmiddleware.NewForwardAuth(sessionStore, handoffStore, database, cfg.BaseURL, cfg.SecretKey, cfg.CookieDomain, policyStore, groupStore, auditLog)

	uiHandlers := ui.New(database, userStore, sessionStore, otpStore, totpStore, passkeyStore, resetStore, settingsStore, trustedDeviceStore, m, auditLog, renderer, oidcStorage, cfg.BaseURL, rpID, cfg.SecretKey, cfg.CookieDomain, policyStore, inviteStore, socialStore, qrTokenStore, handoffStore, redirectPolicy)
	adminHandlers := admin.New(database, userStore, adminStore, adminSessStore, sessionStore, totpStore, passkeyStore, trustedDeviceStore, oidcStorage, m, resetStore, settingsStore, auditLog, renderer, cfg.BaseURL, cfg.AdminBasePath, version, cfg.DBPath, cfg.SecretKey, envSMTP,
		admin.EnvDefaults{AllowedDomains: cfg.AllowedEmailDomains, SessionTTLHours: cfg.SessionTTLHours, RegistrationMode: cfg.RegistrationMode, RegistrationAllowedDomains: cfg.RegistrationAllowedDomains, GitHubClientID: cfg.GitHubClientID, GitHubClientSecret: cfg.GitHubClientSecret, GoogleClientID: cfg.GoogleClientID, GoogleClientSecret: cfg.GoogleClientSecret, DiscordClientID: cfg.DiscordClientID, DiscordClientSecret: cfg.DiscordClientSecret}, policyStore, groupStore, inviteStore, webhookStore, claimStore, notifyService, backupStore)

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

	swHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := gatekeeper.Assets.ReadFile("web/static/sw.js")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Service-Worker-Allowed", "/")
		w.Write([]byte(strings.ReplaceAll(string(data), "__GK_VERSION__", version)))
	})
	serveManifest := func(file string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			data, err := gatekeeper.Assets.ReadFile("web/static/" + file)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/manifest+json")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.Write(data)
		}
	}
	attachBase := func(r chi.Router) {
		r.Use(gkmiddleware.TrustedRealIP)
		r.Use(chimiddleware.Recoverer)
		r.Use(gkmiddleware.SecureHeaders)
		r.Use(gkmiddleware.CSRF)
		r.Handle("/static/*", staticHandler)
		r.Get("/sw.js", swHandler)
	}

	pub := chi.NewRouter()
	attachBase(pub)
	pub.Get("/manifest.json", serveManifest("manifest.json"))
	pub.Get("/auth/verify", fwAuth.Verify)
	pub.Get("/oidc/icon/{id}", func(w http.ResponseWriter, r *http.Request) {
		oidcStorage.ServeIcon(w, r, chi.URLParam(r, "id"))
	})
	oidc := func(w http.ResponseWriter, r *http.Request) { oidcProvider.ServeHTTP(w, r) }
	pub.Get("/.well-known/openid-configuration", oidc)
	pub.Get("/.well-known/jwks.json", oidc)
	pub.Get("/end_session", uiHandlers.EndSession)
	pub.Post("/end_session", uiHandlers.EndSession)
	for _, p := range []string{"/authorize", "/authorize/callback", "/userinfo", "/revoke", "/device_authorization", "/keys"} {
		pub.Get(p, oidc)
		pub.Post(p, oidc)
	}
	pub.Post("/oauth/token", oidc)
	pub.Post("/oauth/introspect", oidc)
	pub.Handle("/oauth/*", http.HandlerFunc(oidc))
	pub.Group(func(r chi.Router) {
		uiHandlers.Mount(r)
	})

	adm := chi.NewRouter()
	attachBase(adm)
	adm.Get("/manifest-admin.json", serveManifest("manifest-admin.json"))
	adm.Get("/oidc/icon/{id}", func(w http.ResponseWriter, r *http.Request) {
		oidcStorage.ServeIcon(w, r, chi.URLParam(r, "id"))
	})
	adm.Get("/avatar/{id}", func(w http.ResponseWriter, r *http.Request) {
		data, mime := userStore.GetAvatar(r.Context(), chi.URLParam(r, "id"))
		if len(data) == 0 {
			http.NotFound(w, r)
			return
		}
		if mime == "" {
			mime = "image/jpeg"
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data)
	})
	if cfg.AdminBasePath != "" {
		adm.Route(cfg.AdminBasePath, func(r chi.Router) {
			adminHandlers.Mount(r)
		})
	} else {
		adminHandlers.Mount(adm)
	}

	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		for range ticker.C {
			sessionStore.CleanExpired(context.Background())
			handoffStore.CleanExpired(context.Background())
		}
	}()

	go func() {
		rotateSigningKey := func() {
			rotated, err := oidcStorage.RotateSigningKeyIfDue(context.Background())
			if err != nil {
				slog.Error("oidc signing key rotation failed", "err", err)
				return
			}
			if rotated {
				slog.Info("oidc signing key rotated")
			}
		}
		rotateSigningKey()
		ticker := time.NewTicker(time.Hour)
		for range ticker.C {
			rotateSigningKey()
		}
	}()

	go func() {
		purgeAuditLog := func() {
			val := settingsStore.Get(context.Background(), "audit_retention_days", "90")
			n, err := strconv.Atoi(val)
			if err != nil || n <= 0 {
				return
			}
			cutoff := time.Now().AddDate(0, 0, -n).Unix()
			database.ExecContext(context.Background(), `DELETE FROM audit_log WHERE created_at < ?`, cutoff)
		}
		purgeAuditLog()
		ticker := time.NewTicker(24 * time.Hour)
		for range ticker.C {
			purgeAuditLog()
		}
	}()

	var backupScheduler gkbackup.Scheduler
	backupScheduler.Start(
		func() time.Duration {
			return gkbackup.ScheduleInterval(settingsStore.Get(context.Background(), "backup_schedule", "manual"))
		},
		func(ctx context.Context) error {
			storage := gkbackup.BuildStorage(settingsStore)
			if storage == nil {
				return nil
			}
			retentionStr := settingsStore.Get(ctx, "backup_retention", "10")
			retention, _ := strconv.Atoi(retentionStr)
			if retention <= 0 {
				retention = 10
			}
			return gkbackup.RunBackup(ctx, database, cfg.DBPath, []byte(cfg.SecretKey), storage, backupStore, retention)
		},
	)
	defer backupScheduler.Stop()

	go func() {
		adminAddr := fmt.Sprintf(":%d", cfg.AdminPort)
		slog.Info("admin server starting", "addr", adminAddr, "admin_url", cfg.AdminURL)
		if err := http.ListenAndServe(adminAddr, adm); err != nil {
			slog.Error("admin server error", "err", err)
			os.Exit(1)
		}
	}()

	pubAddr := fmt.Sprintf(":%d", cfg.Port)
	slog.Info("gatekeeper starting", "addr", pubAddr, "base_url", cfg.BaseURL, "version", version)
	if err := http.ListenAndServe(pubAddr, pub); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}
