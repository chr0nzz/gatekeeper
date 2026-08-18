package admin

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gatekeeper "github.com/chr0nzz/gatekeeper"
	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
	"github.com/chr0nzz/gatekeeper/internal/mailer"
	gkmiddleware "github.com/chr0nzz/gatekeeper/internal/middleware"
	"github.com/chr0nzz/gatekeeper/internal/notify"
	oidcstore "github.com/chr0nzz/gatekeeper/internal/oidc"
	gktemplates "github.com/chr0nzz/gatekeeper/internal/templates"
	"github.com/go-chi/chi/v5"
)

const adminTestSecret = "0123456789abcdef0123456789abcdef"

type adminHarness struct {
	h        *Handlers
	db       *sql.DB
	router   chi.Router
	settings *queries.SettingsStore
	users    *queries.UserStore
	admins   *queries.AdminStore
	sessions *queries.AdminSessionStore
	adminID  string
}

func newAdminHarness(t *testing.T) *adminHarness {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	settings := queries.NewSettingsStore(conn)
	settings.SetCipher(auth.NewSettingsCipher([]byte(adminTestSecret)))
	users := queries.NewUserStore(conn)
	admins := queries.NewAdminStore(conn)
	adminSess := queries.NewAdminSessionStore(conn)
	webhooks := queries.NewWebhookStore(conn)

	renderer, err := gktemplates.New(gatekeeper.Assets, "web/templates")
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	oidcStorage := oidcstore.NewStorage(conn, "https://auth.example.com")
	if err := oidcStorage.EnsureSigningKey(context.Background()); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	m := mailer.New(func(ctx context.Context) mailer.Settings { return mailer.Settings{} })

	passkeys, err := auth.NewPasskeyStore(conn, "auth.example.com", "GateKeeper", "https://auth.example.com", nil)
	if err != nil {
		t.Fatalf("passkey store: %v", err)
	}

	h := New(
		conn, users, admins, adminSess,
		auth.NewSessionStore(conn, func() time.Duration { return time.Hour }, ""),
		auth.NewTOTPStore(conn, []byte(adminTestSecret)),
		passkeys,
		auth.NewTrustedDeviceStore(conn, ""),
		oidcStorage, m,
		auth.NewPasswordResetStore(conn),
		settings,
		audit.New(conn),
		renderer,
		"https://auth.example.com", "", "test", filepath.Join(t.TempDir(), "gk.db"), adminTestSecret,
		mailer.Settings{},
		EnvDefaults{},
		queries.NewPolicyStore(conn),
		queries.NewGroupStore(conn),
		queries.NewInviteStore(conn),
		webhooks,
		queries.NewClaimStore(conn),
		notify.New(conn, webhooks, m),
		queries.NewBackupStore(conn),
	)

	r := chi.NewRouter()
	r.Use(gkmiddleware.CSRF)
	h.Mount(r)

	return &adminHarness{
		h: h, db: conn, router: r, settings: settings,
		users: users, admins: admins, sessions: adminSess,
	}
}

func (a *adminHarness) signIn(t *testing.T) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := a.admins.Create(ctx, "admin@example.com", hash, "Test Admin"); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	admin, err := a.admins.GetByEmail(ctx, "admin@example.com")
	if err != nil || admin == nil {
		t.Fatalf("load admin: %v", err)
	}
	a.adminID = admin.ID
	id, err := a.sessions.Create(ctx, admin.ID)
	if err != nil {
		t.Fatalf("admin session: %v", err)
	}
	return &http.Cookie{Name: "gk_admin", Value: id}
}

func (a *adminHarness) addUser(t *testing.T, email string) string {
	t.Helper()
	id, err := a.users.Create(context.Background(), email, "", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

func (a *adminHarness) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	return rec
}

func (a *adminHarness) postForm(path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	const csrf = "test-csrf-token"
	if form == nil {
		form = url.Values{}
	}
	if form.Get("csrf_token") == "" {
		form.Set("csrf_token", csrf)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "gk_csrf", Value: csrf})
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	return rec
}

func (a *adminHarness) postWithoutCSRF(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "gk_csrf", Value: "test-csrf-token"})
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	return rec
}

func (a *adminHarness) set(t *testing.T, key, value string) {
	t.Helper()
	if err := a.settings.Set(context.Background(), key, value); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

func adminLocation(rec *httptest.ResponseRecorder) string {
	return rec.Header().Get("Location")
}
