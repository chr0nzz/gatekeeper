package ui

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
	oidcstore "github.com/chr0nzz/gatekeeper/internal/oidc"
	gktemplates "github.com/chr0nzz/gatekeeper/internal/templates"
	"github.com/go-chi/chi/v5"
)

const testSecret = "0123456789abcdef0123456789abcdef"

type uiHarness struct {
	h        *Handlers
	db       *sql.DB
	router   chi.Router
	settings *queries.SettingsStore
	sessions *auth.SessionStore
	users    *queries.UserStore
	otps     *auth.OTPStore
	handoff  *auth.HandoffStore
}

func newUIHarness(t *testing.T) *uiHarness {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	settings := queries.NewSettingsStore(conn)
	settings.SetCipher(auth.NewSettingsCipher([]byte(testSecret)))
	users := queries.NewUserStore(conn)
	sessions := auth.NewSessionStore(conn, func() time.Duration { return time.Hour }, "")
	otps := auth.NewOTPStore(conn, []byte(testSecret))
	handoff := auth.NewHandoffStore(conn)

	renderer, err := gktemplates.New(gatekeeper.Assets, "web/templates")
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	oidcStorage := oidcstore.NewStorage(conn, "https://auth.example.com")
	if err := oidcStorage.EnsureSigningKey(context.Background()); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	m := mailer.New(func(ctx context.Context) mailer.Settings { return mailer.Settings{} })

	h := New(
		conn, users, sessions, otps,
		auth.NewTOTPStore(conn, []byte(testSecret)),
		mustPasskeys(t, conn),
		auth.NewPasswordResetStore(conn),
		settings,
		auth.NewTrustedDeviceStore(conn, ""),
		m,
		audit.New(conn),
		renderer,
		oidcStorage,
		"https://auth.example.com", "auth.example.com", testSecret, "",
		queries.NewPolicyStore(conn),
		queries.NewInviteStore(conn),
		queries.NewSocialStore(conn),
		queries.NewQRTokenStore(conn),
		handoff,
		auth.NewRedirectPolicy("https://auth.example.com", "", "", nil),
	)

	r := chi.NewRouter()
	r.Use(gkmiddleware.CSRF)
	h.Mount(r)

	return &uiHarness{
		h: h, db: conn, router: r, settings: settings,
		sessions: sessions, users: users, otps: otps, handoff: handoff,
	}
}

func mustPasskeys(t *testing.T, conn *sql.DB) *auth.PasskeyStore {
	t.Helper()
	p, err := auth.NewPasskeyStore(conn, "auth.example.com", "GateKeeper", "https://auth.example.com", nil)
	if err != nil {
		t.Fatalf("passkey store: %v", err)
	}
	return p
}

func (u *uiHarness) addUser(t *testing.T, email, password string) string {
	t.Helper()
	hash := ""
	if password != "" {
		h, err := auth.HashPassword(password)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		hash = h
	}
	id, err := u.users.Create(context.Background(), email, hash, false)
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}

func (u *uiHarness) signIn(t *testing.T, userID string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := u.sessions.Create(rec, req, auth.SessionData{UserID: userID}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gk_session" {
			return c
		}
	}
	t.Fatal("no session cookie was set")
	return nil
}

func (u *uiHarness) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	u.router.ServeHTTP(rec, req)
	return rec
}

func (u *uiHarness) postForm(path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
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
	u.router.ServeHTTP(rec, req)
	return rec
}

func (u *uiHarness) set(t *testing.T, key, value string) {
	t.Helper()
	if err := u.settings.Set(context.Background(), key, value); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

func (u *uiHarness) auditCount(event string) int {
	var n int
	u.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event=?`, event).Scan(&n)
	return n
}

func location(rec *httptest.ResponseRecorder) string {
	return rec.Header().Get("Location")
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func newGetRequest(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func newPostRequest(path string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}
