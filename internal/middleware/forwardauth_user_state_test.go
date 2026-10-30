package middleware

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

	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

func newUserStateHarness(t *testing.T) (*ForwardAuth, *auth.SessionStore, *sql.DB) {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "fa.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	sessions := auth.NewSessionStore(conn, func() time.Duration { return time.Hour }, "")
	fa := NewForwardAuth(sessions, auth.NewHandoffStore(conn), conn, "https://auth.example.com", "0123456789abcdef0123456789abcdef", "",
		queries.NewPolicyStore(conn), queries.NewGroupStore(conn), audit.New(conn))
	return fa, sessions, conn
}

func verifyAs(t *testing.T, fa *ForwardAuth, sessions *auth.SessionStore, userID string) *httptest.ResponseRecorder {
	t.Helper()
	sessRec := httptest.NewRecorder()
	if _, err := sessions.Create(sessRec, httptest.NewRequest(http.MethodGet, "/", nil), auth.SessionData{UserID: userID}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "radarr.example.com")
	req.Header.Set("X-Forwarded-Uri", "/movies")
	for _, c := range sessRec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	fa.Verify(rec, req)
	return rec
}

func TestVerifyAllowsActiveUser(t *testing.T) {
	fa, sessions, conn := newUserStateHarness(t)
	uid, err := queries.NewUserStore(conn).Create(context.Background(), "ok@example.com", "", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	rec := verifyAs(t, fa, sessions, uid)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Auth-Email"); got != "ok@example.com" {
		t.Errorf("X-Auth-Email = %q", got)
	}
}

func TestVerifySendsForcedPasswordChangeToChangePage(t *testing.T) {
	fa, sessions, conn := newUserStateHarness(t)
	uid, err := queries.NewUserStore(conn).Create(context.Background(), "force@example.com", "", true)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	rec := verifyAs(t, fa, sessions, uid)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	want := "https://auth.example.com/profile/password?forced=1&redirect_uri=" + url.QueryEscape("https://radarr.example.com/movies")
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if rec.Header().Get("X-Auth-User") != "" {
		t.Error("identity headers set for a user who must change their password")
	}
}

func TestVerifyRejectsUserDisabledOutsideAdminUI(t *testing.T) {
	for _, mutate := range []string{
		`UPDATE users SET disabled=1 WHERE id=?`,
		`DELETE FROM users WHERE id=?`,
	} {
		fa, sessions, conn := newUserStateHarness(t)
		uid, err := queries.NewUserStore(conn).Create(context.Background(), "gone@example.com", "", false)
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		if _, err := conn.Exec(mutate, uid); err != nil {
			t.Fatalf("mutate: %v", err)
		}

		rec := verifyAs(t, fa, sessions, uid)
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://auth.example.com/login") {
			t.Errorf("after %q: status %d location %q, want redirect to login", mutate, rec.Code, rec.Header().Get("Location"))
		}
	}
}
