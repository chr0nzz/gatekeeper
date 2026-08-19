package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

func TestHandoffRedemptionAndPolicyDenialAreAudited(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(filepath.Join(t.TempDir(), "fa.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer conn.Close()

	sessions := auth.NewSessionStore(conn, func() time.Duration { return time.Hour }, "")
	handoff := auth.NewHandoffStore(conn)
	fa := NewForwardAuth(sessions, handoff, conn, "https://auth.example.com", "0123456789abcdef0123456789abcdef", "",
		queries.NewPolicyStore(conn), queries.NewGroupStore(conn), audit.New(conn))

	users := queries.NewUserStore(conn)
	uid, err := users.Create(ctx, "fa@example.com", "", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, err := handoff.Create(ctx, uid, "radarr.example.com")
	if err != nil {
		t.Fatalf("create handoff: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "radarr.example.com")
	req.Header.Set("X-Forwarded-Uri", "/_gk/auth?token="+url.QueryEscape(token)+"&redirect=/movies")
	rec := httptest.NewRecorder()
	fa.Verify(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("handoff status = %d, want 302", rec.Code)
	}

	var actor string
	conn.QueryRow(`SELECT COALESCE(actor_id,'') FROM audit_log WHERE event='login.handoff' AND user_id=?`, uid).Scan(&actor)
	if actor != "radarr.example.com" {
		t.Errorf("login.handoff actor = %q, want radarr.example.com", actor)
	}

	sessRec := httptest.NewRecorder()
	if _, err := sessions.Create(sessRec, httptest.NewRequest(http.MethodGet, "/", nil), auth.SessionData{UserID: uid}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/auth/verify?policy=locked-down", nil)
	req2.Header.Set("X-Forwarded-Host", "sonarr.example.com")
	for _, c := range sessRec.Result().Cookies() {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	fa.Verify(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("policy status = %d, want 403", rec2.Code)
	}

	var host, detail string
	conn.QueryRow(`SELECT COALESCE(actor_id,''), COALESCE(detail,'') FROM audit_log WHERE event='forwardauth.denied' AND user_id=?`, uid).Scan(&host, &detail)
	if host != "sonarr.example.com" || detail != "policy: locked-down" {
		t.Errorf("forwardauth.denied = %q / %q, want sonarr.example.com / policy: locked-down", host, detail)
	}
}
