package notify

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/db"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
)

func ntfOpenDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "gatekeeper.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func ntfNewService(t *testing.T) (*Service, *sql.DB, *queries.WebhookStore) {
	t.Helper()
	database := ntfOpenDB(t)
	store := queries.NewWebhookStore(database)
	return New(database, store, nil), database, store
}

func ntfAddWebhook(t *testing.T, database *sql.DB, w queries.Webhook) string {
	t.Helper()
	if w.ID == "" {
		w.ID = w.Name
	}
	if w.Events == "" {
		w.Events = "all"
	}
	enabled := 0
	if w.Enabled {
		enabled = 1
	}
	_, err := database.Exec(
		`INSERT INTO webhooks (id,name,type,enabled,url,token,chat_id,username,password,topic,events,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		w.ID, w.Name, w.Type, enabled, w.URL, w.Token, w.ChatID, w.Username, w.Password, w.Topic, w.Events, time.Now().Unix(),
	)
	if err != nil {
		t.Fatalf("insert webhook %s: %v", w.Name, err)
	}
	return w.ID
}

func ntfAddUser(t *testing.T, database *sql.DB, id, email, displayName string) {
	t.Helper()
	now := time.Now().Unix()
	if _, err := database.Exec(
		`INSERT INTO users (id,email,display_name,created_at,updated_at) VALUES (?,?,?,?,?)`,
		id, email, displayName, now, now,
	); err != nil {
		t.Fatalf("insert user %s: %v", id, err)
	}
}

func ntfCountFor(t *testing.T, database *sql.DB, webhookID string) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM notifications WHERE webhook_id=?`, webhookID).Scan(&n); err != nil {
		t.Fatalf("count notifications for %s: %v", webhookID, err)
	}
	return n
}

func ntfLatestFor(t *testing.T, database *sql.DB, webhookID string) queries.Notification {
	t.Helper()
	var n queries.Notification
	err := database.QueryRow(
		`SELECT webhook_id,webhook_name,event,user_id,ip,status,detail,error FROM notifications WHERE webhook_id=? ORDER BY created_at DESC LIMIT 1`,
		webhookID,
	).Scan(&n.WebhookID, &n.WebhookName, &n.Event, &n.UserID, &n.IP, &n.Status, &n.Detail, &n.Error)
	if err != nil {
		t.Fatalf("read notification for %s: %v", webhookID, err)
	}
	return n
}

// Dispatch delivers in a goroutine, so the only stable barrier is the log row
// it writes when the attempt finishes.
func ntfAwaitCount(t *testing.T, database *sql.DB, webhookID string, want int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if got := ntfCountFor(t, database, webhookID); got >= want {
				return
			}
		case <-deadline:
			t.Fatalf("webhook %s logged %d notifications, want %d", webhookID, ntfCountFor(t, database, webhookID), want)
		}
	}
}

// Webhook URLs are operator supplied, so every sender must refuse to reach an
// address on the internal network. The test server stands in for a service that
// is only reachable from inside the deployment.
func TestWebhookSendersRefuseInternalTargets(t *testing.T) {
	received := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- string(body)
	}))
	defer srv.Close()

	senders := map[string]func() error{
		"discord": func() error { return sendDiscord(srv.URL, "login.failure", "message") },
		"slack":   func() error { return sendSlack(srv.URL, "login.failure", "message") },
		"generic": func() error { return sendGeneric(srv.URL, "login.failure", "user-1", "203.0.113.9", "detail") },
		"ntfy":    func() error { return sendNtfy(srv.URL, "alerts", "user", "pass", "login.failure", "message") },
	}
	for name, send := range senders {
		if err := send(); err == nil {
			t.Errorf("%s delivery to a loopback URL succeeded, want refused", name)
		}
	}

	select {
	case body := <-received:
		t.Fatalf("internal server received a webhook delivery: %s", body)
	default:
	}
}

func TestSendTestRefusesInternalTargets(t *testing.T) {
	received := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
	}))
	defer srv.Close()

	svc, database, _ := ntfNewService(t)
	for _, typ := range []string{"discord", "slack", "generic", "ntfy_self"} {
		id := ntfAddWebhook(t, database, queries.Webhook{Name: typ + "-probe", Type: typ, Enabled: true, URL: srv.URL, Topic: "alerts"})
		if err := svc.SendTest(context.Background(), id); err == nil {
			t.Errorf("SendTest for %s reached a loopback URL, want refused", typ)
		}
	}

	select {
	case <-received:
		t.Fatal("SendTest delivered to an internal address")
	default:
	}
}

func TestWebhookSendersRejectNonHTTPSchemes(t *testing.T) {
	bad := []string{"file:///etc/passwd", "gopher://internal:70/", "javascript:alert(1)", "", "not a url"}
	for _, raw := range bad {
		if err := sendDiscord(raw, "login.failure", "message"); err == nil {
			t.Errorf("sendDiscord(%q) = nil, want error", raw)
		}
		if err := sendSlack(raw, "login.failure", "message"); err == nil {
			t.Errorf("sendSlack(%q) = nil, want error", raw)
		}
		if err := sendGeneric(raw, "login.failure", "user-1", "203.0.113.9", "detail"); err == nil {
			t.Errorf("sendGeneric(%q) = nil, want error", raw)
		}
	}
}

func TestTelegramRequiresTokenAndChatID(t *testing.T) {
	if err := sendTelegram("", "12345", "message"); err == nil {
		t.Error("sendTelegram with no token = nil, want error")
	}
	if err := sendTelegram("bot-token", "", "message"); err == nil {
		t.Error("sendTelegram with no chat id = nil, want error")
	}
}

func TestNtfyRequiresTopic(t *testing.T) {
	if err := sendNtfy("https://ntfy.example.com", "", "", "", "login.failure", "message"); err == nil {
		t.Error("sendNtfy with no topic = nil, want error")
	}
}

func TestDisabledWebhookIsNotDelivered(t *testing.T) {
	svc, database, _ := ntfNewService(t)
	off := ntfAddWebhook(t, database, queries.Webhook{Name: "off", Type: "generic", Enabled: false, URL: "http://127.0.0.1:9/hook"})
	on := ntfAddWebhook(t, database, queries.Webhook{Name: "on", Type: "generic", Enabled: true, URL: "http://127.0.0.1:10/hook"})

	svc.Dispatch("login.failure", "user-1", "admin-1", "203.0.113.9", "wrong password")

	ntfAwaitCount(t, database, on, 1)
	if got := ntfCountFor(t, database, off); got != 0 {
		t.Fatalf("disabled webhook logged %d deliveries, want 0", got)
	}
}

func TestDispatchOnlyNotifiesSubscribedWebhooks(t *testing.T) {
	svc, database, _ := ntfNewService(t)
	subscribed := ntfAddWebhook(t, database, queries.Webhook{
		Name: "security-only", Type: "generic", Enabled: true,
		Events: "login.failure, user.deleted", URL: "http://127.0.0.1:9/hook",
	})
	catchAll := ntfAddWebhook(t, database, queries.Webhook{
		Name: "catch-all", Type: "generic", Enabled: true,
		Events: "all", URL: "http://127.0.0.1:10/hook",
	})

	svc.Dispatch("client.created", "user-1", "admin-1", "203.0.113.9", "")
	ntfAwaitCount(t, database, catchAll, 1)
	if got := ntfCountFor(t, database, subscribed); got != 0 {
		t.Fatalf("webhook logged %d deliveries for an unsubscribed event, want 0", got)
	}

	svc.Dispatch("login.failure", "user-1", "admin-1", "203.0.113.9", "wrong password")
	ntfAwaitCount(t, database, subscribed, 1)
	ntfAwaitCount(t, database, catchAll, 2)

	if got := ntfLatestFor(t, database, subscribed).Event; got != "login.failure" {
		t.Fatalf("logged event = %q, want login.failure", got)
	}
}

// A prefix match would wrongly subscribe "login" to "login.failure".
func TestEventSubscriptionRequiresAnExactMatch(t *testing.T) {
	svc, database, _ := ntfNewService(t)
	partial := ntfAddWebhook(t, database, queries.Webhook{
		Name: "partial", Type: "generic", Enabled: true,
		Events: "login", URL: "http://127.0.0.1:9/hook",
	})
	catchAll := ntfAddWebhook(t, database, queries.Webhook{
		Name: "catch-all", Type: "generic", Enabled: true,
		URL: "http://127.0.0.1:10/hook",
	})

	svc.Dispatch("login.failure", "user-1", "admin-1", "203.0.113.9", "")
	ntfAwaitCount(t, database, catchAll, 1)
	if got := ntfCountFor(t, database, partial); got != 0 {
		t.Fatalf("webhook subscribed to \"login\" logged %d deliveries for login.failure, want 0", got)
	}
}

func TestFailedDeliveryIsRecordedWithContext(t *testing.T) {
	svc, database, _ := ntfNewService(t)
	id := ntfAddWebhook(t, database, queries.Webhook{Name: "broken", Type: "generic", Enabled: true, URL: "http://127.0.0.1:9/hook"})
	wh, err := queries.NewWebhookStore(database).GetWebhook(context.Background(), id)
	if err != nil || wh == nil {
		t.Fatalf("get webhook: %v", err)
	}

	svc.send(context.Background(), *wh, "login.failure", "user-1", "203.0.113.9", "wrong password")

	n := ntfLatestFor(t, database, id)
	if n.Status != "failed" {
		t.Fatalf("status = %q, want failed", n.Status)
	}
	if n.Error == "" {
		t.Error("failed delivery recorded an empty error")
	}
	if n.Event != "login.failure" || n.UserID != "user-1" || n.IP != "203.0.113.9" || n.Detail != "wrong password" {
		t.Fatalf("notification lost audit context: %+v", n)
	}
	if n.WebhookName != "broken" {
		t.Fatalf("webhook name = %q, want broken", n.WebhookName)
	}
}

func TestUnknownWebhookTypeIsRecordedAsFailed(t *testing.T) {
	svc, database, _ := ntfNewService(t)
	wh := queries.Webhook{ID: "wh-unknown", Name: "unknown", Type: "carrier-pigeon", Enabled: true, URL: "http://127.0.0.1:9/hook"}
	ntfAddWebhook(t, database, wh)

	svc.send(context.Background(), wh, "login.failure", "user-1", "203.0.113.9", "")

	n := ntfLatestFor(t, database, wh.ID)
	if n.Status != "failed" {
		t.Fatalf("status = %q, want failed", n.Status)
	}
	if !strings.Contains(n.Error, "unknown webhook type") {
		t.Fatalf("error = %q, want it to name the unknown type", n.Error)
	}
}

// Without SMTP the email channel must report failure rather than silently
// dropping a security alert.
func TestEmailWebhookWithoutSMTPFails(t *testing.T) {
	svc, database, _ := ntfNewService(t)
	wh := queries.Webhook{ID: "wh-email", Name: "ops-mail", Type: "email", Enabled: true, URL: "ops@example.com"}
	ntfAddWebhook(t, database, wh)

	svc.send(context.Background(), wh, "login.failure", "user-1", "203.0.113.9", "")

	n := ntfLatestFor(t, database, wh.ID)
	if n.Status != "failed" {
		t.Fatalf("status = %q, want failed", n.Status)
	}
	if !strings.Contains(n.Error, "SMTP not configured") {
		t.Fatalf("error = %q, want it to name the missing SMTP config", n.Error)
	}
	if err := svc.SendTest(context.Background(), wh.ID); err == nil {
		t.Error("SendTest for an email webhook without SMTP = nil, want error")
	}
}

func TestSendTestRejectsMissingAndUnknownWebhooks(t *testing.T) {
	svc, database, _ := ntfNewService(t)

	if err := svc.SendTest(context.Background(), "does-not-exist"); err == nil {
		t.Error("SendTest for a missing webhook = nil, want error")
	}

	id := ntfAddWebhook(t, database, queries.Webhook{Name: "odd", Type: "carrier-pigeon", Enabled: true, URL: "http://127.0.0.1:9/hook"})
	if err := svc.SendTest(context.Background(), id); err == nil {
		t.Error("SendTest for an unknown webhook type = nil, want error")
	}
}

func TestResolveUserPrefersDisplayNameThenEmail(t *testing.T) {
	svc, database, _ := ntfNewService(t)
	ntfAddUser(t, database, "user-named", "named@example.com", "Ada Lovelace")
	ntfAddUser(t, database, "user-plain", "plain@example.com", "")

	cases := map[string]string{
		"user-named":   "Ada Lovelace",
		"user-plain":   "plain@example.com",
		"user-unknown": "user-unknown",
		"":             "",
	}
	for id, want := range cases {
		if got := svc.resolveUser(context.Background(), id); got != want {
			t.Errorf("resolveUser(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestBuildMessageOmitsEmptyFields(t *testing.T) {
	full := buildMessage("login.failure", "Ada Lovelace", "203.0.113.9", "wrong password")
	for _, want := range []string{"Event: login.failure", "User: Ada Lovelace", "IP: 203.0.113.9", "Detail: wrong password"} {
		if !strings.Contains(full, want) {
			t.Errorf("message %q missing %q", full, want)
		}
	}

	sparse := buildMessage("client.created", "", "", "")
	if sparse != "Event: client.created" {
		t.Fatalf("sparse message = %q, want only the event line", sparse)
	}
	for _, unwanted := range []string{"User:", "IP:", "Detail:"} {
		if strings.Contains(sparse, unwanted) {
			t.Errorf("sparse message %q includes an empty %s field", sparse, unwanted)
		}
	}
}

// Operators triage by colour, so a failure must never render as a success.
func TestEventSeverityColours(t *testing.T) {
	const (
		red    = 0xED4245
		yellow = 0xFEE75C
		green  = 0x57F287
	)
	discord := map[string]int{
		"login.failure":    red,
		"totp.invalid":     red,
		"password.failed":  red,
		"session.revoked":  yellow,
		"user.disabled":    yellow,
		"recovery.code":    yellow,
		"client.created":   green,
		"user.created":     green,
		"passkey.register": green,
	}
	for event, want := range discord {
		if got := colorForEvent(event); got != want {
			t.Errorf("colorForEvent(%q) = %#x, want %#x", event, got, want)
		}
	}

	slack := map[string]string{
		"login.failure":   "danger",
		"totp.invalid":    "danger",
		"password.failed": "danger",
		"session.revoked": "warning",
		"user.disabled":   "warning",
		"client.created":  "good",
	}
	for event, want := range slack {
		if got := slackColor(event); got != want {
			t.Errorf("slackColor(%q) = %q, want %q", event, got, want)
		}
	}
}
