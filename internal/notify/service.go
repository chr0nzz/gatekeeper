package notify

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/chr0nzz/gatekeeper/internal/db/queries"
	"github.com/chr0nzz/gatekeeper/internal/mailer"
)

// Service dispatches notifications to configured webhooks.
type Service struct {
	db       *sql.DB
	webhooks *queries.WebhookStore
	mailer   *mailer.Mailer
}

// New creates a Service.
func New(db *sql.DB, webhooks *queries.WebhookStore, m *mailer.Mailer) *Service {
	return &Service{db: db, webhooks: webhooks, mailer: m}
}

// Dispatch sends a notification for the given audit event to all matching webhooks.
func (s *Service) Dispatch(event, userID, actorID, ip, detail string) {
	ctx := context.Background()
	whs, err := s.webhooks.ListEnabledForEvent(ctx, event)
	if err != nil {
		return
	}
	for _, wh := range whs {
		wh := wh
		go s.send(ctx, wh, event, userID, ip, detail)
	}
}

func (s *Service) resolveUser(ctx context.Context, userID string) string {
	if userID == "" {
		return ""
	}
	var name string
	s.db.QueryRowContext(ctx, `SELECT COALESCE(NULLIF(display_name,''), email) FROM users WHERE id=?`, userID).Scan(&name)
	if name == "" {
		return userID
	}
	return name
}

func (s *Service) send(ctx context.Context, wh queries.Webhook, event, userID, ip, detail string) {
	userDisplay := s.resolveUser(ctx, userID)
	msg := buildMessage(event, userDisplay, ip, detail)
	var sendErr error
	switch wh.Type {
	case "discord":
		sendErr = sendDiscord(wh.URL, event, msg)
	case "slack":
		sendErr = sendSlack(wh.URL, event, msg)
	case "telegram":
		sendErr = sendTelegram(wh.Token, wh.ChatID, msg)
	case "ntfy":
		sendErr = sendNtfy("https://ntfy.sh", wh.Topic, "", "", event, msg)
	case "ntfy_self":
		sendErr = sendNtfy(wh.URL, wh.Topic, wh.Username, wh.Password, event, msg)
	case "generic":
		sendErr = sendGeneric(wh.URL, event, userID, ip, detail)
	case "email":
		sendErr = s.sendEmail(wh.URL, event, msg)
	default:
		sendErr = fmt.Errorf("unknown webhook type: %s", wh.Type)
	}

	n := queries.Notification{
		WebhookID:   wh.ID,
		WebhookName: wh.Name,
		Event:       event,
		UserID:      userID,
		IP:          ip,
		Detail:      detail,
	}
	if sendErr != nil {
		n.Status = "failed"
		n.Error = sendErr.Error()
	} else {
		n.Status = "sent"
	}
	s.webhooks.LogNotification(ctx, n)
}

// SendTest dispatches a test notification to a single webhook by ID.
func (s *Service) SendTest(ctx context.Context, webhookID string) error {
	wh, err := s.webhooks.GetWebhook(ctx, webhookID)
	if err != nil || wh == nil {
		return fmt.Errorf("webhook not found")
	}
	msg := "Test notification from GateKeeper."
	switch wh.Type {
	case "discord":
		return sendDiscord(wh.URL, "test.ping", msg)
	case "slack":
		return sendSlack(wh.URL, "test.ping", msg)
	case "telegram":
		return sendTelegram(wh.Token, wh.ChatID, msg)
	case "ntfy":
		return sendNtfy("https://ntfy.sh", wh.Topic, "", "", "test.ping", msg)
	case "ntfy_self":
		return sendNtfy(wh.URL, wh.Topic, wh.Username, wh.Password, "test.ping", msg)
	case "generic":
		return sendGeneric(wh.URL, "test.ping", "", "", "GateKeeper test notification")
	case "email":
		return s.sendEmail(wh.URL, "test.ping", msg)
	}
	return fmt.Errorf("unknown type")
}

func buildMessage(event, userID, ip, detail string) string {
	msg := fmt.Sprintf("Event: %s", event)
	if userID != "" {
		msg += fmt.Sprintf("\nUser: %s", userID)
	}
	if ip != "" {
		msg += fmt.Sprintf("\nIP: %s", ip)
	}
	if detail != "" {
		msg += fmt.Sprintf("\nDetail: %s", detail)
	}
	return msg
}

func (s *Service) sendEmail(to, event, msg string) error {
	if s.mailer == nil {
		return fmt.Errorf("SMTP not configured")
	}
	return s.mailer.SendRaw(to, "GateKeeper alert: "+event, msg)
}
