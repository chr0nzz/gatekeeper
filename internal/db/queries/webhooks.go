package queries

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Webhook represents a configured notification channel.
type Webhook struct {
	ID        string
	Name      string
	Type      string
	Enabled   bool
	URL       string
	Token     string
	ChatID    string
	Username  string
	Password  string
	Topic     string
	Events    string
	CreatedAt int64
}

// Notification is a record of a dispatched webhook call.
type Notification struct {
	ID          string `json:"id"`
	WebhookID   string `json:"webhook_id"`
	WebhookName string `json:"webhook_name"`
	Event       string `json:"event"`
	UserID      string `json:"user_id"`
	IP          string `json:"ip"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	Error       string `json:"error"`
	CreatedAt   int64  `json:"created_at"`
}

// WebhookStore manages webhook and notification records.
type WebhookStore struct {
	db *sql.DB
}

// NewWebhookStore creates a WebhookStore.
func NewWebhookStore(db *sql.DB) *WebhookStore {
	return &WebhookStore{db: db}
}

// ListWebhooks returns all webhooks ordered by created_at.
func (s *WebhookStore) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,type,enabled,url,token,chat_id,username,password,topic,events,created_at FROM webhooks ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var w Webhook
		var enabled int
		rows.Scan(&w.ID, &w.Name, &w.Type, &enabled, &w.URL, &w.Token, &w.ChatID, &w.Username, &w.Password, &w.Topic, &w.Events, &w.CreatedAt)
		w.Enabled = enabled == 1
		out = append(out, w)
	}
	return out, nil
}

// GetWebhook returns a single webhook by ID.
func (s *WebhookStore) GetWebhook(ctx context.Context, id string) (*Webhook, error) {
	var w Webhook
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT id,name,type,enabled,url,token,chat_id,username,password,topic,events,created_at FROM webhooks WHERE id=?`, id).
		Scan(&w.ID, &w.Name, &w.Type, &enabled, &w.URL, &w.Token, &w.ChatID, &w.Username, &w.Password, &w.Topic, &w.Events, &w.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	w.Enabled = enabled == 1
	return &w, err
}

// CreateWebhook inserts a new webhook.
func (s *WebhookStore) CreateWebhook(ctx context.Context, w Webhook) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webhooks (id,name,type,enabled,url,token,chat_id,username,password,topic,events,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		uuid.New().String(), w.Name, w.Type, 1, w.URL, w.Token, w.ChatID, w.Username, w.Password, w.Topic, w.Events, time.Now().Unix(),
	)
	return err
}

// UpdateWebhook updates a webhook by ID.
func (s *WebhookStore) UpdateWebhook(ctx context.Context, w Webhook) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webhooks SET name=?,type=?,url=?,token=?,chat_id=?,username=?,password=?,topic=?,events=? WHERE id=?`,
		w.Name, w.Type, w.URL, w.Token, w.ChatID, w.Username, w.Password, w.Topic, w.Events, w.ID,
	)
	return err
}

// SetEnabled sets the enabled flag for a webhook.
func (s *WebhookStore) SetEnabled(ctx context.Context, id string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE webhooks SET enabled=? WHERE id=?`, v, id)
	return err
}

// DeleteWebhook removes a webhook by ID.
func (s *WebhookStore) DeleteWebhook(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id=?`, id)
	return err
}

// ListEnabledForEvent returns enabled webhooks that subscribe to the given event.
func (s *WebhookStore) ListEnabledForEvent(ctx context.Context, event string) ([]Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,type,url,token,chat_id,username,password,topic,events FROM webhooks WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var w Webhook
		rows.Scan(&w.ID, &w.Name, &w.Type, &w.URL, &w.Token, &w.ChatID, &w.Username, &w.Password, &w.Topic, &w.Events)
		w.Enabled = true
		if w.Events == "all" || eventMatches(w.Events, event) {
			out = append(out, w)
		}
	}
	return out, nil
}

func eventMatches(events, event string) bool {
	for _, e := range strings.Split(events, ",") {
		if strings.TrimSpace(e) == event {
			return true
		}
	}
	return false
}

// LogNotification writes a notification delivery result.
func (s *WebhookStore) LogNotification(ctx context.Context, n Notification) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO notifications (id,webhook_id,webhook_name,event,user_id,ip,status,detail,error,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		uuid.New().String(), n.WebhookID, n.WebhookName, n.Event, n.UserID, n.IP, n.Status, n.Detail, n.Error, time.Now().Unix(),
	)
	return err
}

// ListNotifications returns recent notifications, newest first.
func (s *WebhookStore) ListNotifications(ctx context.Context, limit int) ([]Notification, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,webhook_id,webhook_name,event,user_id,ip,status,detail,error,created_at FROM notifications ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		rows.Scan(&n.ID, &n.WebhookID, &n.WebhookName, &n.Event, &n.UserID, &n.IP, &n.Status, &n.Detail, &n.Error, &n.CreatedAt)
		out = append(out, n)
	}
	return out, nil
}

// UnreadCount returns the count of notifications created after the given timestamp.
func (s *WebhookStore) UnreadCount(ctx context.Context, since int64) int {
	var count int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notifications WHERE created_at > ?`, since).Scan(&count)
	return count
}
