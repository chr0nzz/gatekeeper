package queries

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// QRToken represents a pending QR login session.
type QRToken struct {
	ID          string
	UserID      string
	Status      string
	OIDCRequest string
	RedirectURI string
	Binding     string
	ExpiresAt   int64
}

// QRTokenStore manages QR login tokens.
type QRTokenStore struct {
	db *sql.DB
}

// NewQRTokenStore creates a QRTokenStore.
func NewQRTokenStore(db *sql.DB) *QRTokenStore {
	return &QRTokenStore{db: db}
}

// Create inserts a pending QR token bound to the browser that requested it.
func (q *QRTokenStore) Create(ctx context.Context, oidcRequest, redirectURI, binding string) (string, error) {
	id := uuid.New().String()
	now := time.Now()
	_, err := q.db.ExecContext(ctx,
		`INSERT INTO qr_login_tokens (id, status, oidc_request, redirect_uri, binding, created_at, expires_at)
		 VALUES (?, 'pending', ?, ?, ?, ?, ?)`,
		id, oidcRequest, redirectURI, binding, now.Unix(), now.Add(5*time.Minute).Unix(),
	)
	return id, err
}

// Consume atomically claims an approved token exactly once.
func (q *QRTokenStore) Consume(ctx context.Context, id, binding string) (*QRToken, error) {
	tok, err := q.Get(ctx, id)
	if err != nil || tok == nil {
		return nil, err
	}
	if tok.Status != "approved" || tok.Binding == "" || tok.Binding != binding {
		return nil, nil
	}
	res, err := q.db.ExecContext(ctx,
		`UPDATE qr_login_tokens SET status='used' WHERE id=? AND status='approved' AND binding=?`, id, binding,
	)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return nil, nil
	}
	return tok, nil
}

// Get retrieves a QR token by ID.
func (q *QRTokenStore) Get(ctx context.Context, id string) (*QRToken, error) {
	var t QRToken
	err := q.db.QueryRowContext(ctx,
		`SELECT id, user_id, status, oidc_request, redirect_uri, binding, expires_at FROM qr_login_tokens WHERE id=?`, id,
	).Scan(&t.ID, &t.UserID, &t.Status, &t.OIDCRequest, &t.RedirectURI, &t.Binding, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &t, err
}

// Approve marks a token as approved by the given user.
func (q *QRTokenStore) Approve(ctx context.Context, id, userID string) error {
	_, err := q.db.ExecContext(ctx,
		`UPDATE qr_login_tokens SET status='approved', user_id=? WHERE id=? AND status='pending'`, userID, id,
	)
	return err
}

// Cleanup removes expired tokens.
func (q *QRTokenStore) Cleanup(ctx context.Context) {
	q.db.ExecContext(ctx, `DELETE FROM qr_login_tokens WHERE expires_at<? OR status='used'`, time.Now().Unix())
}
