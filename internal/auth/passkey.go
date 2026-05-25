package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// PasskeyStore manages WebAuthn credential storage.
type PasskeyStore struct {
	db      *sql.DB
	webauth *webauthn.WebAuthn
}

// NewPasskeyStore creates a PasskeyStore.
func NewPasskeyStore(db *sql.DB, rpID, rpDisplayName, rpOrigin string) (*PasskeyStore, error) {
	wauth, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}
	return &PasskeyStore{db: db, webauth: wauth}, nil
}

// WebAuthn exposes the underlying webauthn.WebAuthn for handler use.
func (p *PasskeyStore) WebAuthn() *webauthn.WebAuthn {
	return p.webauth
}

// WAUser implements webauthn.User for a GateKeeper user.
type WAUser struct {
	ID          string
	Email       string
	Credentials []webauthn.Credential
}

func (u *WAUser) WebAuthnID() []byte        { return []byte(u.ID) }
func (u *WAUser) WebAuthnName() string      { return u.Email }
func (u *WAUser) WebAuthnDisplayName() string { return u.Email }
func (u *WAUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// LoadUser retrieves a WAUser with their credentials.
func (p *PasskeyStore) LoadUser(ctx context.Context, userID, email string) (*WAUser, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT credential_data FROM passkeys WHERE user_id=?`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	user := &WAUser{ID: userID, Email: email}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(raw), &cred); err != nil {
			return nil, err
		}
		user.Credentials = append(user.Credentials, cred)
	}
	return user, nil
}

// SaveSession stores a WebAuthn session.
func (p *PasskeyStore) SaveSession(ctx context.Context, sessionID string, userID *string, data *webauthn.SessionData) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	now := time.Now()
	_, err = p.db.ExecContext(ctx,
		`INSERT INTO webauthn_sessions (id, user_id, data, created_at, expires_at) VALUES (?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET data=excluded.data`,
		sessionID, userIDOrNull(userID), string(raw), now.Unix(), now.Add(5*time.Minute).Unix(),
	)
	return err
}

// GetSession retrieves and deletes a WebAuthn session.
func (p *PasskeyStore) GetSession(ctx context.Context, sessionID string) (*webauthn.SessionData, error) {
	var raw string
	err := p.db.QueryRowContext(ctx,
		`SELECT data FROM webauthn_sessions WHERE id=? AND expires_at>?`,
		sessionID, time.Now().Unix(),
	).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, errors.New("session not found or expired")
	}
	if err != nil {
		return nil, err
	}
	p.db.ExecContext(ctx, `DELETE FROM webauthn_sessions WHERE id=?`, sessionID)
	var sd webauthn.SessionData
	return &sd, json.Unmarshal([]byte(raw), &sd)
}

// RegisterCredential stores a newly registered credential.
func (p *PasskeyStore) RegisterCredential(ctx context.Context, userID, name string, cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	credID := fmt.Sprintf("%x", cred.ID)
	_, err = p.db.ExecContext(ctx,
		`INSERT INTO passkeys (id, user_id, name, credential_id, credential_data, created_at) VALUES (?,?,?,?,?,?)`,
		uuid.New().String(), userID, name, credID, string(raw), time.Now().Unix(),
	)
	return err
}

// FindCredentialByID finds a user by credential ID for authentication.
func (p *PasskeyStore) FindCredentialByID(ctx context.Context, credID []byte) (string, string, *webauthn.Credential, error) {
	credHex := fmt.Sprintf("%x", credID)
	var userID, rawCred string
	err := p.db.QueryRowContext(ctx,
		`SELECT user_id, credential_data FROM passkeys WHERE credential_id=?`,
		credHex,
	).Scan(&userID, &rawCred)
	if err == sql.ErrNoRows {
		return "", "", nil, errors.New("credential not found")
	}
	if err != nil {
		return "", "", nil, err
	}
	var email string
	if strings.HasPrefix(userID, "admin:") {
		p.db.QueryRowContext(ctx, `SELECT email FROM admin_users WHERE id=?`,
			strings.TrimPrefix(userID, "admin:")).Scan(&email)
	} else {
		p.db.QueryRowContext(ctx, `SELECT email FROM users WHERE id=?`, userID).Scan(&email)
	}
	var cred webauthn.Credential
	if err := json.Unmarshal([]byte(rawCred), &cred); err != nil {
		return "", "", nil, err
	}
	return userID, email, &cred, nil
}

// UpdateCredential persists a modified credential (e.g., updated sign count).
func (p *PasskeyStore) UpdateCredential(ctx context.Context, userID string, cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	credHex := fmt.Sprintf("%x", cred.ID)
	_, err = p.db.ExecContext(ctx,
		`UPDATE passkeys SET credential_data=?, last_used=? WHERE user_id=? AND credential_id=?`,
		string(raw), time.Now().Unix(), userID, credHex,
	)
	return err
}

// DeleteCredential removes a passkey for a user.
func (p *PasskeyStore) DeleteCredential(ctx context.Context, userID, passkeyID string) error {
	_, err := p.db.ExecContext(ctx,
		`DELETE FROM passkeys WHERE id=? AND user_id=?`,
		passkeyID, userID,
	)
	return err
}

// ListCredentials lists all passkeys for a user.
func (p *PasskeyStore) ListCredentials(ctx context.Context, userID string) ([]PasskeyInfo, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, name, created_at, last_used FROM passkeys WHERE user_id=?`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PasskeyInfo
	for rows.Next() {
		var pk PasskeyInfo
		var lastUsed sql.NullInt64
		if err := rows.Scan(&pk.ID, &pk.Name, &pk.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			pk.LastUsed = time.Unix(lastUsed.Int64, 0)
		}
		out = append(out, pk)
	}
	return out, nil
}

// PasskeyInfo is a display record for a stored passkey.
type PasskeyInfo struct {
	ID        string
	Name      string
	CreatedAt int64
	LastUsed  time.Time
}

func userIDOrNull(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}
