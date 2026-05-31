package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	keyRotationDays = 30
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 24 * time.Hour * 30
)

// Storage implements op.Storage for GateKeeper.
type Storage struct {
	db     *sql.DB
	issuer string
}

// NewStorage creates an OIDC Storage.
func NewStorage(db *sql.DB, issuer string) *Storage {
	return &Storage{db: db, issuer: issuer}
}

// EnsureSigningKey creates a signing key if none exists.
func (s *Storage) EnsureSigningKey(ctx context.Context) error {
	var count int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_signing_keys WHERE rotated_at IS NULL`).Scan(&count)
	if count > 0 {
		return nil
	}
	return s.rotateKey(ctx)
}

func (s *Storage) rotateKey(ctx context.Context) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO oidc_signing_keys (id, private_key, algorithm, created_at) VALUES (?,?,?,?)`,
		uuid.New().String(), string(priv), "RS256", time.Now().Unix(),
	)
	return err
}

func (s *Storage) loadCurrentKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	var id, privPEM string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, private_key FROM oidc_signing_keys WHERE rotated_at IS NULL ORDER BY created_at DESC LIMIT 1`,
	).Scan(&id, &privPEM)
	if err == sql.ErrNoRows {
		return nil, "", errors.New("no signing key")
	}
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode([]byte(privPEM))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key, id, err
}

// AuthRequestDone marks an auth request as completed by a user login.
func (s *Storage) AuthRequestDone(ctx context.Context, id, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE oidc_auth_requests SET done=1, user_id=? WHERE id=?`,
		userID, id,
	)
	return err
}

// -- AuthStorage implementation --

// CreateAuthRequest stores a new authorization request.
func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	id := uuid.New().String()
	scopes, _ := json.Marshal(req.Scopes)
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_auth_requests
		 (id, client_id, user_id, redirect_uri, state, nonce, scopes, code_challenge, code_challenge_method, response_type, created_at, expires_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, req.ClientID, nullableStr(userID), req.RedirectURI, req.State, req.Nonce,
		string(scopes), req.CodeChallenge, req.CodeChallengeMethod,
		string(req.ResponseType), now.Unix(), now.Add(10*time.Minute).Unix(),
	)
	if err != nil {
		return nil, err
	}
	return s.AuthRequestByID(ctx, id)
}

// AuthRequestByID retrieves an authorization request by ID.
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	var r authRequest
	var scopesRaw string
	var userID sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, user_id, redirect_uri, state, nonce, scopes,
		        code_challenge, code_challenge_method, response_type, done
		 FROM oidc_auth_requests WHERE id=? AND expires_at>?`,
		id, time.Now().Unix(),
	).Scan(&r.id, &r.clientID, &userID, &r.redirectURI, &r.state, &r.nonce,
		&scopesRaw, &r.codeChallenge, &r.codeChallengeMethod, &r.responseType, &r.done)
	if err == sql.ErrNoRows {
		return nil, errors.New("auth request not found or expired")
	}
	if err != nil {
		return nil, err
	}
	if userID.Valid {
		r.userID = userID.String
	}
	json.Unmarshal([]byte(scopesRaw), &r.scopes)
	return &r, nil
}

// AuthRequestByCode retrieves an authorization request by its issued code.
// SaveAuthCode overwrites the request ID with the code, so lookup is identical.
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	return s.AuthRequestByID(ctx, code)
}

// SaveAuthCode stores the mapping from auth request ID to authorization code.
// We replace the request ID with the code so AuthRequestByCode can look it up directly.
func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE oidc_auth_requests SET id=? WHERE id=?`,
		code, id,
	)
	return err
}

// DeleteAuthRequest removes an auth request after code exchange.
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_auth_requests WHERE id=?`, id)
	return err
}

// CreateAccessToken issues an access token.
func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expires := now.Add(accessTokenTTL)
	id := uuid.New().String()

	var clientID, userID, authReqID string
	var scopes []byte
	switch r := req.(type) {
	case *authRequest:
		clientID = r.clientID
		userID = r.userID
		authReqID = r.id
		scopes, _ = json.Marshal(r.scopes)
	case *credentialsRequest:
		clientID = r.clientID
		authReqID = uuid.New().String()
		scopes, _ = json.Marshal(r.scopes)
	default:
		return "", time.Time{}, errors.New("invalid request type")
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO oidc_tokens (id, auth_request_id, client_id, user_id, access_token, scopes, created_at, access_expires)
		 VALUES (?,?,?,?,?,?,?,?)`,
		id, authReqID, clientID, nullableStr(userID), token, string(scopes), now.Unix(), expires.Unix(),
	)
	return token, expires, err
}

// CreateAccessAndRefreshTokens issues both an access and refresh token.
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	access, expires, err := s.CreateAccessToken(ctx, req)
	if err != nil {
		return "", "", time.Time{}, err
	}
	refresh, err := randomToken(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	now := time.Now()
	s.db.ExecContext(ctx,
		`UPDATE oidc_tokens SET refresh_token=?, refresh_expires=? WHERE access_token=?`,
		refresh, now.Add(refreshTokenTTL).Unix(), access,
	)
	return access, refresh, expires, nil
}

// TokenRequestByRefreshToken retrieves a token request from a refresh token.
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	var r authRequest
	var scopesRaw string
	now := time.Now()
	err := s.db.QueryRowContext(ctx,
		`SELECT auth_request_id, client_id, user_id, scopes FROM oidc_tokens
		 WHERE refresh_token=? AND refresh_expires>?`,
		refreshToken, now.Unix(),
	).Scan(&r.id, &r.clientID, &r.userID, &scopesRaw)
	if err == sql.ErrNoRows {
		return nil, errors.New("invalid refresh token")
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(scopesRaw), &r.scopes)
	r.done = true
	return &r, nil
}

// TerminateSession revokes all tokens for a user+client pair.
func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM oidc_tokens WHERE user_id=? AND client_id=?`,
		userID, clientID,
	)
	return err
}

// RevokeToken revokes an access or refresh token.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrID string, userID string, clientID string) *oidc.Error {
	s.db.ExecContext(ctx,
		`DELETE FROM oidc_tokens WHERE (access_token=? OR refresh_token=? OR id=?) AND client_id=?`,
		tokenOrID, tokenOrID, tokenOrID, clientID,
	)
	return nil
}

// GetRefreshTokenInfo retrieves refresh token metadata.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	var userID, tokenID string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, id FROM oidc_tokens WHERE refresh_token=? AND client_id=?`,
		token, clientID,
	).Scan(&userID, &tokenID)
	return userID, tokenID, err
}

// SigningKey returns the current active signing key.
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	key, id, err := s.loadCurrentKey(ctx)
	if err != nil {
		return nil, err
	}
	return &signingKey{id: id, key: key}, nil
}

// SignatureAlgorithms returns the supported signing algorithms.
func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet returns all public keys for token verification.
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, private_key FROM oidc_signing_keys ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []op.Key
	for rows.Next() {
		var id, privPEM string
		if err := rows.Scan(&id, &privPEM); err != nil {
			continue
		}
		block, _ := pem.Decode([]byte(privPEM))
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		keys = append(keys, &signingKey{id: id, key: k})
	}
	return keys, nil
}

// -- OPStorage implementation --

// GetClientByClientID returns an OIDC client.
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	var c OIDCClient
	err := s.db.QueryRowContext(ctx,
		`SELECT client_id, client_secret, redirect_uris, name, credentials_scopes FROM oidc_clients WHERE client_id=?`,
		clientID,
	).Scan(&c.clientID, &c.secret, &c.redirectURIsRaw, &c.name, &c.credentialsScopes)
	if err == sql.ErrNoRows {
		return nil, errors.New("client not found")
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ClientCredentials validates client credentials for the client_credentials grant.
func (s *Storage) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error) {
	var c OIDCClient
	err := s.db.QueryRowContext(ctx,
		`SELECT client_id, client_secret, redirect_uris, name, credentials_scopes FROM oidc_clients WHERE client_id=?`,
		clientID,
	).Scan(&c.clientID, &c.secret, &c.redirectURIsRaw, &c.name, &c.credentialsScopes)
	if err == sql.ErrNoRows {
		return nil, errors.New("client not found")
	}
	if err != nil {
		return nil, err
	}
	if c.secret != clientSecret {
		return nil, errors.New("invalid client secret")
	}
	if c.credentialsScopes == "" {
		return nil, errors.New("client credentials not enabled for this client")
	}
	return &c, nil
}

// ClientCredentialsTokenRequest builds a token request for the client_credentials grant.
func (s *Storage) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	var credScopes string
	s.db.QueryRowContext(ctx, `SELECT credentials_scopes FROM oidc_clients WHERE client_id=?`, clientID).Scan(&credScopes)
	allowed := strings.Fields(credScopes)
	allowedSet := make(map[string]bool, len(allowed))
	for _, sc := range allowed {
		allowedSet[sc] = true
	}
	var granted []string
	for _, sc := range scopes {
		if allowedSet[sc] {
			granted = append(granted, sc)
		}
	}
	if len(scopes) == 0 {
		granted = allowed
	}
	return &credentialsRequest{clientID: clientID, scopes: granted}, nil
}

// AuthorizeClientIDSecret validates client credentials.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	var stored string
	err := s.db.QueryRowContext(ctx,
		`SELECT client_secret FROM oidc_clients WHERE client_id=?`,
		clientID,
	).Scan(&stored)
	if err == sql.ErrNoRows {
		return errors.New("client not found")
	}
	if err != nil {
		return err
	}
	if stored != clientSecret {
		return errors.New("invalid client secret")
	}
	return nil
}

// SetUserinfoFromScopes is deprecated; no-op.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

// SetUserinfoFromToken populates userinfo from an access token.
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT email FROM users WHERE id=?`, subject).Scan(&email)
	if err != nil {
		return err
	}
	userinfo.Subject = subject
	userinfo.UserInfoEmail = oidc.UserInfoEmail{Email: email, EmailVerified: oidc.Bool(true)}
	userinfo.UserInfoProfile = oidc.UserInfoProfile{PreferredUsername: email}
	userinfo.Claims = s.userGroupClaims(ctx, subject)
	return nil
}

// SetIntrospectionFromToken implements token introspection.
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	var email string
	s.db.QueryRowContext(ctx, `SELECT email FROM users WHERE id=?`, subject).Scan(&email)
	userinfo.SetUserInfo(&oidc.UserInfo{
		Subject:       subject,
		UserInfoEmail: oidc.UserInfoEmail{Email: email},
	})
	return nil
}

// GetPrivateClaimsFromScopes adds group membership and per-client custom claims.
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT gr.name FROM groups gr
		 INNER JOIN group_members gm ON gm.group_id = gr.id
		 WHERE gm.user_id=?
		 ORDER BY gr.name`,
		userID,
	)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var groups []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		groups = append(groups, name)
	}
	if len(groups) == 0 {
		groups = []string{}
	}

	claims := map[string]any{"groups": groups}

	crows, err := s.db.QueryContext(ctx,
		`SELECT claim_key, value_source FROM client_claims WHERE client_id=?`,
		clientID,
	)
	if err != nil {
		return claims, nil
	}
	defer crows.Close()

	var needUser bool
	type pending struct{ key, source string }
	var pendings []pending
	for crows.Next() {
		var key, source string
		crows.Scan(&key, &source)
		pendings = append(pendings, pending{key, source})
		if source == "user.email" || source == "user.display_name" {
			needUser = true
		}
	}

	var userEmail, userDisplayName string
	if needUser && userID != "" {
		s.db.QueryRowContext(ctx, `SELECT COALESCE(email,''), COALESCE(display_name,'') FROM users WHERE id=?`, userID).
			Scan(&userEmail, &userDisplayName)
	}

	for _, p := range pendings {
		switch p.source {
		case "user.id":
			claims[p.key] = userID
		case "user.email":
			claims[p.key] = userEmail
		case "user.display_name":
			claims[p.key] = userDisplayName
		case "groups":
			claims[p.key] = groups
		default:
			if strings.HasPrefix(p.source, "literal:") {
				claims[p.key] = p.source[len("literal:"):]
			}
		}
	}

	return claims, nil
}

// GetKeyByIDAndClientID retrieves a signing key by ID.
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	var privPEM string
	err := s.db.QueryRowContext(ctx,
		`SELECT private_key FROM oidc_signing_keys WHERE id=?`,
		keyID,
	).Scan(&privPEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(privPEM))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKey{Key: key, KeyID: keyID, Algorithm: "RS256", Use: "sig"}, nil
}

// ValidateJWTProfileScopes validates scopes for JWT profile.
func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// Health returns nil if the storage is healthy.
func (s *Storage) Health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// -- Client management --

// ListClients lists all OIDC clients.
func (s *Storage) ListClients(ctx context.Context) ([]ClientRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT client_id, name, icon_url, (icon_data IS NOT NULL AND LENGTH(icon_data)>0), redirect_uris, credentials_scopes, created_at FROM oidc_clients ORDER BY name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientRecord
	for rows.Next() {
		var c ClientRecord
		if err := rows.Scan(&c.ClientID, &c.Name, &c.IconURL, &c.HasIcon, &c.RedirectURIsRaw, &c.CredentialsScopes, &c.CreatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(c.RedirectURIsRaw), &c.RedirectURIs)
		out = append(out, c)
	}
	return out, nil
}

// CreateClient registers a new OIDC client.
func (s *Storage) CreateClient(ctx context.Context, clientID, secret, name, iconURL, credentialsScopes string, redirectURIs []string) error {
	raw, _ := json.Marshal(redirectURIs)
	iconData, iconMime := fetchIcon(iconURL)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_clients (id, client_id, client_secret, redirect_uris, name, icon_url, icon_data, icon_mime, credentials_scopes, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		uuid.New().String(), clientID, secret, string(raw), name, iconURL, iconData, iconMime, credentialsScopes, time.Now().Unix(),
	)
	return err
}

// ServeIcon writes the cached icon for a client to the response, or 404 if none.
func (s *Storage) ServeIcon(w http.ResponseWriter, r *http.Request, clientID string) {
	var data []byte
	var mime string
	s.db.QueryRowContext(r.Context(), `SELECT icon_data, icon_mime FROM oidc_clients WHERE client_id=?`, clientID).Scan(&data, &mime)
	if len(data) == 0 {
		http.NotFound(w, r)
		return
	}
	if mime == "" {
		mime = "image/png"
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// HasIcon returns true if a client has a cached icon.
func (s *Storage) HasIcon(ctx context.Context, clientID string) bool {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_clients WHERE client_id=? AND icon_data IS NOT NULL AND LENGTH(icon_data)>0`, clientID).Scan(&n)
	return n > 0
}

func fetchIcon(iconURL string) ([]byte, string) {
	if iconURL == "" {
		return nil, ""
	}
	resp, err := http.Get(iconURL) //nolint
	if err != nil || resp.StatusCode != 200 {
		return nil, ""
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil || len(data) == 0 {
		return nil, ""
	}
	mime := resp.Header.Get("Content-Type")
	if idx := strings.Index(mime, ";"); idx > 0 {
		mime = mime[:idx]
	}
	if mime == "" {
		mime = "image/png"
	}
	return data, mime
}

// DeleteClient removes an OIDC client.
func (s *Storage) DeleteClient(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_clients WHERE client_id=?`, clientID)
	return err
}

// UpdateClient updates a client's name, icon, redirect URIs, credentials scopes, and optionally its secret.
func (s *Storage) UpdateClient(ctx context.Context, clientID, name, iconURL, newSecret, credentialsScopes string, redirectURIs []string) error {
	raw, _ := json.Marshal(redirectURIs)
	iconData, iconMime := fetchIcon(iconURL)
	if newSecret != "" {
		_, err := s.db.ExecContext(ctx,
			`UPDATE oidc_clients SET name=?, icon_url=?, icon_data=?, icon_mime=?, redirect_uris=?, credentials_scopes=?, client_secret=? WHERE client_id=?`,
			name, iconURL, iconData, iconMime, string(raw), credentialsScopes, newSecret, clientID,
		)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE oidc_clients SET name=?, icon_url=?, icon_data=?, icon_mime=?, redirect_uris=?, credentials_scopes=? WHERE client_id=?`,
		name, iconURL, iconData, iconMime, string(raw), credentialsScopes, clientID,
	)
	return err
}

// -- OIDCClient implements op.Client --

// OIDCClient is a registered OIDC application.
type OIDCClient struct {
	clientID          string
	secret            string
	redirectURIsRaw   string
	name              string
	credentialsScopes string
}

func (c *OIDCClient) GetID() string { return c.clientID }
func (c *OIDCClient) RedirectURIs() []string {
	var uris []string
	json.Unmarshal([]byte(c.redirectURIsRaw), &uris)
	return uris
}
func (c *OIDCClient) PostLogoutRedirectURIs() []string    { return nil }
func (c *OIDCClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c *OIDCClient) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (c *OIDCClient) ResponseTypes() []oidc.ResponseType  { return []oidc.ResponseType{oidc.ResponseTypeCode} }
func (c *OIDCClient) GrantTypes() []oidc.GrantType {
	grants := []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
	if c.credentialsScopes != "" {
		grants = append(grants, oidc.GrantTypeClientCredentials)
	}
	return grants
}
func (c *OIDCClient) LoginURL(id string) string            { return "/login?oidc_request=" + id }
func (c *OIDCClient) AccessTokenType() op.AccessTokenType  { return op.AccessTokenTypeBearer }
func (c *OIDCClient) IDTokenLifetime() time.Duration       { return accessTokenTTL }
func (c *OIDCClient) DevMode() bool                        { return false }
func (c *OIDCClient) ClockSkew() time.Duration             { return 0 }
func (c *OIDCClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *OIDCClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *OIDCClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *OIDCClient) IsScopeAllowed(scope string) bool {
	return scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access"
}

// credentialsRequest implements op.TokenRequest for client_credentials grant.
type credentialsRequest struct {
	clientID string
	scopes   []string
}

func (r *credentialsRequest) GetSubject() string    { return r.clientID }
func (r *credentialsRequest) GetAudience() []string { return []string{r.clientID} }
func (r *credentialsRequest) GetScopes() []string   { return r.scopes }

// -- authRequest implements op.AuthRequest and op.RefreshTokenRequest --

type authRequest struct {
	id                  string
	clientID            string
	userID              string
	redirectURI         string
	state               string
	nonce               string
	scopes              []string
	codeChallenge       string
	codeChallengeMethod string
	responseType        string
	done                bool
}

func (r *authRequest) GetID() string    { return r.id }
func (r *authRequest) GetACR() string   { return "" }
func (r *authRequest) GetAMR() []string { return nil }
func (r *authRequest) GetClientID() string { return r.clientID }
func (r *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if r.codeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: r.codeChallenge, Method: oidc.CodeChallengeMethod(r.codeChallengeMethod)}
}
func (r *authRequest) GetNonce() string                    { return r.nonce }
func (r *authRequest) GetRedirectURI() string              { return r.redirectURI }
func (r *authRequest) GetResponseType() oidc.ResponseType  { return oidc.ResponseType(r.responseType) }
func (r *authRequest) GetResponseMode() oidc.ResponseMode  { return "" }
func (r *authRequest) GetScopes() []string                 { return r.scopes }
func (r *authRequest) GetState() string                    { return r.state }
func (r *authRequest) GetSubject() string                  { return r.userID }
func (r *authRequest) Done() bool                          { return r.done }
func (r *authRequest) GetAudience() []string               { return []string{r.clientID} }
func (r *authRequest) GetAuthTime() time.Time              { return time.Now() }
func (r *authRequest) GetClientSecret() string             { return "" }
func (r *authRequest) SetCurrentScopes(scopes []string)    { r.scopes = scopes }
func (r *authRequest) GetCurrentScopes() []string          { return r.scopes }

// -- signingKey implements both op.SigningKey and op.Key --

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

func (k *signingKey) ID() string                               { return k.id }
func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *signingKey) Algorithm() jose.SignatureAlgorithm       { return jose.RS256 }
func (k *signingKey) Use() string                              { return "sig" }
func (k *signingKey) Key() any                                 { return k.key }

// -- ClientRecord for admin display --

// ClientRecord holds OIDC client data for display.
type ClientRecord struct {
	ClientID          string
	Name              string
	IconURL           string
	HasIcon           bool
	RedirectURIsRaw   string
	RedirectURIs      []string
	CredentialsScopes string
	CreatedAt         int64
}

// -- helpers --

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GetUserinfo returns userinfo claims for a user.
func (s *Storage) GetUserinfo(ctx context.Context, userID, clientID string, scopes []string) (*oidc.UserInfo, error) {
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT email FROM users WHERE id=?`, userID).Scan(&email)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	info := &oidc.UserInfo{Subject: userID}
	for _, scope := range scopes {
		switch scope {
		case "email":
			info.UserInfoEmail = oidc.UserInfoEmail{Email: email, EmailVerified: oidc.Bool(true)}
		case "profile":
			info.UserInfoProfile = oidc.UserInfoProfile{PreferredUsername: email}
		}
	}
	info.Claims = s.userGroupClaims(ctx, userID)
	return info, nil
}

func (s *Storage) userGroupClaims(ctx context.Context, userID string) map[string]any {
	rows, err := s.db.QueryContext(ctx,
		`SELECT gr.name FROM groups gr
		 INNER JOIN group_members gm ON gm.group_id = gr.id
		 WHERE gm.user_id=? ORDER BY gr.name`,
		userID,
	)
	groups := []string{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			rows.Scan(&name)
			groups = append(groups, name)
		}
	}
	return map[string]any{"groups": groups}
}
