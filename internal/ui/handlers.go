package ui

import (
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
	"github.com/chr0nzz/gatekeeper/internal/mailer"
	gkmiddleware "github.com/chr0nzz/gatekeeper/internal/middleware"
	oidcstore "github.com/chr0nzz/gatekeeper/internal/oidc"
	"github.com/chr0nzz/gatekeeper/internal/templates"
)


const (
	loginMaxFails  = 20
	loginWindowDur = 15 * time.Minute
)

type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*limEntry
}

type limEntry struct {
	fails   int
	resetAt time.Time
}

func newLoginLimiter() *loginLimiter {
	l := &loginLimiter{entries: make(map[string]*limEntry)}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		for range t.C {
			l.mu.Lock()
			now := time.Now()
			for ip, e := range l.entries {
				if now.After(e.resetAt) {
					delete(l.entries, ip)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.entries[ip]
	if !ok || now.After(e.resetAt) {
		l.entries[ip] = &limEntry{fails: 0, resetAt: now.Add(loginWindowDur)}
		return true
	}
	return e.fails < loginMaxFails
}

func (l *loginLimiter) record(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.entries[ip]
	if !ok || now.After(e.resetAt) {
		l.entries[ip] = &limEntry{fails: 1, resetAt: now.Add(loginWindowDur)}
		return
	}
	e.fails++
}

// Handlers holds all user-facing handler dependencies.
type Handlers struct {
	db             *sql.DB
	users          *queries.UserStore
	sessions       *auth.SessionStore
	otps           *auth.OTPStore
	totp           *auth.TOTPStore
	passkeys       *auth.PasskeyStore
	resetStore     *auth.PasswordResetStore
	settings       *queries.SettingsStore
	trustedDevices *auth.TrustedDeviceStore
	mailer         *mailer.Mailer
	auditLog       *audit.Logger
	renderer       *templates.Renderer
	oidcStorage    *oidcstore.Storage
	policies       *queries.PolicyStore
	invites        *queries.InviteStore
	limiter        *loginLimiter
	baseURL        string
	issuer         string
	secretKey      string
	cookieDomain   string
}

// New creates a user-facing Handlers.
func New(
	db *sql.DB,
	users *queries.UserStore,
	sessions *auth.SessionStore,
	otps *auth.OTPStore,
	totp *auth.TOTPStore,
	passkeys *auth.PasskeyStore,
	resetStore *auth.PasswordResetStore,
	settings *queries.SettingsStore,
	trustedDevices *auth.TrustedDeviceStore,
	m *mailer.Mailer,
	auditLog *audit.Logger,
	renderer *templates.Renderer,
	oidcStorage *oidcstore.Storage,
	baseURL, issuer, secretKey, cookieDomain string,
	policies *queries.PolicyStore,
	invites *queries.InviteStore,
) *Handlers {
	return &Handlers{
		db: db, users: users, sessions: sessions, otps: otps, totp: totp,
		passkeys: passkeys, resetStore: resetStore, settings: settings,
		trustedDevices: trustedDevices, mailer: m,
		auditLog: auditLog, renderer: renderer, oidcStorage: oidcStorage,
		policies: policies, invites: invites, limiter: newLoginLimiter(),
		baseURL: baseURL, issuer: issuer,
		secretKey: secretKey, cookieDomain: cookieDomain,
	}
}

func (h *Handlers) render(w http.ResponseWriter, name string, data interface{}) {
	h.renderer.Render(w, name, data)
}

func (h *Handlers) csrf(r *http.Request) string {
	return gkmiddleware.CSRFToken(r)
}

func (h *Handlers) checkCSRF(r *http.Request) bool {
	token := h.csrf(r)
	return token != "" && r.FormValue("csrf_token") == token
}

func remoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (h *Handlers) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _, err := h.sessions.Get(r)
		if err != nil || data == nil || data.UserID == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Mount registers all user-facing routes.
func (h *Handlers) Mount(r chi.Router) {
	r.Get("/", h.GetHome)
	r.Get("/avatar/{id}", h.GetAvatar)
	r.Get("/login", h.GetLogin)
	r.Post("/login", h.PostLogin)
	r.Get("/login/otp", h.GetOTP)
	r.Post("/login/otp", h.PostOTP)
	r.Get("/login/totp", h.GetTOTP)
	r.Post("/login/totp", h.PostTOTP)
	r.Get("/login/totp/recovery", h.GetTOTPRecovery)
	r.Post("/login/totp/recovery", h.PostTOTPRecovery)
	r.Post("/login/passkey/begin", h.PostPasskeyLoginBegin)
	r.Post("/login/passkey/finish", h.PostPasskeyLoginFinish)
	r.Get("/forgot-password", h.GetForgotPassword)
	r.Post("/forgot-password", h.PostForgotPassword)
	r.Get("/reset-password", h.GetResetPassword)
	r.Post("/reset-password", h.PostResetPassword)
	r.Post("/logout", h.PostLogout)
	r.Get("/register", h.GetRegister)
	r.Post("/register", h.PostRegister)

	r.Group(func(r chi.Router) {
		r.Use(h.requireSession)
		r.Post("/profile/name", h.PostProfileName)
		r.Post("/profile/avatar", h.PostProfileAvatar)
		r.Get("/profile/password", h.GetChangePassword)
		r.Post("/profile/password", h.PostChangePassword)
		r.Get("/profile/totp/enroll", h.GetTOTPEnroll)
		r.Post("/profile/totp/enroll", h.PostTOTPEnroll)
		r.Get("/profile/totp/recovery-codes", h.GetTOTPRecoveryCodes)
		r.Get("/profile/totp/disable", h.GetTOTPDisable)
		r.Post("/profile/totp/disable", h.PostTOTPDisable)
		r.Get("/register/passkey", h.GetPasskeyRegister)
		r.Post("/register/passkey/begin", h.PostPasskeyRegisterBegin)
		r.Post("/register/passkey/finish", h.PostPasskeyRegisterFinish)
		r.Post("/passkey/{id}/delete", h.PostPasskeyDelete)
		r.Post("/session/{id}/revoke", h.PostSessionRevoke)
		r.Post("/sessions/revoke-others", h.PostRevokeOtherSessions)
	})
}

func (h *Handlers) GetHome(w http.ResponseWriter, r *http.Request) {
	data, sessID, err := h.sessions.Get(r)
	if err != nil || data == nil || data.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	user, err := h.users.GetByID(r.Context(), data.UserID)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	passkeys, _ := h.passkeys.ListCredentials(r.Context(), user.ID)
	sessions, _ := h.sessions.ListUserSessions(r.Context(), user.ID, sessID)
	avatarErr := r.URL.Query().Get("avatar_err")
	h.render(w, "home.html", map[string]interface{}{
		"User":        user,
		"Passkeys":    passkeys,
		"Sessions":    sessions,
		"TOTPEnabled": user.TOTPEnabled,
		"AvatarErr":   avatarErr,
		"CSRFToken":   h.csrf(r),
	})
}

func (h *Handlers) GetLogin(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	oidcRequest := r.URL.Query().Get("oidc_request")
	// If already authenticated, complete the OIDC flow or forward directly.
	data, sessID, _ := h.sessions.Get(r)
	if data != nil && data.UserID != "" && !data.PendingOTP && !data.PendingTOTP {
		if oidcRequest != "" {
			data.OIDCRequestID = oidcRequest
			h.sessions.Update(r.Context(), sessID, *data)
			h.completeLogin(w, r, sessID, data)
		} else {
			h.redirect(w, r, sessID, redirectURI)
		}
		return
	}

	tplData := map[string]string{
		"RedirectURI": redirectURI,
		"OIDCRequest": oidcRequest,
		"AppName":     "",
		"FaviconURL":  "",
	}
	if oidcRequest != "" && h.oidcStorage != nil {
		if req, err := h.oidcStorage.AuthRequestByID(r.Context(), oidcRequest); err == nil {
			clientID := req.GetClientID()
			var name string
			var hasIcon bool
			h.db.QueryRowContext(r.Context(),
				`SELECT name, (icon_data IS NOT NULL AND LENGTH(icon_data)>0) FROM oidc_clients WHERE client_id=?`,
				clientID).Scan(&name, &hasIcon)
			if name != "" {
				tplData["AppName"] = name
			}
			if hasIcon {
				tplData["FaviconURL"] = "/oidc/icon/" + clientID
			}
		}
	}
	h.render(w, "login.html", tplData)
}

func (h *Handlers) PostLogin(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if !h.limiter.allow(ip) {
		h.render(w, "login.html", map[string]string{"Error": "Too many login attempts. Please try again later."})
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	loginMode := r.FormValue("login_mode")
	redirectURI := r.FormValue("redirect_uri")
	oidcRequest := r.FormValue("oidc_request")

	user, err := h.users.GetByEmail(r.Context(), email)
	if err != nil || user == nil || user.Disabled {
		h.limiter.record(ip)
		h.auditLog.Log(r.Context(), audit.EventLoginFailure, "", "", r.RemoteAddr, email)
		h.render(w, "login.html", map[string]string{"Error": "Invalid credentials", "RedirectURI": redirectURI})
		return
	}
	if !h.emailDomainAllowed(r, email) {
		h.limiter.record(ip)
		h.auditLog.Log(r.Context(), audit.EventLoginFailure, user.ID, "", r.RemoteAddr, "domain not allowed")
		h.render(w, "login.html", map[string]string{"Error": "Invalid credentials", "RedirectURI": redirectURI})
		return
	}

	if (password == "" || loginMode == "passwordless") && user.PasswordlessEnabled {
		h.handleOTPDispatch(w, r, user.ID, redirectURI, oidcRequest)
		return
	}

	if auth.VerifyPassword(password, user.PasswordHash) != nil {
		h.limiter.record(ip)
		h.auditLog.Log(r.Context(), audit.EventLoginFailure, user.ID, "", r.RemoteAddr, email)
		h.render(w, "login.html", map[string]string{"Error": "Invalid credentials", "RedirectURI": redirectURI})
		return
	}

	// Trusted device - skip 2FA entirely.
	if h.trustedDevices.IsTrusted(r, user.ID) {
		sessID, _ := h.sessions.Create(w, r, auth.SessionData{UserID: user.ID, RedirectURI: redirectURI, OIDCRequestID: oidcRequest})
		h.auditLog.Log(r.Context(), audit.EventLoginSuccess, user.ID, "", r.RemoteAddr, "trusted-device")
		data := &auth.SessionData{UserID: user.ID, RedirectURI: redirectURI, OIDCRequestID: oidcRequest}
		h.completeLogin(w, r, sessID, data)
		return
	}

	if user.TOTPEnabled {
		h.sessions.Create(w, r, auth.SessionData{
			UserID:        user.ID,
			PendingTOTP:   true,
			RedirectURI:   redirectURI,
			OIDCRequestID: oidcRequest,
		})
		http.Redirect(w, r, "/login/totp", http.StatusFound)
		return
	}

	h.handleOTPDispatch(w, r, user.ID, redirectURI, oidcRequest)
}

func (h *Handlers) handleOTPDispatch(w http.ResponseWriter, r *http.Request, userID, redirectURI, oidcRequest string) {
	code, err := h.otps.Issue(r.Context(), userID)
	if err != nil {
		http.Error(w, "Could not issue OTP", http.StatusInternalServerError)
		return
	}
	user, _ := h.users.GetByID(r.Context(), userID)
	if user != nil {
		h.mailer.SendOTP(r.Context(), user.Email, code) //nolint
	}
	h.auditLog.Log(r.Context(), audit.EventOTPSent, userID, "", r.RemoteAddr, "")
	h.sessions.Create(w, r, auth.SessionData{
		UserID:        userID,
		PendingOTP:    true,
		RedirectURI:   redirectURI,
		OIDCRequestID: oidcRequest,
	})
	http.Redirect(w, r, "/login/otp", http.StatusFound)
}

func (h *Handlers) GetOTP(w http.ResponseWriter, r *http.Request) {
	h.render(w, "otp.html", map[string]string{"OIDCRequest": r.URL.Query().Get("oidc_request")})
}

func (h *Handlers) PostOTP(w http.ResponseWriter, r *http.Request) {
	data, sessID, err := h.sessions.Get(r)
	if err != nil || data == nil || !data.PendingOTP {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	if err := h.otps.Verify(r.Context(), data.UserID, code); err != nil {
		h.auditLog.Log(r.Context(), audit.EventOTPFailed, data.UserID, "", r.RemoteAddr, "")
		h.render(w, "otp.html", map[string]string{"Error": err.Error()})
		return
	}

	h.auditLog.Log(r.Context(), audit.EventOTPVerified, data.UserID, "", r.RemoteAddr, "")
	h.trustedDevices.Trust(w, r, data.UserID)
	h.completeLogin(w, r, sessID, data)
}

func (h *Handlers) GetTOTP(w http.ResponseWriter, r *http.Request) {
	h.render(w, "totp.html", map[string]string{"OIDCRequest": r.URL.Query().Get("oidc_request")})
}

func (h *Handlers) PostTOTP(w http.ResponseWriter, r *http.Request) {
	data, sessID, err := h.sessions.Get(r)
	if err != nil || data == nil || !data.PendingTOTP {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	if err := h.totp.Validate(r.Context(), data.UserID, code); err != nil {
		h.auditLog.Log(r.Context(), audit.EventTOTPFailed, data.UserID, "", r.RemoteAddr, "")
		h.render(w, "totp.html", map[string]string{"Error": err.Error()})
		return
	}

	h.auditLog.Log(r.Context(), audit.EventTOTPVerified, data.UserID, "", r.RemoteAddr, "")
	h.trustedDevices.Trust(w, r, data.UserID)
	h.completeLogin(w, r, sessID, data)
}

func (h *Handlers) GetTOTPRecovery(w http.ResponseWriter, r *http.Request) {
	h.render(w, "totp_recovery.html", nil)
}

func (h *Handlers) PostTOTPRecovery(w http.ResponseWriter, r *http.Request) {
	data, sessID, err := h.sessions.Get(r)
	if err != nil || data == nil || !data.PendingTOTP {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if err := h.totp.UseRecoveryCode(r.Context(), data.UserID, code); err != nil {
		h.render(w, "totp_recovery.html", map[string]string{"Error": err.Error()})
		return
	}
	h.auditLog.Log(r.Context(), audit.EventTOTPRecoveryUsed, data.UserID, "", r.RemoteAddr, "")
	h.trustedDevices.Trust(w, r, data.UserID)
	h.completeLogin(w, r, sessID, data)
}

func (h *Handlers) completeLogin(w http.ResponseWriter, r *http.Request, sessID string, data *auth.SessionData) {
	user, _ := h.users.GetByID(r.Context(), data.UserID)
	if user != nil && user.ForcePasswordChange {
		data.PendingOTP = false
		data.PendingTOTP = false
		h.sessions.Update(r.Context(), sessID, *data)
		http.Redirect(w, r, "/profile/password?forced=1&redirect_uri="+url.QueryEscape(data.RedirectURI), http.StatusFound)
		return
	}
	data.PendingOTP = false
	data.PendingTOTP = false
	h.sessions.Update(r.Context(), sessID, *data)
	h.auditLog.Log(r.Context(), audit.EventLoginSuccess, data.UserID, "", r.RemoteAddr, "")

	if data.OIDCRequestID != "" && h.oidcStorage != nil {
		req, reqErr := h.oidcStorage.AuthRequestByID(r.Context(), data.OIDCRequestID)
		if reqErr == nil && req != nil {
			var policyID string
			h.db.QueryRowContext(r.Context(), `SELECT policy_id FROM oidc_clients WHERE client_id=?`, req.GetClientID()).Scan(&policyID)
			if policyID != "" {
				ok, _ := h.policies.IsUserInPolicyByID(r.Context(), policyID, data.UserID)
				if !ok {
					h.render(w, "access_denied.html", map[string]interface{}{"AppName": req.GetClientID()})
					return
				}
			}
		}
		if err := h.oidcStorage.AuthRequestDone(r.Context(), data.OIDCRequestID, data.UserID); err != nil {
			slog.Error("oidc auth request done failed", "id", data.OIDCRequestID, "err", err)
		} else {
			http.Redirect(w, r, "/authorize/callback?id="+url.QueryEscape(data.OIDCRequestID), http.StatusFound)
			return
		}
	}

	h.redirect(w, r, sessID, data.RedirectURI)
}

// redirect sends the user to target, using cross-domain token handoff when
// the target is outside the shared cookie domain.
func (h *Handlers) redirect(w http.ResponseWriter, r *http.Request, sessID, target string) {
	if target == "" {
		target = "/"
	}
	if h.needsCrossDomain(target) {
		token := auth.GenerateCrossToken(sessID, h.secretKey)
		u, err := url.Parse(target)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		cb := u.Scheme + "://" + u.Host + "/_gk/auth" +
			"?token=" + url.QueryEscape(token) +
			"&redirect=" + url.QueryEscape(u.RequestURI())
		http.Redirect(w, r, cb, http.StatusFound)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// needsCrossDomain returns true when the target URL's host is not covered by
// the shared cookie domain (e.g. a completely different TLD).
func (h *Handlers) needsCrossDomain(target string) bool {
	if h.cookieDomain == "" {
		return false
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return false
	}
	suffix := strings.TrimPrefix(h.cookieDomain, ".")
	host := u.Hostname()
	return host != suffix && !strings.HasSuffix(host, "."+suffix)
}

func (h *Handlers) PostPasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, session, err := h.passkeys.WebAuthn().BeginDiscoverableLogin(
		webauthnlib.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessID, _ := auth.RandomTokenExport(32)
	h.passkeys.SaveSession(r.Context(), sessID, nil, session)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Passkey-Session", sessID)
	json.NewEncoder(w).Encode(options)
}

func (h *Handlers) PostPasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	sessID := r.Header.Get("X-Passkey-Session")
	sessionData, err := h.passkeys.GetSession(r.Context(), sessID)
	if err != nil {
		http.Error(w, "session expired", http.StatusBadRequest)
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, email, cred, err := h.passkeys.FindCredentialByID(r.Context(), parsedResponse.RawID)
	if err != nil {
		http.Error(w, "credential not found", http.StatusUnauthorized)
		return
	}

	waUser, err := h.passkeys.LoadUser(r.Context(), userID, email)
	if err != nil {
		http.Error(w, "user load error", http.StatusInternalServerError)
		return
	}

	updatedCred, err := h.passkeys.WebAuthn().ValidateDiscoverableLogin(
		func(rawID, userHandle []byte) (webauthnlib.User, error) {
			return waUser, nil
		},
		*sessionData, parsedResponse,
	)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	_ = cred
	h.passkeys.UpdateCredential(r.Context(), userID, updatedCred)

	sessData := auth.SessionData{UserID: userID}
	_, err = h.sessions.Create(w, r, sessData)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	h.auditLog.Log(r.Context(), audit.EventLoginPasskey, userID, "", r.RemoteAddr, "")
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) GetForgotPassword(w http.ResponseWriter, r *http.Request) {
	h.render(w, "forgot_password.html", nil)
}

func (h *Handlers) PostForgotPassword(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	ip := strings.Split(r.RemoteAddr, ":")[0]

	h.render(w, "forgot_password.html", map[string]string{
		"Success": "If an account with that email exists, a reset link has been sent.",
	})

	go func() {
		ctx := r.Context()
		if err := auth.CheckResetRateLimit(ctx, h.db, email, "email", r); err != nil {
			return
		}
		if err := auth.CheckResetRateLimit(ctx, h.db, ip, "ip", r); err != nil {
			return
		}
		user, err := h.users.GetByEmail(ctx, email)
		if err != nil || user == nil {
			return
		}
		token, err := h.resetStore.IssueToken(ctx, user.ID)
		if err != nil {
			return
		}
		resetURL := h.baseURL + "/reset-password?token=" + token
		h.mailer.SendPasswordReset(ctx, email, resetURL)
		h.auditLog.Log(ctx, audit.EventPasswordResetReq, user.ID, "", ip, email)
	}()
}

func (h *Handlers) GetResetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_, err := h.resetStore.ValidateToken(r.Context(), token)
	if err != nil {
		h.render(w, "reset_password.html", map[string]string{"Error": "This link is invalid or has expired.", "Token": ""})
		return
	}
	h.render(w, "reset_password.html", map[string]string{"Token": token})
}

func (h *Handlers) PostResetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if password != confirm {
		h.render(w, "reset_password.html", map[string]string{"Error": "Passwords do not match", "Token": token})
		return
	}

	userID, err := h.resetStore.Redeem(r.Context(), token)
	if err != nil {
		h.auditLog.Log(r.Context(), audit.EventPasswordResetBad, "", "", r.RemoteAddr, "")
		h.render(w, "reset_password.html", map[string]string{"Error": "This link is invalid or has expired.", "Token": ""})
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		h.render(w, "reset_password.html", map[string]string{"Error": err.Error(), "Token": token})
		return
	}

	if err := h.users.SetPassword(r.Context(), userID, hash, false); err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	h.sessions.RevokeAll(r.Context(), userID)
	h.auditLog.Log(r.Context(), audit.EventPasswordResetDone, userID, "", r.RemoteAddr, "")

	user, _ := h.users.GetByID(r.Context(), userID)
	if user != nil {
		h.mailer.SendPasswordChanged(r.Context(), user.Email)
	}
	http.Redirect(w, r, "/login?success=password_reset", http.StatusFound)
}

func (h *Handlers) PostLogout(w http.ResponseWriter, r *http.Request) {
	_, sessID, _ := h.sessions.Get(r)
	if sessID != "" {
		h.sessions.Destroy(w, r, sessID)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *Handlers) GetAvatar(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	data, mime := h.users.GetAvatar(r.Context(), id)
	if len(data) == 0 {
		http.NotFound(w, r)
		return
	}
	if mime == "" {
		mime = "image/jpeg"
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func (h *Handlers) PostProfileName(w http.ResponseWriter, r *http.Request) {
	data, _, err := h.sessions.Get(r)
	if err != nil || data == nil || data.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("display_name"))
	h.users.SetDisplayName(r.Context(), data.UserID, name)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) PostProfileAvatar(w http.ResponseWriter, r *http.Request) {
	sess, _, err := h.sessions.Get(r)
	if err != nil || sess == nil || sess.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	user, _ := h.users.GetByID(r.Context(), sess.UserID)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	hash := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(user.Email))))
	gravatarURL := fmt.Sprintf("https://www.gravatar.com/avatar/%x?s=160&d=404", hash)
	resp, err := http.Get(gravatarURL) //nolint
	if err != nil || resp.StatusCode != 200 {
		http.Redirect(w, r, "/?avatar_err=not_found", http.StatusFound)
		return
	}
	defer resp.Body.Close()
	imgData, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil || len(imgData) == 0 {
		http.Redirect(w, r, "/?avatar_err=fetch_failed", http.StatusFound)
		return
	}
	mime := resp.Header.Get("Content-Type")
	if idx := strings.Index(mime, ";"); idx > 0 {
		mime = mime[:idx]
	}
	h.users.SetAvatar(r.Context(), sess.UserID, imgData, mime)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) GetChangePassword(w http.ResponseWriter, r *http.Request) {
	forced := r.URL.Query().Get("forced") == "1"
	redirectURI := r.URL.Query().Get("redirect_uri")
	h.render(w, "change_password.html", map[string]interface{}{
		"Forced":      forced,
		"RedirectURI": redirectURI,
		"CSRFToken":   h.csrf(r),
	})
}

func (h *Handlers) PostChangePassword(w http.ResponseWriter, r *http.Request) {
	data, sessID, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}

	user, err := h.users.GetByID(r.Context(), data.UserID)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	current := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if auth.VerifyPassword(current, user.PasswordHash) != nil {
		h.render(w, "change_password.html", map[string]string{"Error": "Current password is incorrect"})
		return
	}
	if newPass != confirm {
		h.render(w, "change_password.html", map[string]string{"Error": "Passwords do not match"})
		return
	}
	if user.TOTPEnabled {
		totpCode := strings.TrimSpace(r.FormValue("totp_code"))
		if err := h.totp.Validate(r.Context(), user.ID, totpCode); err != nil {
			h.render(w, "change_password.html", map[string]string{"Error": "Invalid TOTP code"})
			return
		}
	}

	hash, err := auth.HashPassword(newPass)
	if err != nil {
		h.render(w, "change_password.html", map[string]string{"Error": err.Error()})
		return
	}
	if err := h.users.SetPassword(r.Context(), user.ID, hash, false); err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	h.sessions.RevokeUser(r.Context(), user.ID, sessID)
	h.auditLog.Log(r.Context(), audit.EventPasswordChanged, user.ID, "", r.RemoteAddr, "")
	h.mailer.SendPasswordChanged(r.Context(), user.Email)
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI != "" {
		h.redirect(w, r, sessID, redirectURI)
		return
	}
	h.render(w, "change_password.html", map[string]interface{}{"Success": "Password changed. All other sessions have been signed out."})
}

func (h *Handlers) GetTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	data, _, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	user, _ := h.users.GetByID(r.Context(), data.UserID)
	key, err := auth.GenerateSecret(h.issuer, user.Email)
	if err != nil {
		http.Error(w, "TOTP generation failed", http.StatusInternalServerError)
		return
	}
	png, err := auth.QRCodePNG(key)
	if err != nil {
		http.Error(w, "QR code generation failed", http.StatusInternalServerError)
		return
	}
	h.render(w, "totp_enroll.html", map[string]interface{}{
		"Secret":    key.Secret(),
		"QRCodeB64": base64.StdEncoding.EncodeToString(png),
		"TOTPKey":   key.URL(),
		"CSRFToken": h.csrf(r),
	})
}

func (h *Handlers) PostTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	data, _, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	secret := r.FormValue("secret")
	code := strings.TrimSpace(r.FormValue("code"))

	codes, err := h.totp.ConfirmEnrollment(r.Context(), data.UserID, secret, code)
	if err != nil {
		h.render(w, "totp_enroll.html", map[string]string{"Error": err.Error(), "Secret": secret})
		return
	}
	h.auditLog.Log(r.Context(), audit.EventTOTPEnrolled, data.UserID, "", r.RemoteAddr, "")
	h.render(w, "totp_recovery_display.html", map[string]interface{}{"Codes": codes})
}

func (h *Handlers) GetTOTPRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	h.render(w, "totp_recovery_display.html", nil)
}

func (h *Handlers) GetTOTPDisable(w http.ResponseWriter, r *http.Request) {
	h.render(w, "totp_disable.html", map[string]interface{}{"CSRFToken": h.csrf(r)})
}

func (h *Handlers) PostTOTPDisable(w http.ResponseWriter, r *http.Request) {
	data, _, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if err := h.totp.Validate(r.Context(), data.UserID, code); err != nil {
		h.render(w, "totp_disable.html", map[string]string{"Error": "Invalid TOTP code"})
		return
	}
	h.totp.Revoke(r.Context(), data.UserID)
	h.auditLog.Log(r.Context(), audit.EventTOTPRevoked, data.UserID, "", r.RemoteAddr, "self")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) GetPasskeyRegister(w http.ResponseWriter, r *http.Request) {
	h.render(w, "passkey_register.html", nil)
}

func (h *Handlers) PostPasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	data, _, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := h.users.GetByID(r.Context(), data.UserID)
	if err != nil || user == nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}
	waUser, err := h.passkeys.LoadUser(r.Context(), user.ID, user.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	options, session, err := h.passkeys.WebAuthn().BeginRegistration(waUser,
		webauthnlib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessID, _ := auth.RandomTokenExport(32)
	h.passkeys.SaveSession(r.Context(), sessID, &user.ID, session)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Passkey-Session", sessID)
	json.NewEncoder(w).Encode(options)
}

func (h *Handlers) PostPasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	data, _, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := h.users.GetByID(r.Context(), data.UserID)
	if err != nil || user == nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	sessID := r.Header.Get("X-Passkey-Session")
	sessionData, err := h.passkeys.GetSession(r.Context(), sessID)
	if err != nil {
		http.Error(w, "session expired", http.StatusBadRequest)
		return
	}

	waUser, err := h.passkeys.LoadUser(r.Context(), user.ID, user.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cred, err := h.passkeys.WebAuthn().CreateCredential(waUser, *sessionData, parsedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey"
	}
	if err := h.passkeys.RegisterCredential(r.Context(), user.ID, name, cred); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog.Log(r.Context(), audit.EventPasskeyRegistered, user.ID, "", r.RemoteAddr, name)
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) PostPasskeyDelete(w http.ResponseWriter, r *http.Request) {
	data, _, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.passkeys.DeleteCredential(r.Context(), data.UserID, id)
	h.auditLog.Log(r.Context(), audit.EventPasskeyRevoked, data.UserID, "", r.RemoteAddr, "")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) PostSessionRevoke(w http.ResponseWriter, r *http.Request) {
	data, currentID, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if id != currentID {
		h.sessions.RevokeSession(r.Context(), data.UserID, id)
		h.auditLog.Log(r.Context(), audit.EventSessionRevoked, data.UserID, "", r.RemoteAddr, "")
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) PostRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	data, currentID, err := h.sessions.Get(r)
	if err != nil || data == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	h.sessions.RevokeUser(r.Context(), data.UserID, currentID)
	h.auditLog.Log(r.Context(), audit.EventSessionRevoked, data.UserID, "", r.RemoteAddr, "")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) GetRegister(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("invite")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	inv, err := h.invites.GetByToken(r.Context(), token)
	if err != nil || inv == nil || inv.IsUsed() || inv.IsExpired() {
		h.render(w, "register.html", map[string]interface{}{"Error": "This invite link is invalid or has expired."})
		return
	}
	h.render(w, "register.html", map[string]interface{}{
		"Token":     token,
		"Email":     inv.Email,
		"CSRFToken": h.csrf(r),
	})
}

func (h *Handlers) PostRegister(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	token := r.FormValue("invite_token")
	inv, err := h.invites.GetByToken(r.Context(), token)
	if err != nil || inv == nil || inv.IsUsed() || inv.IsExpired() {
		h.render(w, "register.html", map[string]interface{}{"Error": "This invite link is invalid or has expired.", "CSRFToken": h.csrf(r)})
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email == "" {
		email = inv.Email
	}
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	if email == "" {
		h.render(w, "register.html", map[string]interface{}{"Error": "Email is required.", "Token": token, "CSRFToken": h.csrf(r)})
		return
	}
	if password == "" || len(password) < 12 {
		h.render(w, "register.html", map[string]interface{}{"Error": "Password must be at least 12 characters.", "Token": token, "Email": inv.Email, "CSRFToken": h.csrf(r)})
		return
	}
	if password != confirm {
		h.render(w, "register.html", map[string]interface{}{"Error": "Passwords do not match.", "Token": token, "Email": inv.Email, "CSRFToken": h.csrf(r)})
		return
	}

	existing, _ := h.users.GetByEmail(r.Context(), email)
	if existing != nil {
		h.render(w, "register.html", map[string]interface{}{"Error": "An account with that email already exists.", "Token": token, "Email": inv.Email, "CSRFToken": h.csrf(r)})
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	userID, err := h.users.Create(r.Context(), email, hash, false)
	if err != nil {
		h.render(w, "register.html", map[string]interface{}{"Error": "Could not create account. Please try again.", "Token": token, "Email": inv.Email, "CSRFToken": h.csrf(r)})
		return
	}
	h.invites.MarkUsed(r.Context(), inv.ID)
	h.auditLog.Log(r.Context(), "user.registered", userID, "", r.RemoteAddr, email)
	h.sessions.Create(w, r, auth.SessionData{UserID: userID})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) emailDomainAllowed(r *http.Request, email string) bool {
	raw := h.settings.Get(r.Context(), "allowed_email_domains", "")
	if raw == "" {
		return true
	}
	atIdx := strings.LastIndex(email, "@")
	if atIdx < 0 {
		return false
	}
	domain := strings.ToLower(email[atIdx+1:])
	for _, d := range strings.Split(raw, ",") {
		if strings.TrimSpace(strings.ToLower(d)) == domain {
			return true
		}
	}
	return false
}
