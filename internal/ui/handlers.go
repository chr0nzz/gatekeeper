package ui

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/auth/social"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
	"github.com/chr0nzz/gatekeeper/internal/mailer"
	gkmiddleware "github.com/chr0nzz/gatekeeper/internal/middleware"
	oidcstore "github.com/chr0nzz/gatekeeper/internal/oidc"
	gktemplates "github.com/chr0nzz/gatekeeper/internal/templates"
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
	renderer       *gktemplates.Renderer
	oidcStorage    *oidcstore.Storage
	policies       *queries.PolicyStore
	invites        *queries.InviteStore
	socialAccounts *queries.SocialStore
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
	renderer *gktemplates.Renderer,
	oidcStorage *oidcstore.Storage,
	baseURL, issuer, secretKey, cookieDomain string,
	policies *queries.PolicyStore,
	invites *queries.InviteStore,
	socialAccounts *queries.SocialStore,
) *Handlers {
	return &Handlers{
		db: db, users: users, sessions: sessions, otps: otps, totp: totp,
		passkeys: passkeys, resetStore: resetStore, settings: settings,
		trustedDevices: trustedDevices, mailer: m,
		auditLog: auditLog, renderer: renderer, oidcStorage: oidcStorage,
		policies: policies, invites: invites, socialAccounts: socialAccounts,
		limiter: newLoginLimiter(),
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

func (h *Handlers) checkPasswordPolicy(ctx context.Context, password string) error {
	minLen := 12
	if v := h.settings.Get(ctx, "password_min_length", "12"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 8 {
			minLen = n
		}
	}
	return auth.CheckPasswordPolicy(
		password,
		minLen,
		h.settings.Get(ctx, "password_require_uppercase", "0") == "1",
		h.settings.Get(ctx, "password_require_number", "0") == "1",
		h.settings.Get(ctx, "password_require_symbol", "0") == "1",
	)
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
	r.Get("/auth/social/{provider}/begin", h.GetSocialBegin)
	r.Get("/auth/social/{provider}/callback", h.GetSocialCallback)

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
		r.Post("/social/{id}/disconnect", h.PostSocialDisconnect)
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
	linkedSocial, _ := h.socialAccounts.ListByUser(r.Context(), user.ID)
	avatarErr := r.URL.Query().Get("avatar_err")
	socialErr := r.URL.Query().Get("social_err")
	h.render(w, "home.html", map[string]interface{}{
		"User":            user,
		"Passkeys":        passkeys,
		"Sessions":        sessions,
		"TOTPEnabled":     user.TOTPEnabled,
		"AvatarErr":       avatarErr,
		"SocialError":     socialErrMsg(socialErr),
		"ShowSocialError": socialErr != "",
		"CSRFToken":       h.csrf(r),
		"SocialAccounts":  linkedSocial,
		"SocialProviders": h.enabledSocialProviders(r.Context()),
		"UserHasPassword": user.PasswordHash != "",
	})
}

func (h *Handlers) GetLogin(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	oidcRequest := r.URL.Query().Get("oidc_request")
	// If already authenticated, complete the OIDC flow or forward directly.
	data, sessID, _ := h.sessions.Get(r)
	if data != nil && data.UserID != "" && !data.PendingOTP && !data.PendingTOTP {
		user, _ := h.users.GetByID(r.Context(), data.UserID)
		if user == nil || user.Disabled {
			h.sessions.Destroy(w, r, sessID)
		} else if oidcRequest != "" {
			data.OIDCRequestID = oidcRequest
			h.sessions.Update(r.Context(), sessID, *data)
			h.completeLogin(w, r, sessID, data)
			return
		} else {
			h.redirect(w, r, sessID, redirectURI)
			return
		}
	}

	tplData := h.brand(r)
	tplData["RedirectURI"] = redirectURI
	tplData["OIDCRequest"] = oidcRequest
	tplData["AppName"] = ""
	tplData["FaviconURL"] = ""
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
	mode := h.settings.Get(r.Context(), "registration_mode", "disabled")
	tplData["CanRegister"] = mode == "open" || mode == "approval"
	tplData["SocialProviders"] = h.enabledSocialProviders(r.Context())
	if errCode := r.URL.Query().Get("social_err"); errCode != "" {
		tplData["Error"] = socialErrMsg(errCode)
	}
	h.render(w, "login.html", tplData)
}

func (h *Handlers) PostLogin(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	redirectURI := r.FormValue("redirect_uri")
	oidcRequest := r.FormValue("oidc_request")

	loginErr := func(msg string) {
		d := h.brand(r)
		d["Error"] = msg
		d["RedirectURI"] = redirectURI
		d["OIDCRequest"] = oidcRequest
		h.render(w, "login.html", d)
	}

	if !h.limiter.allow(ip) {
		loginErr("Too many login attempts. Please try again later.")
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	loginMode := r.FormValue("login_mode")

	user, err := h.users.GetByEmail(r.Context(), email)
	if err != nil || user == nil || user.Disabled {
		h.limiter.record(ip)
		h.auditLog.Log(r.Context(), audit.EventLoginFailure, "", "", r.RemoteAddr, email)
		loginErr("Invalid credentials")
		return
	}
	if !h.emailDomainAllowed(r, email) {
		h.limiter.record(ip)
		h.auditLog.Log(r.Context(), audit.EventLoginFailure, user.ID, "", r.RemoteAddr, "domain not allowed")
		loginErr("Invalid credentials")
		return
	}

	if (password == "" || loginMode == "passwordless") && user.PasswordlessEnabled {
		h.handleOTPDispatch(w, r, user.ID, redirectURI, oidcRequest)
		return
	}

	if auth.VerifyPassword(password, user.PasswordHash) != nil {
		h.limiter.record(ip)
		h.auditLog.Log(r.Context(), audit.EventLoginFailure, user.ID, "", r.RemoteAddr, email)
		loginErr("Invalid credentials")
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

	redirectURI := r.URL.Query().Get("redirect_uri")
	sessData := auth.SessionData{UserID: userID, RedirectURI: redirectURI}
	newSessID, err2 := h.sessions.Create(w, r, sessData)
	if err2 != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	h.auditLog.Log(r.Context(), audit.EventLoginPasskey, userID, "", r.RemoteAddr, "")

	target := redirectURI
	if target == "" {
		target = "/"
	}
	if h.needsCrossDomain(target) {
		token := auth.GenerateCrossToken(newSessID, h.secretKey)
		u, _ := url.Parse(target)
		target = u.Scheme + "://" + u.Host + "/_gk/auth" +
			"?token=" + url.QueryEscape(token) +
			"&redirect=" + url.QueryEscape(u.RequestURI())
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(target))
}



func (h *Handlers) brand(r *http.Request) map[string]interface{} {
	return map[string]interface{}{
		"BrandName":    h.settings.Get(r.Context(), "login_app_name", ""),
		"BrandLogoURL": h.settings.Get(r.Context(), "login_logo_url", ""),
		"BrandTagline": h.settings.Get(r.Context(), "login_tagline", ""),
	}
}

func (h *Handlers) GetForgotPassword(w http.ResponseWriter, r *http.Request) {
	h.render(w, "forgot_password.html", h.brand(r))
}

func (h *Handlers) PostForgotPassword(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	ip := strings.Split(r.RemoteAddr, ":")[0]

	data := h.brand(r)
	data["Success"] = "If an account with that email exists, a reset link has been sent."
	h.render(w, "forgot_password.html", data)

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
		d := h.brand(r)
		d["Error"] = "This link is invalid or has expired."
		h.render(w, "reset_password.html", d)
		return
	}
	d := h.brand(r)
	d["Token"] = token
	h.render(w, "reset_password.html", d)
}

func (h *Handlers) PostResetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	resetErr := func(msg, tok string) {
		d := h.brand(r)
		d["Error"] = msg
		d["Token"] = tok
		h.render(w, "reset_password.html", d)
	}

	if password != confirm {
		resetErr("Passwords do not match", token)
		return
	}
	if err := h.checkPasswordPolicy(r.Context(), password); err != nil {
		resetErr(err.Error(), token)
		return
	}

	userID, err := h.resetStore.Redeem(r.Context(), token)
	if err != nil {
		h.auditLog.Log(r.Context(), audit.EventPasswordResetBad, "", "", r.RemoteAddr, "")
		resetErr("This link is invalid or has expired.", "")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		resetErr(err.Error(), token)
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

func (h *Handlers) EndSession(w http.ResponseWriter, r *http.Request) {
	data, sessID, _ := h.sessions.Get(r)
	if sessID != "" {
		h.sessions.Destroy(w, r, sessID)
		userID := ""
		if data != nil {
			userID = data.UserID
		}
		h.auditLog.Log(r.Context(), "session.oidc_logout", userID, "", r.RemoteAddr, "")
	}
	target := r.FormValue("post_logout_redirect_uri")
	if target == "" {
		target = r.URL.Query().Get("post_logout_redirect_uri")
	}
	if target != "" {
		if u, err := url.Parse(target); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
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
	if err := h.checkPasswordPolicy(r.Context(), newPass); err != nil {
		h.render(w, "change_password.html", map[string]string{"Error": err.Error()})
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
	mode := h.settings.Get(r.Context(), "registration_mode", "disabled")
	token := r.URL.Query().Get("invite")

	if token != "" {
		inv, err := h.invites.GetByToken(r.Context(), token)
		if err != nil || inv == nil || inv.IsUsed() || inv.IsExpired() {
			d := h.brand(r)
			d["Error"] = "This invite link is invalid or has expired."
			h.render(w, "register.html", d)
			return
		}
		d := h.brand(r)
		d["Token"] = token
		d["Email"] = inv.Email
		d["CSRFToken"] = h.csrf(r)
		h.render(w, "register.html", d)
		return
	}

	switch mode {
	case "open", "approval":
		d := h.brand(r)
		d["CSRFToken"] = h.csrf(r)
		d["Mode"] = mode
		h.render(w, "register.html", d)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handlers) PostRegister(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}

	mode := h.settings.Get(r.Context(), "registration_mode", "disabled")
	token := r.FormValue("invite_token")

	var invLockedEmail string
	var invID string

	if token != "" {
		inv, err := h.invites.GetByToken(r.Context(), token)
		if err != nil || inv == nil || inv.IsUsed() || inv.IsExpired() {
			h.render(w, "register.html", map[string]interface{}{"Error": "This invite link is invalid or has expired.", "CSRFToken": h.csrf(r)})
			return
		}
		invLockedEmail = inv.Email
		invID = inv.ID
	} else if mode != "open" && mode != "approval" {
		http.NotFound(w, r)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email == "" {
		email = invLockedEmail
	}
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	errData := func(msg string) map[string]interface{} {
		d := h.brand(r)
		d["Error"] = msg
		d["Token"] = token
		d["Email"] = invLockedEmail
		d["Mode"] = mode
		d["CSRFToken"] = h.csrf(r)
		return d
	}

	if email == "" {
		h.render(w, "register.html", errData("Email is required."))
		return
	}
	if token == "" && !h.registrationDomainAllowed(r, email) {
		h.render(w, "register.html", errData("Registration is not allowed for this email domain."))
		return
	}
	if err := h.checkPasswordPolicy(r.Context(), password); err != nil {
		h.render(w, "register.html", errData(err.Error()))
		return
	}
	if password != confirm {
		h.render(w, "register.html", errData("Passwords do not match."))
		return
	}
	if existing, _ := h.users.GetByEmail(r.Context(), email); existing != nil {
		h.render(w, "register.html", errData("An account with that email already exists."))
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if mode == "approval" && token == "" {
		userID, err := h.users.CreatePending(r.Context(), email, hash)
		if err != nil {
			h.render(w, "register.html", errData("Could not create account. Please try again."))
			return
		}
		h.auditLog.Log(r.Context(), "user.pending", userID, "", r.RemoteAddr, email)
		h.render(w, "register.html", map[string]interface{}{"Pending": true})
		return
	}

	userID, err := h.users.Create(r.Context(), email, hash, false)
	if err != nil {
		h.render(w, "register.html", errData("Could not create account. Please try again."))
		return
	}
	if invID != "" {
		h.invites.MarkUsed(r.Context(), invID)
	}
	h.auditLog.Log(r.Context(), "user.registered", userID, "", r.RemoteAddr, email)
	h.sessions.Create(w, r, auth.SessionData{UserID: userID})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) registrationDomainAllowed(r *http.Request, email string) bool {
	raw := h.settings.Get(r.Context(), "registration_allowed_domains", "")
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

type socialProviderMeta struct {
	Name  string
	Label string
	Icon  template.HTML
}

var knownProviders = []socialProviderMeta{
	{Name: "github", Label: "GitHub", Icon: `<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 2C6.48 2 2 6.58 2 12.26c0 4.53 2.87 8.37 6.84 9.73.5.09.68-.22.68-.49l-.01-1.71c-2.78.62-3.37-1.37-3.37-1.37-.45-1.17-1.11-1.48-1.11-1.48-.91-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.89 1.57 2.34 1.12 2.91.85.09-.66.35-1.12.63-1.38-2.22-.26-4.56-1.14-4.56-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05A9.4 9.4 0 0 1 12 7.07c.85 0 1.7.12 2.5.34 1.91-1.33 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.81-4.57 5.06.36.32.68.94.68 1.9l-.01 2.82c0 .27.18.59.69.49A10.27 10.27 0 0 0 22 12.26C22 6.58 17.52 2 12 2z"/></svg>`},
	{Name: "google", Label: "Google", Icon: `<svg viewBox="0 0 24 24" width="16" height="16"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>`},
	{Name: "discord", Label: "Discord", Icon: `<svg viewBox="0 0 24 24" width="16" height="16" fill="#5865F2"><path d="M20.317 4.37a19.8 19.8 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.74 19.74 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>`},
}

func (h *Handlers) enabledSocialProviders(ctx context.Context) []socialProviderMeta {
	var out []socialProviderMeta
	for _, p := range knownProviders {
		if h.settings.Get(ctx, "social_"+p.Name+"_enabled", "0") == "1" &&
			h.settings.Get(ctx, "social_"+p.Name+"_client_id", "") != "" &&
			h.settings.Get(ctx, "social_"+p.Name+"_client_secret", "") != "" {
			out = append(out, p)
		}
	}
	return out
}

func socialErrMsg(code string) string {
	switch code {
	case "no_account":
		return "No account is linked to this social login. Contact an administrator."
	case "account_disabled":
		return "Your account is disabled."
	case "already_linked":
		return "This social account is already linked to a different user."
	case "email_required":
		return "Your social profile does not have a verified email address."
	default:
		return "Social login failed. Please try again."
	}
}

func (h *Handlers) GetSocialBegin(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	isLink := r.URL.Query().Get("link") == "1"

	clientID := h.settings.Get(r.Context(), "social_"+provider+"_client_id", "")
	clientSecret := h.settings.Get(r.Context(), "social_"+provider+"_client_secret", "")
	if h.settings.Get(r.Context(), "social_"+provider+"_enabled", "0") != "1" || clientID == "" || clientSecret == "" {
		http.NotFound(w, r)
		return
	}

	state, err := auth.RandomTokenExport(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "gk_oauth_state", Value: state, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	if isLink {
		http.SetCookie(w, &http.Cookie{Name: "gk_oauth_link", Value: "1", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	} else {
		http.SetCookie(w, &http.Cookie{Name: "gk_oauth_link", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	}
	if oidcReq := r.URL.Query().Get("oidc_request"); oidcReq != "" {
		http.SetCookie(w, &http.Cookie{Name: "gk_oauth_oidc", Value: oidcReq, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	} else {
		http.SetCookie(w, &http.Cookie{Name: "gk_oauth_oidc", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	}

	redirectURI := h.baseURL + "/auth/social/" + provider + "/callback"
	authURL, err := social.AuthURL(provider, clientID, redirectURI, state)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handlers) GetSocialCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")

	stateCookie, _ := r.Cookie("gk_oauth_state")
	if stateCookie == nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		http.Redirect(w, r, "/login?social_err=failed", http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "gk_oauth_state", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})

	isLink := false
	if c, _ := r.Cookie("gk_oauth_link"); c != nil && c.Value == "1" {
		isLink = true
	}
	http.SetCookie(w, &http.Cookie{Name: "gk_oauth_link", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})

	oidcReq := ""
	if c, _ := r.Cookie("gk_oauth_oidc"); c != nil {
		oidcReq = c.Value
	}
	http.SetCookie(w, &http.Cookie{Name: "gk_oauth_oidc", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})

	clientID := h.settings.Get(r.Context(), "social_"+provider+"_client_id", "")
	clientSecret := h.settings.Get(r.Context(), "social_"+provider+"_client_secret", "")
	redirectURI := h.baseURL + "/auth/social/" + provider + "/callback"

	code := r.URL.Query().Get("code")
	accessToken, err := social.ExchangeToken(r.Context(), provider, clientID, clientSecret, code, redirectURI)
	if err != nil {
		http.Redirect(w, r, "/login?social_err=failed", http.StatusFound)
		return
	}

	profile, err := social.FetchProfile(r.Context(), provider, accessToken)
	if err != nil || profile == nil {
		http.Redirect(w, r, "/login?social_err=failed", http.StatusFound)
		return
	}
	if profile.Email == "" {
		http.Redirect(w, r, "/login?social_err=email_required", http.StatusFound)
		return
	}

	if isLink {
		sessData, _, _ := h.sessions.Get(r)
		if sessData == nil || sessData.UserID == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		existing, _ := h.socialAccounts.FindByProvider(r.Context(), provider, profile.ProviderID)
		if existing != nil && existing.UserID != sessData.UserID {
			http.Redirect(w, r, "/?social_err=already_linked", http.StatusFound)
			return
		}
		if existing == nil {
			h.socialAccounts.Create(r.Context(), sessData.UserID, provider, profile.ProviderID, profile.Email)
			h.auditLog.Log(r.Context(), "social.linked", sessData.UserID, provider, r.RemoteAddr, "")
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	account, _ := h.socialAccounts.FindByProvider(r.Context(), provider, profile.ProviderID)
	var userID string
	if account != nil {
		userID = account.UserID
	} else {
		existing, _ := h.users.GetByEmail(r.Context(), strings.ToLower(profile.Email))
		if existing != nil && !existing.Disabled {
			h.socialAccounts.Create(r.Context(), existing.ID, provider, profile.ProviderID, profile.Email)
			h.auditLog.Log(r.Context(), "social.linked", existing.ID, provider, r.RemoteAddr, "auto")
			userID = existing.ID
		} else {
			mode := h.settings.Get(r.Context(), "registration_mode", "disabled")
			if mode == "disabled" || mode == "invite_only" {
				http.Redirect(w, r, "/login?social_err=no_account", http.StatusFound)
				return
			}
			if mode == "approval" {
				newID, err := h.users.CreatePending(r.Context(), strings.ToLower(profile.Email), "")
				if err != nil {
					http.Redirect(w, r, "/login?social_err=failed", http.StatusFound)
					return
				}
				h.socialAccounts.Create(r.Context(), newID, provider, profile.ProviderID, profile.Email)
				h.auditLog.Log(r.Context(), "user.pending", newID, "", r.RemoteAddr, "social:"+provider)
				http.Redirect(w, r, "/register?pending=1", http.StatusFound)
				return
			}
			newID, err := h.users.Create(r.Context(), strings.ToLower(profile.Email), "", false)
			if err != nil {
				http.Redirect(w, r, "/login?social_err=failed", http.StatusFound)
				return
			}
			h.socialAccounts.Create(r.Context(), newID, provider, profile.ProviderID, profile.Email)
			h.auditLog.Log(r.Context(), "user.registered", newID, "", r.RemoteAddr, "social:"+provider)
			userID = newID
		}
	}

	user, _ := h.users.GetByID(r.Context(), userID)
	if user == nil || user.Disabled {
		http.Redirect(w, r, "/login?social_err=account_disabled", http.StatusFound)
		return
	}

	sd := auth.SessionData{UserID: userID, OIDCRequestID: oidcReq}
	sessID, _ := h.sessions.Create(w, r, sd)
	h.auditLog.Log(r.Context(), "login.social", userID, provider, r.RemoteAddr, "")
	if oidcReq != "" {
		h.completeLogin(w, r, sessID, &sd)
	} else {
		h.redirect(w, r, sessID, "")
	}
}

func (h *Handlers) PostSocialDisconnect(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	sessData, _, _ := h.sessions.Get(r)
	if sessData == nil || sessData.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id := chi.URLParam(r, "id")
	user, _ := h.users.GetByID(r.Context(), sessData.UserID)
	socialCount := h.socialAccounts.CountByUser(r.Context(), sessData.UserID)
	hasPassword := user != nil && user.PasswordHash != ""
	if !hasPassword && socialCount <= 1 {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	h.socialAccounts.Delete(r.Context(), id)
	h.auditLog.Log(r.Context(), "social.unlinked", sessData.UserID, "", r.RemoteAddr, id)
	http.Redirect(w, r, "/", http.StatusFound)
}
