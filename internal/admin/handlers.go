package admin

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
	"github.com/chr0nzz/gatekeeper/internal/mailer"
	gkmiddleware "github.com/chr0nzz/gatekeeper/internal/middleware"
	"github.com/chr0nzz/gatekeeper/internal/notify"
	oidcstore "github.com/chr0nzz/gatekeeper/internal/oidc"
	"github.com/chr0nzz/gatekeeper/internal/templates"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

const adminCookieName = "gk_admin"

// Handlers holds all admin handler dependencies.
type Handlers struct {
	db             *sql.DB
	users          *queries.UserStore
	admins         *queries.AdminStore
	adminSess      *queries.AdminSessionStore
	sessions       *auth.SessionStore
	totp           *auth.TOTPStore
	passkeys       *auth.PasskeyStore
	trustedDevices *auth.TrustedDeviceStore
	oidcStorage    *oidcstore.Storage
	mailer         *mailer.Mailer
	resetStore     *auth.PasswordResetStore
	settings       *queries.SettingsStore
	auditLog       *audit.Logger
	renderer       *templates.Renderer
	policies       *queries.PolicyStore
	groups         *queries.GroupStore
	invites        *queries.InviteStore
	webhooks       *queries.WebhookStore
	claims         *queries.ClaimStore
	notifier       *notify.Service
	backups        *queries.BackupStore
	limiter        *auth.Limiter
	baseURL        string
	adminBase      string
	dbPath         string
	secretKey      string
	version        string
	envSMTP        mailer.Settings
	envDefaults    EnvDefaults
	updateCache    updateCache
}

type updateCache struct {
	mu        sync.Mutex
	result    *updateResult
	fetchedAt time.Time
}

type updateResult struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	URL       string `json:"url"`
	Body      string `json:"body"`
	HasUpdate bool   `json:"has_update"`
}

// EnvDefaults holds env var fallback values for settings that are managed in the UI.
type EnvDefaults struct {
	AllowedDomains             string
	SessionTTLHours            int
	RegistrationMode           string
	RegistrationAllowedDomains string
	GitHubClientID             string
	GitHubClientSecret         string
	GoogleClientID             string
	GoogleClientSecret         string
	DiscordClientID            string
	DiscordClientSecret        string
}

// New creates an admin Handlers.
func New(
	db *sql.DB,
	users *queries.UserStore,
	admins *queries.AdminStore,
	adminSess *queries.AdminSessionStore,
	sessions *auth.SessionStore,
	totp *auth.TOTPStore,
	passkeys *auth.PasskeyStore,
	trustedDevices *auth.TrustedDeviceStore,
	oidcStorage *oidcstore.Storage,
	m *mailer.Mailer,
	resetStore *auth.PasswordResetStore,
	settings *queries.SettingsStore,
	auditLog *audit.Logger,
	renderer *templates.Renderer,
	baseURL, adminBase, version, dbPath, secretKey string,
	envSMTP mailer.Settings,
	envDefaults EnvDefaults,
	policies *queries.PolicyStore,
	groups *queries.GroupStore,
	invites *queries.InviteStore,
	webhooks *queries.WebhookStore,
	claims *queries.ClaimStore,
	notifier *notify.Service,
	backups *queries.BackupStore,
) *Handlers {
	return &Handlers{
		db: db, users: users, admins: admins, adminSess: adminSess,
		sessions: sessions, totp: totp, passkeys: passkeys,
		trustedDevices: trustedDevices,
		oidcStorage:    oidcStorage, mailer: m, resetStore: resetStore,
		settings: settings, auditLog: auditLog, renderer: renderer,
		policies: policies, groups: groups, invites: invites, webhooks: webhooks, claims: claims, notifier: notifier,
		backups: backups,
		limiter: auth.NewLimiter(10, 15*time.Minute),
		baseURL: baseURL, adminBase: adminBase, version: version, dbPath: dbPath, secretKey: secretKey,
		envSMTP: envSMTP, envDefaults: envDefaults,
	}
}

func (h *Handlers) adminIDFromRequest(r *http.Request) string {
	if key := r.Header.Get("X-Api-Key"); key != "" {
		return h.admins.GetByAPIKey(r.Context(), key)
	}
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		return ""
	}
	id, _ := h.adminSess.Get(r.Context(), cookie.Value)
	return id
}

func (h *Handlers) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.admins.Exists(r.Context()) {
			http.Redirect(w, r, h.adminBase+"/setup", http.StatusFound)
			return
		}
		if h.adminIDFromRequest(r) == "" {
			http.Redirect(w, r, h.adminBase+"/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handlers) passwordPolicy(ctx context.Context) auth.PasswordPolicy {
	return auth.LoadPasswordPolicy(func(key, fallback string) string {
		return h.settings.Get(ctx, key, fallback)
	})
}

func (h *Handlers) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["CSRFToken"] = h.csrfToken(r)
	data["AdminBase"] = h.adminBase
	data["ActivePage"] = activePageFor(name)
	data["AdminEmail"] = h.adminEmailFromRequest(r)
	data["AppVersion"] = h.version
	var userCount, clientCount int
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users`).Scan(&userCount)
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM oidc_clients`).Scan(&clientCount)
	data["SidebarUserCount"] = userCount
	data["SidebarClientCount"] = clientCount
	data["HasUpdate"] = h.cachedHasUpdate(r.Context())
	data["PasswordMinLength"] = h.passwordPolicy(r.Context()).MinLength
	h.renderer.Render(w, name, data)
}

func (h *Handlers) adminEmailFromRequest(r *http.Request) string {
	adminID := h.adminIDFromRequest(r)
	if adminID == "" {
		return ""
	}
	admin, _ := h.admins.GetByID(r.Context(), adminID)
	if admin == nil {
		return ""
	}
	return admin.Email
}

func activePageFor(name string) string {
	switch name {
	case "admin_dashboard.html":
		return "dashboard"
	case "admin_users.html", "admin_user_new.html", "admin_user_detail.html":
		return "users"
	case "admin_clients.html", "admin_client_claims.html":
		return "clients"
	case "admin_policies.html", "admin_policy_detail.html":
		return "policies"
	case "admin_groups.html", "admin_group_detail.html":
		return "groups"
	case "admin_invites.html":
		return "invites"
	case "admin_audit.html":
		return "audit"
	case "admin_settings.html":
		return "settings"
	case "admin_profile.html":
		return "profile"
	case "admin_integrations.html":
		return "integrations"
	case "admin_webhooks.html":
		return "webhooks"
	case "admin_social.html":
		return "social"
	case "admin_admins.html":
		return "admins"
	case "admin_backups.html":
		return "backups"
	}
	return ""
}

func (h *Handlers) csrfToken(r *http.Request) string {
	return gkmiddleware.CSRFToken(r)
}

func (h *Handlers) checkCSRF(r *http.Request) bool {
	token := h.csrfToken(r)
	return token != "" && r.FormValue("csrf_token") == token
}

// Mount registers all admin routes on the given router.
func (h *Handlers) Mount(r chi.Router) {
	r.Get("/setup", h.GetSetup)
	r.Post("/setup", h.PostSetup)
	r.Get("/login", h.GetLogin)
	r.Post("/login", h.PostLogin)
	r.Post("/login/passkey/begin", h.PostLoginPasskeyBegin)
	r.Post("/login/passkey/finish", h.PostLoginPasskeyFinish)
	r.Post("/logout", h.PostLogout)

	r.Group(func(r chi.Router) {
		r.Use(h.requireAdmin)
		r.Get("/", h.GetDashboard)
		r.Get("/api/activity", h.GetActivityData)
		r.Get("/api/auth-methods", h.GetAuthMethodsData)
		r.Get("/api/dashboard-stats", h.GetDashboardStats)
		r.Get("/api/search", h.GetSearch)
		r.Get("/api/version-check", h.GetVersionCheck)
		r.Get("/users", h.GetUsers)
		r.Get("/users/new", h.GetNewUser)
		r.Post("/users", h.PostCreateUser)
		r.Get("/users/{id}", h.GetUser)
		r.Post("/users/{id}/password", h.PostSetPassword)
		r.Post("/users/{id}/reset-email", h.PostSendReset)
		r.Post("/users/{id}/disable", h.PostDisableUser)
		r.Post("/users/{id}/enable", h.PostEnableUser)
		r.Post("/users/{id}/delete", h.PostDeleteUser)
		r.Post("/users/{id}/revoke-sessions", h.PostRevokeSessions)
		r.Post("/users/{id}/revoke-totp", h.PostRevokeTOTP)
		r.Post("/users/{id}/passwordless", h.PostTogglePasswordless)
		r.Post("/users/{id}/approve", h.PostApproveUser)
		r.Post("/users/{id}/reject", h.PostRejectUser)
		r.Post("/users/{id}/make-admin", h.PostMakeUserAdmin)
		r.Post("/users/{id}/groups/{groupID}/add", h.PostAddUserToGroup)
		r.Post("/users/{id}/groups/{groupID}/remove", h.PostRemoveUserFromGroup)
		r.Get("/clients", h.GetClients)
		r.Post("/clients", h.PostCreateClient)
		r.Post("/clients/{id}/delete", h.PostDeleteClient)
		r.Post("/clients/{id}/edit", h.PostEditClient)
		r.Get("/clients/{id}/icon", h.GetClientIcon)
		r.Get("/clients/{id}/claims", h.GetClientClaims)
		r.Post("/clients/{id}/claims", h.PostCreateClaim)
		r.Post("/clients/{id}/claims/{claimID}/delete", h.PostDeleteClaim)
		r.Get("/clients/{id}/test", h.GetClientTest)
		r.Get("/policies", h.GetPolicies)
		r.Post("/policies", h.PostCreatePolicy)
		r.Get("/policies/{id}", h.GetPolicy)
		r.Post("/policies/{id}/delete", h.PostDeletePolicy)
		r.Post("/policies/{id}/members", h.PostAddPolicyMember)
		r.Post("/policies/{id}/members/{userID}/remove", h.PostRemovePolicyMember)
		r.Post("/policies/{id}/inject", h.PostPolicyInject)
		r.Post("/policies/{id}/inject/clear", h.PostPolicyInjectClear)
		r.Get("/invites", h.GetInvites)
		r.Post("/invites", h.PostCreateInvite)
		r.Post("/invites/{id}/revoke", h.PostRevokeInvite)
		r.Get("/groups", h.GetGroups)
		r.Post("/groups", h.PostCreateGroup)
		r.Get("/groups/{id}", h.GetGroup)
		r.Post("/groups/{id}/delete", h.PostDeleteGroup)
		r.Post("/groups/{id}/members", h.PostAddGroupMember)
		r.Post("/groups/{id}/members/{userID}/remove", h.PostRemoveGroupMember)
		r.Get("/integrations", h.GetIntegrations)
		r.Get("/audit", h.GetAudit)
		r.Get("/audit/export.csv", h.GetAuditExport)
		r.Get("/settings", h.GetSettings)
		r.Post("/settings", h.PostSettings)
		r.Get("/social", h.GetSocialSettings)
		r.Post("/social", h.PostSocialSettings)
		r.Get("/webhooks", h.GetWebhooks)
		r.Post("/webhooks", h.PostCreateWebhook)
		r.Post("/webhooks/{id}/edit", h.PostEditWebhook)
		r.Post("/webhooks/{id}/delete", h.PostDeleteWebhook)
		r.Post("/webhooks/{id}/toggle", h.PostToggleWebhook)
		r.Post("/webhooks/{id}/test", h.PostTestWebhook)

		r.Get("/backups", h.GetBackups)
		r.Post("/backups/settings", h.PostBackupSettings)
		r.Post("/backups/now", h.PostBackupNow)
		r.Post("/backups/upload", h.PostBackupUpload)
		r.Get("/backups/{id}/download", h.GetBackupDownload)
		r.Post("/backups/{id}/restore", h.PostBackupRestore)
		r.Post("/backups/{id}/delete", h.PostBackupDelete)
		r.Get("/admins", h.GetAdmins)
		r.Post("/admins", h.PostCreateAdmin)
		r.Post("/admins/{id}/delete", h.PostDeleteAdmin)

		r.Get("/profile", h.GetProfile)
		r.Post("/profile/display-name", h.PostProfileDisplayName)
		r.Post("/profile/password", h.PostProfilePassword)
		r.Post("/profile/revoke-sessions", h.PostProfileRevokeSessions)
		r.Post("/profile/api-key/rotate", h.PostProfileAPIKeyRotate)
		r.Get("/profile/totp/enroll", h.GetProfileTOTPEnroll)
		r.Post("/profile/totp/enroll", h.PostProfileTOTPEnroll)
		r.Post("/profile/totp/disable", h.PostProfileTOTPDisable)
		r.Get("/profile/passkey", h.GetProfilePasskey)
		r.Post("/profile/passkey/begin", h.PostProfilePasskeyBegin)
		r.Post("/profile/passkey/finish", h.PostProfilePasskeyFinish)
		r.Post("/profile/passkey/{id}/delete", h.PostProfilePasskeyDelete)
	})
}

func (h *Handlers) GetSetup(w http.ResponseWriter, r *http.Request) {
	if h.admins.Exists(r.Context()) {
		http.Redirect(w, r, h.adminBase+"/login", http.StatusFound)
		return
	}
	h.render(w, r, "admin_setup.html", nil)
}

func (h *Handlers) PostSetup(w http.ResponseWriter, r *http.Request) {
	if h.admins.Exists(r.Context()) {
		http.Redirect(w, r, h.adminBase+"/login", http.StatusFound)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if password != confirm {
		h.render(w, r, "admin_setup.html", map[string]interface{}{"Error": "Passwords do not match"})
		return
	}
	if err := h.passwordPolicy(r.Context()).Check(password); err != nil {
		h.render(w, r, "admin_setup.html", map[string]interface{}{"Error": err.Error()})
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		h.render(w, r, "admin_setup.html", map[string]interface{}{"Error": err.Error()})
		return
	}
	if err := h.admins.Create(r.Context(), email, hash, ""); err != nil {
		h.render(w, r, "admin_setup.html", map[string]interface{}{"Error": "Could not create admin: " + err.Error()})
		return
	}
	http.Redirect(w, r, h.adminBase+"/login", http.StatusFound)
}

func (h *Handlers) GetLogin(w http.ResponseWriter, r *http.Request) {
	if !h.admins.Exists(r.Context()) {
		http.Redirect(w, r, h.adminBase+"/setup", http.StatusFound)
		return
	}
	h.render(w, r, "admin_login.html", nil)
}

func (h *Handlers) PostLogin(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	ip := adminRemoteIP(r)

	// Password verification is deliberately expensive, so throttle before it runs.
	if !h.limiter.Allow(ip) {
		h.auditLog.Log(r.Context(), audit.EventAdminLoginFailed, "", "", r.RemoteAddr, "rate limited: "+email)
		h.render(w, r, "admin_login.html", map[string]interface{}{"Error": "Too many attempts. Try again later."})
		return
	}

	admin, err := h.admins.GetByEmail(r.Context(), email)
	if err != nil || admin == nil || auth.VerifyPassword(password, admin.PasswordHash) != nil {
		h.limiter.Record(ip)
		h.auditLog.Log(r.Context(), audit.EventAdminLoginFailed, "", "", r.RemoteAddr, email)
		h.render(w, r, "admin_login.html", map[string]interface{}{"Error": "Invalid credentials"})
		return
	}
	h.limiter.Reset(ip)

	sessID, err := h.adminSess.Create(r.Context(), admin.ID)
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    sessID,
		Path:     h.adminBase + "/",
		MaxAge:   8 * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	h.auditLog.Log(r.Context(), audit.EventAdminLogin, admin.ID, "", r.RemoteAddr, "password")
	http.Redirect(w, r, h.adminBase+"/", http.StatusFound)
}

func adminRemoteIP(r *http.Request) string {
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

func (h *Handlers) PostLoginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	if !h.limiter.Allow(adminRemoteIP(r)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
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

func (h *Handlers) PostLoginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
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
	userID, email, _, err := h.passkeys.FindCredentialByID(r.Context(), parsedResponse.RawID)
	if err != nil || !strings.HasPrefix(userID, "admin:") {
		http.Error(w, "credential not found", http.StatusUnauthorized)
		return
	}
	adminID := strings.TrimPrefix(userID, "admin:")
	waUser, err := h.passkeys.LoadUser(r.Context(), userID, email)
	if err != nil {
		http.Error(w, "user load error", http.StatusInternalServerError)
		return
	}
	_, err = h.passkeys.WebAuthn().ValidateDiscoverableLogin(
		func(rawID, userHandle []byte) (webauthnlib.User, error) { return waUser, nil },
		*sessionData, parsedResponse,
	)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	sessIDAdmin, err := h.adminSess.Create(r.Context(), adminID)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    sessIDAdmin,
		Path:     h.adminBase + "/",
		MaxAge:   8 * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	h.auditLog.Log(r.Context(), audit.EventAdminLoginPasskey, adminID, "", r.RemoteAddr, "")
	w.Header().Set("X-Redirect", h.adminBase+"/")
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) PostLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(adminCookieName)
	if err == nil {
		adminID, _ := h.adminSess.Get(r.Context(), cookie.Value)
		h.adminSess.Destroy(r.Context(), cookie.Value)
		if adminID != "" {
			h.auditLog.Log(r.Context(), audit.EventAdminLogout, adminID, "", r.RemoteAddr, "")
		}
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: "", MaxAge: -1, Path: h.adminBase + "/"})
	http.Redirect(w, r, h.adminBase+"/login", http.StatusFound)
}

func (h *Handlers) GetDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().Unix()
	since24h := now - 86400

	var totalUsers, activeUsers, disabledUsers, oidcClientCount int
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&totalUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE disabled=0`).Scan(&activeUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE disabled=1`).Scan(&disabledUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_clients`).Scan(&oidcClientCount)

	var signIns24h, failed24h, oidcTokens24h, totalAttempts, lockedUsers, no2faUsers int
	var passkeyLogins, totpLogins, otpLogins int
	var activeSessions, trustedDevices, totalAuditEvents int
	var usersWithPasskeys, usersWithTOTP, usersNoFactor int
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event IN ('login.success','login.passkey','login.social','admin.login','admin.login.passkey') AND created_at > ?`, since24h).Scan(&signIns24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event LIKE '%fail%' AND created_at > ?`, since24h).Scan(&failed24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_tokens WHERE created_at > ?`, since24h).Scan(&oidcTokens24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event IN ('login.success','login.passkey','login.social','admin.login','admin.login.passkey','login.failure') AND created_at > ?`, since24h).Scan(&totalAttempts)
	h.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_id) FROM otp_lockouts WHERE locked_until > ?`, now).Scan(&lockedUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE disabled=0 AND totp_enabled=0`).Scan(&no2faUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event='login.passkey' AND created_at > ?`, since24h).Scan(&passkeyLogins)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event='totp.verified' AND created_at > ?`, since24h).Scan(&totpLogins)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event='otp.verified' AND created_at > ?`, since24h).Scan(&otpLogins)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE expires_at > ?`, now).Scan(&activeSessions)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trusted_devices WHERE expires_at > ?`, now).Scan(&trustedDevices)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&totalAuditEvents)
	h.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_id) FROM passkeys`).Scan(&usersWithPasskeys)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE totp_enabled=1`).Scan(&usersWithTOTP)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE disabled=0 AND totp_enabled=0`).Scan(&usersNoFactor)

	successRate := 0
	if totalAttempts > 0 {
		successRate = (signIns24h * 100) / totalAttempts
	}

	totalMethods := passkeyLogins + totpLogins + otpLogins + oidcTokens24h
	pct := func(n int) int {
		if totalMethods == 0 {
			return 0
		}
		return (n * 100) / totalMethods
	}
	type AuthMethod struct {
		Name string
		Icon string
		Pct  int
	}
	authMethods := []AuthMethod{
		{"Passkey", "passkey", pct(passkeyLogins)},
		{"TOTP", "totp", pct(totpLogins)},
		{"Email OTP", "mail", pct(otpLogins)},
		{"OIDC", "clients", pct(oidcTokens24h)},
	}

	// Sparklines: hourly counts for last 12 hours
	sparkSignIns := hourlySparkline(ctx, h.db, 12, `SELECT COUNT(*) FROM audit_log WHERE event IN ('login.success','login.passkey') AND created_at >= ? AND created_at < ?`)
	sparkFailed := hourlySparkline(ctx, h.db, 12, `SELECT COUNT(*) FROM audit_log WHERE event LIKE '%fail%' AND created_at >= ? AND created_at < ?`)
	sparkOIDC := hourlySparkline(ctx, h.db, 12, `SELECT COUNT(*) FROM oidc_tokens WHERE created_at >= ? AND created_at < ?`)

	type RecentEvent struct {
		Event       string
		User        string
		UserName    string
		UserID      string
		HasAvatar   bool
		Detail      string
		Time        string
		Kind        string
		Method      string
		MethodClass string
	}
	rows, _ := h.db.QueryContext(ctx,
		`SELECT a.event, COALESCE(u.email, au.email, a.user_id, ''), COALESCE(u.display_name, au.email, ''), COALESCE(a.user_id,''), (u.avatar_data IS NOT NULL AND LENGTH(u.avatar_data)>0), COALESCE(a.detail,''), a.created_at
		 FROM audit_log a
		 LEFT JOIN users u ON u.id = a.user_id
		 LEFT JOIN admin_users au ON au.id = a.user_id
		 ORDER BY a.created_at DESC LIMIT 8`,
	)
	var recentEvents []RecentEvent
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e RecentEvent
			var ts int64
			rows.Scan(&e.Event, &e.User, &e.UserName, &e.UserID, &e.HasAvatar, &e.Detail, &ts)
			e.Time = time.Unix(ts, 0).Format("15:04:05")
			e.Kind = eventKind(e.Event)
			e.Method, e.MethodClass = loginMethod(e.Event)
			recentEvents = append(recentEvents, e)
		}
	}

	clients, _ := h.oidcStorage.ListClients(ctx)

	pctOf := func(n int) int {
		if totalUsers == 0 {
			return 0
		}
		return (n * 100) / totalUsers
	}

	h.render(w, r, "admin_dashboard.html", map[string]interface{}{
		"TotalUsers":        totalUsers,
		"ActiveUsers":       activeUsers,
		"DisabledUsers":     disabledUsers,
		"LockedUsers":       lockedUsers,
		"No2FAUsers":        no2faUsers,
		"OIDCClientCount":   oidcClientCount,
		"SignIns24h":        signIns24h,
		"Failed24h":         failed24h,
		"OIDCTokens24h":     oidcTokens24h,
		"SuccessRate":       successRate,
		"ActiveSessions":    activeSessions,
		"TrustedDevices":    trustedDevices,
		"TotalAuditEvents":  totalAuditEvents,
		"UsersWithPasskeys": usersWithPasskeys,
		"UsersWithTOTP":     usersWithTOTP,
		"UsersNoFactor":     usersNoFactor,
		"PctPasskeys":       pctOf(usersWithPasskeys),
		"PctTOTP":           pctOf(usersWithTOTP),
		"PctNoFactor":       pctOf(usersNoFactor),
		"RecentEvents":      recentEvents,
		"AuthMethods":       authMethods,
		"HasAuthData":       totalMethods > 0,
		"SparkSignIns":      sparkSignIns,
		"SparkFailed":       sparkFailed,
		"SparkOIDC":         sparkOIDC,
		"OIDCClients":       clients,
		"Policies":          func() interface{} { p, _ := h.policies.List(ctx); return p }(),
	})
}

func hourlySparkline(ctx context.Context, db *sql.DB, hours int, query string) string {
	now := time.Now().Unix()
	bucketSecs := int64(3600)
	counts := make([]int, hours)
	for i := 0; i < hours; i++ {
		start := now - int64(hours-i)*bucketSecs
		end := start + bucketSecs
		db.QueryRowContext(ctx, query, start, end).Scan(&counts[i])
	}
	maxVal := 1
	for _, v := range counts {
		if v > maxVal {
			maxVal = v
		}
	}
	w, h := 64, 28
	pts := ""
	for i, v := range counts {
		x := (i * w) / (hours - 1)
		y := h - (v*h)/maxVal
		if y < 1 {
			y = 1
		}
		if pts != "" {
			pts += " "
		}
		pts += fmt.Sprintf("%d,%d", x, y)
	}
	return pts
}

func (h *Handlers) GetDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().Unix()
	since24h := now - 86400
	var signIns24h, failed24h, oidcTokens24h, totalAttempts, lockedUsers int
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event IN ('login.success','login.passkey','login.social','admin.login','admin.login.passkey') AND created_at > ?`, since24h).Scan(&signIns24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event LIKE '%fail%' AND created_at > ?`, since24h).Scan(&failed24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_tokens WHERE created_at > ?`, since24h).Scan(&oidcTokens24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event IN ('login.success','login.passkey','login.social','admin.login','admin.login.passkey','login.failure') AND created_at > ?`, since24h).Scan(&totalAttempts)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM otp_lockouts WHERE locked_until > ?`, now).Scan(&lockedUsers)
	successRate := 0
	if totalAttempts > 0 {
		successRate = (signIns24h * 100) / totalAttempts
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"sign_ins_24h":    signIns24h,
		"failed_24h":      failed24h,
		"oidc_tokens_24h": oidcTokens24h,
		"success_rate":    successRate,
		"locked_users":    lockedUsers,
	})
}

func (h *Handlers) GetActivityData(w http.ResponseWriter, r *http.Request) {
	rangeParam := r.URL.Query().Get("range")
	var buckets int
	var bucketSecs int64
	var since int64
	now := time.Now().Unix()
	switch rangeParam {
	case "7d":
		buckets = 28
		bucketSecs = 6 * 3600
		since = now - 7*24*3600
	case "30d":
		buckets = 30
		bucketSecs = 24 * 3600
		since = now - 30*24*3600
	default:
		buckets = 24
		bucketSecs = 3600
		since = now - 24*3600
	}

	type Point struct {
		T    int64 `json:"t"`
		Ok   int   `json:"ok"`
		Fail int   `json:"fail"`
	}
	points := make([]Point, buckets)
	for i := range points {
		points[i].T = since + int64(i)*bucketSecs
	}

	rows, err := h.db.QueryContext(r.Context(),
		`SELECT created_at,
		  CASE WHEN event LIKE '%fail%' OR event LIKE '%failure%' THEN 1 ELSE 0 END
		 FROM audit_log
		 WHERE event IN ('login.success','login.passkey','login.social','admin.login','admin.login.passkey','login.failure','otp.failed','totp.failed')
		   AND created_at >= ?`,
		since,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ts int64
			var isFail int
			rows.Scan(&ts, &isFail)
			idx := int((ts - since) / bucketSecs)
			if idx >= 0 && idx < buckets {
				if isFail == 1 {
					points[idx].Fail++
				} else {
					points[idx].Ok++
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	enc, _ := json.Marshal(points)
	w.Write(enc)
}

func (h *Handlers) GetAuthMethodsData(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()
	var since int64
	switch r.URL.Query().Get("range") {
	case "7d":
		since = now - 7*86400
	case "30d":
		since = now - 30*86400
	default:
		since = now - 86400
	}
	var passkey, totp, otp, oidc, social int
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM audit_log WHERE event='login.passkey' AND created_at > ?`, since).Scan(&passkey)
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM audit_log WHERE event='totp.verified' AND created_at > ?`, since).Scan(&totp)
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM audit_log WHERE event='otp.verified' AND created_at > ?`, since).Scan(&otp)
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM oidc_tokens WHERE created_at > ?`, since).Scan(&oidc)
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM audit_log WHERE event='login.social' AND created_at > ?`, since).Scan(&social)
	total := passkey + totp + otp + oidc + social
	pct := func(n int) int {
		if total == 0 {
			return 0
		}
		return (n * 100) / total
	}
	type method struct {
		Name  string `json:"name"`
		Icon  string `json:"icon"`
		Pct   int    `json:"pct"`
		Count int    `json:"count"`
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]method{
		{"Passkey", "passkey", pct(passkey), passkey},
		{"TOTP", "totp", pct(totp), totp},
		{"Email OTP", "mail", pct(otp), otp},
		{"Social", "social", pct(social), social},
		{"OIDC", "clients", pct(oidc), oidc},
	})
}

func (h *Handlers) GetSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	type Result struct {
		Label string `json:"label"`
		Sub   string `json:"sub"`
		Icon  string `json:"icon"`
		URL   string `json:"url"`
	}
	var results []Result

	if q != "" {
		like := "%" + q + "%"
		rows, err := h.db.QueryContext(r.Context(),
			`SELECT id, COALESCE(NULLIF(display_name,''),email), email FROM users WHERE email LIKE ? OR display_name LIKE ? LIMIT 8`,
			like, like,
		)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, label, email string
				rows.Scan(&id, &label, &email)
				results = append(results, Result{Label: label, Sub: email, Icon: "user", URL: h.adminBase + "/users/" + id})
			}
		}

		crows, err := h.db.QueryContext(r.Context(),
			`SELECT client_id, name FROM oidc_clients WHERE client_id LIKE ? OR name LIKE ? LIMIT 4`,
			like, like,
		)
		if err == nil {
			defer crows.Close()
			for crows.Next() {
				var id, name string
				crows.Scan(&id, &name)
				results = append(results, Result{Label: name, Sub: id, Icon: "clients", URL: h.adminBase + "/clients"})
			}
		}

		grows, err := h.db.QueryContext(r.Context(),
			`SELECT id, name FROM groups WHERE name LIKE ? LIMIT 4`,
			like,
		)
		if err == nil {
			defer grows.Close()
			for grows.Next() {
				var id, name string
				grows.Scan(&id, &name)
				results = append(results, Result{Label: name, Sub: "group", Icon: "groups", URL: h.adminBase + "/groups/" + id})
			}
		}

		arows, err := h.db.QueryContext(r.Context(),
			`SELECT id, COALESCE(NULLIF(display_name,''),email), email FROM admin_users WHERE email LIKE ? OR display_name LIKE ? LIMIT 4`,
			like, like,
		)
		if err == nil {
			defer arows.Close()
			for arows.Next() {
				var id, label, email string
				arows.Scan(&id, &label, &email)
				results = append(results, Result{Label: label, Sub: email, Icon: "admins", URL: h.adminBase + "/admins"})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	enc, _ := json.Marshal(results)
	w.Write(enc)
}

func eventKind(event string) string {
	switch {
	case strings.Contains(event, "fail") || strings.Contains(event, "failure") || strings.Contains(event, "lockout"):
		return "err"
	case strings.Contains(event, "disabled") || strings.Contains(event, "revoked") || strings.Contains(event, "deleted"):
		return "warn"
	case strings.Contains(event, "logout"):
		return "info"
	case strings.Contains(event, "success") || strings.Contains(event, "passkey") || strings.Contains(event, "enrolled") || strings.Contains(event, "created") || strings.Contains(event, "verified") || strings.Contains(event, "changed") || strings.Contains(event, "registered") || event == "admin.login":
		return "ok"
	default:
		return "info"
	}
}

func loginMethod(event string) (string, string) {
	switch event {
	case "login.passkey", "admin.login.passkey":
		return "Passkey", "method-passkey"
	case "totp.verified":
		return "TOTP", "method-totp"
	case "otp.verified", "otp.sent":
		return "Email OTP", "method-emailotp"
	case "login.success":
		return "Password", "method-password"
	case "admin.login":
		return "Password", "method-password"
	case "login.social":
		return "Social", "method-social"
	}
	return "", ""
}

func eventCategory(event string) string {
	switch {
	case strings.HasPrefix(event, "admin."):
		return "admin"
	case strings.HasPrefix(event, "oidc."):
		return "oidc"
	default:
		return "auth"
	}
}

func (h *Handlers) GetNewUser(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin_user_new.html", nil)
}

func (h *Handlers) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.users.List(r.Context())
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	type UserRow struct {
		queries.User
		Sessions int
		Passkeys int
		LastSeen string
		IsLocked bool
		Initials string
		Status   string
	}
	now := time.Now().Unix()
	var rows []UserRow
	for _, u := range users {
		var sessions int
		h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM sessions WHERE user_id=? AND expires_at>?`, u.ID, now).Scan(&sessions)
		var lockedUntil sql.NullInt64
		h.db.QueryRowContext(r.Context(), `SELECT MAX(locked_until) FROM otp_lockouts WHERE user_id=?`, u.ID).Scan(&lockedUntil)
		isLocked := lockedUntil.Valid && lockedUntil.Int64 > now

		var passkeys int
		h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM passkeys WHERE user_id=?`, u.ID).Scan(&passkeys)

		var lastSeenTs sql.NullInt64
		h.db.QueryRowContext(r.Context(),
			`SELECT MAX(created_at) FROM audit_log WHERE user_id=? AND event IN ('login.success','login.passkey','otp.verified','totp.verified')`,
			u.ID).Scan(&lastSeenTs)
		lastSeen := ""
		if lastSeenTs.Valid && lastSeenTs.Int64 > 0 {
			t := time.Unix(lastSeenTs.Int64, 0)
			if time.Since(t) < 24*time.Hour {
				lastSeen = t.Format("15:04")
			} else if time.Since(t) < 7*24*time.Hour {
				lastSeen = t.Format("Mon")
			} else {
				lastSeen = t.Format("Jan 2")
			}
		}

		initials := strings.ToUpper(u.Email[:1])
		if at := strings.Index(u.Email, "@"); at > 1 {
			initials = strings.ToUpper(u.Email[:2])
		}
		status := "active"
		if u.PendingApproval {
			status = "pending"
		} else if u.Disabled {
			status = "disabled"
		} else if isLocked {
			status = "locked"
		}
		rows = append(rows, UserRow{User: u, Sessions: sessions, Passkeys: passkeys, LastSeen: lastSeen, IsLocked: isLocked, Initials: initials, Status: status})
	}
	active := 0
	locked := 0
	disabled := 0
	pending := 0
	no2fa := 0
	var pendingRows []UserRow
	var normalRows []UserRow
	for _, row := range rows {
		switch row.Status {
		case "active":
			active++
		case "locked":
			locked++
		case "disabled":
			disabled++
		case "pending":
			pending++
		}
		if !row.TOTPEnabled {
			no2fa++
		}
		if row.Status == "pending" {
			pendingRows = append(pendingRows, row)
		} else {
			normalRows = append(normalRows, row)
		}
	}
	h.render(w, r, "admin_users.html", map[string]interface{}{
		"Users":        normalRows,
		"PendingUsers": pendingRows,
		"Total":        len(normalRows),
		"Active":       active,
		"Locked":       locked,
		"Disabled":     disabled,
		"Pending":      pending,
		"No2FA":        no2fa,
	})
}

func (h *Handlers) PostCreateUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	passwordless := r.FormValue("passwordless") == "1"

	var hash string
	if !passwordless {
		password := r.FormValue("password")
		if err := h.passwordPolicy(r.Context()).Check(password); err != nil {
			h.render(w, r, "admin_user_new.html", map[string]interface{}{"Error": err.Error()})
			return
		}
		var err error
		hash, err = auth.HashPassword(password)
		if err != nil {
			h.render(w, r, "admin_user_new.html", map[string]interface{}{"Error": err.Error()})
			return
		}
	}

	adminID := h.adminIDFromRequest(r)
	id, err := h.users.Create(r.Context(), email, hash, !passwordless)
	if err != nil {
		h.render(w, r, "admin_user_new.html", map[string]interface{}{"Error": "Could not create user: " + err.Error()})
		return
	}
	if passwordless {
		h.users.SetPasswordless(r.Context(), id, true)
	}
	h.auditLog.Log(r.Context(), audit.EventUserCreated, id, adminID, r.RemoteAddr, email)
	http.Redirect(w, r, h.adminBase+"/users", http.StatusFound)
}

func (h *Handlers) GetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.users.GetByID(r.Context(), id)
	if err != nil || user == nil {
		http.NotFound(w, r)
		return
	}
	passkeys, _ := h.passkeys.ListCredentials(r.Context(), id)
	recoveryCodes, _ := h.totp.RecoveryCodeCount(r.Context(), id)

	now := time.Now().Unix()
	var sessions int
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM sessions WHERE user_id=? AND expires_at>?`, id, now).Scan(&sessions)
	var lockedUntil sql.NullInt64
	h.db.QueryRowContext(r.Context(), `SELECT MAX(locked_until) FROM otp_lockouts WHERE user_id=?`, id).Scan(&lockedUntil)
	isLocked := lockedUntil.Valid && lockedUntil.Int64 > now

	initials := strings.ToUpper(user.Email[:1])
	if at := strings.Index(user.Email, "@"); at > 1 {
		initials = strings.ToUpper(user.Email[:2])
	}

	type UserDetail struct {
		*queries.User
		Initials string
		Sessions int
		Locked   bool
		LastSeen string
	}

	userGroups, _ := h.groups.GetUserGroups(r.Context(), id)
	allGroups, _ := h.groups.List(r.Context())
	userGroupSet := map[string]bool{}
	for _, g := range userGroups {
		userGroupSet[g] = true
	}
	type GroupMembership struct {
		queries.Group
		IsMember bool
	}
	var groupMemberships []GroupMembership
	for _, g := range allGroups {
		groupMemberships = append(groupMemberships, GroupMembership{Group: g, IsMember: userGroupSet[g.Name]})
	}

	existingAdmin, _ := h.admins.GetByEmail(r.Context(), user.Email)

	errMessages := map[string]string{
		"admin_missing":  "Password is required.",
		"admin_mismatch": "Passwords do not match.",
		"admin_exists":   "An admin account with this email already exists.",
		"admin_server":   "Server error. Please try again.",
	}
	successMessages := map[string]string{
		"admin_promoted": "Admin account created. The user can now sign in to the admin panel.",
	}
	errMsg := errMessages[r.URL.Query().Get("err")]
	successMsg := successMessages[r.URL.Query().Get("success")]

	h.render(w, r, "admin_user_detail.html", map[string]interface{}{
		"User":             UserDetail{User: user, Initials: initials, Sessions: sessions, Locked: isLocked, LastSeen: ""},
		"Passkeys":         passkeys,
		"RecoveryCodes":    recoveryCodes,
		"GroupMemberships": groupMemberships,
		"IsAdmin":          existingAdmin != nil,
		"Error":            errMsg,
		"Success":          successMsg,
	})
}

func (h *Handlers) PostSetPassword(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	password := r.FormValue("password")
	if err := h.passwordPolicy(r.Context()).Check(password); err != nil {
		http.Redirect(w, r, h.adminBase+"/users/"+id+"?err="+encodeMsg(err.Error()), http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.users.SetPassword(r.Context(), id, hash, true); err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	adminID := h.adminIDFromRequest(r)
	h.auditLog.Log(r.Context(), audit.EventAdminPasswordSet, id, adminID, r.RemoteAddr, "")
	h.sessions.RevokeAll(r.Context(), id)
	h.trustedDevices.RevokeAll(r.Context(), id)
	http.Redirect(w, r, h.adminBase+"/users/"+id, http.StatusFound)
}

func (h *Handlers) PostSendReset(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	user, err := h.users.GetByID(r.Context(), id)
	if err != nil || user == nil {
		http.NotFound(w, r)
		return
	}
	token, err := h.resetStore.IssueToken(r.Context(), id)
	if err == nil {
		resetURL := h.baseURL + "/reset-password?token=" + token
		h.mailer.SendPasswordReset(r.Context(), user.Email, resetURL)
		adminID := h.adminIDFromRequest(r)
		h.auditLog.Log(r.Context(), audit.EventPasswordResetReq, id, adminID, r.RemoteAddr, "admin-triggered")
	}
	http.Redirect(w, r, h.adminBase+"/users/"+id, http.StatusFound)
}

func (h *Handlers) PostDisableUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.users.SetDisabled(r.Context(), id, true)
	h.sessions.RevokeAll(r.Context(), id)
	h.trustedDevices.RevokeAll(r.Context(), id)
	adminID := h.adminIDFromRequest(r)
	h.auditLog.Log(r.Context(), audit.EventUserDisabled, id, adminID, r.RemoteAddr, "")
	http.Redirect(w, r, h.adminBase+"/users", http.StatusFound)
}

func (h *Handlers) PostEnableUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.users.SetDisabled(r.Context(), id, false)
	adminID := h.adminIDFromRequest(r)
	h.auditLog.Log(r.Context(), audit.EventUserEnabled, id, adminID, r.RemoteAddr, "")
	http.Redirect(w, r, h.adminBase+"/users", http.StatusFound)
}

func (h *Handlers) PostDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	adminID := h.adminIDFromRequest(r)
	h.sessions.RevokeAll(r.Context(), id)
	h.trustedDevices.RevokeAll(r.Context(), id)
	h.users.Delete(r.Context(), id)
	h.auditLog.Log(r.Context(), audit.EventUserDeleted, id, adminID, r.RemoteAddr, "")
	http.Redirect(w, r, h.adminBase+"/users", http.StatusFound)
}

func (h *Handlers) PostApproveUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	adminID := h.adminIDFromRequest(r)
	h.users.Approve(r.Context(), id)
	h.auditLog.Log(r.Context(), "user.approved", id, adminID, r.RemoteAddr, "")
	http.Redirect(w, r, h.adminBase+"/users", http.StatusFound)
}

func (h *Handlers) PostRejectUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	adminID := h.adminIDFromRequest(r)
	h.users.Delete(r.Context(), id)
	h.auditLog.Log(r.Context(), "user.rejected", id, adminID, r.RemoteAddr, "")
	http.Redirect(w, r, h.adminBase+"/users", http.StatusFound)
}

func (h *Handlers) PostRevokeSessions(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.sessions.RevokeAll(r.Context(), id)
	h.trustedDevices.RevokeAll(r.Context(), id)
	adminID := h.adminIDFromRequest(r)
	h.auditLog.Log(r.Context(), audit.EventSessionRevoked, id, adminID, r.RemoteAddr, "admin-all")
	http.Redirect(w, r, h.adminBase+"/users/"+id, http.StatusFound)
}

func (h *Handlers) PostRevokeTOTP(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.totp.Revoke(r.Context(), id)
	adminID := h.adminIDFromRequest(r)
	h.auditLog.Log(r.Context(), audit.EventTOTPRevoked, id, adminID, r.RemoteAddr, "admin")
	http.Redirect(w, r, h.adminBase+"/users/"+id, http.StatusFound)
}

func (h *Handlers) PostTogglePasswordless(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	enabled := r.FormValue("enabled") == "1"
	h.users.SetPasswordless(r.Context(), id, enabled)
	http.Redirect(w, r, h.adminBase+"/users/"+id, http.StatusFound)
}

func (h *Handlers) GetClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.oidcStorage.ListClients(r.Context())
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	policies, _ := h.policies.List(r.Context())
	type PolicyOption struct {
		ID   string
		Name string
	}
	type ClientWithPolicy struct {
		oidcstore.ClientRecord
		PolicyID   string
		PolicyName string
	}
	var enriched []ClientWithPolicy
	for _, c := range clients {
		var policyID, policyName string
		h.db.QueryRowContext(r.Context(), `SELECT COALESCE(policy_id,'') FROM oidc_clients WHERE client_id=?`, c.ClientID).Scan(&policyID)
		for _, p := range policies {
			if p.ID == policyID {
				policyName = p.Name
				break
			}
		}
		enriched = append(enriched, ClientWithPolicy{ClientRecord: c, PolicyID: policyID, PolicyName: policyName})
	}
	var policyOptions []PolicyOption
	for _, p := range policies {
		policyOptions = append(policyOptions, PolicyOption{ID: p.ID, Name: p.Name})
	}
	h.render(w, r, "admin_clients.html", map[string]interface{}{
		"Clients":  enriched,
		"Policies": policyOptions,
		"BaseURL":  h.baseURL,
	})
}

func (h *Handlers) PostCreateClient(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	name := strings.TrimSpace(r.FormValue("name"))
	iconURL := strings.TrimSpace(r.FormValue("icon_url"))
	policyID := strings.TrimSpace(r.FormValue("policy_id"))
	credentialsScopes := strings.TrimSpace(r.FormValue("credentials_scopes"))
	urisRaw := strings.TrimSpace(r.FormValue("redirect_uris"))
	var uris []string
	for _, u := range strings.Split(urisRaw, "\n") {
		u = strings.TrimSpace(u)
		if u != "" {
			uris = append(uris, u)
		}
	}
	if err := h.oidcStorage.CreateClient(r.Context(), clientID, clientSecret, name, iconURL, credentialsScopes, uris); err != nil {
		clients, _ := h.oidcStorage.ListClients(r.Context())
		h.render(w, r, "admin_clients.html", map[string]interface{}{"Clients": clients, "Error": err.Error()})
		return
	}
	if policyID != "" {
		h.db.ExecContext(r.Context(), `UPDATE oidc_clients SET policy_id=? WHERE client_id=?`, policyID, clientID)
	}
	http.Redirect(w, r, h.adminBase+"/clients", http.StatusFound)
}

func (h *Handlers) GetClientIcon(w http.ResponseWriter, r *http.Request) {
	h.oidcStorage.ServeIcon(w, r, chi.URLParam(r, "id"))
}

func (h *Handlers) PostDeleteClient(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.oidcStorage.DeleteClient(r.Context(), id)
	http.Redirect(w, r, h.adminBase+"/clients", http.StatusFound)
}

func (h *Handlers) PostEditClient(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	name := strings.TrimSpace(r.FormValue("name"))
	iconURL := strings.TrimSpace(r.FormValue("icon_url"))
	urisRaw := strings.TrimSpace(r.FormValue("redirect_uris"))
	newSecret := strings.TrimSpace(r.FormValue("client_secret"))
	policyID := strings.TrimSpace(r.FormValue("policy_id"))
	credentialsScopes := strings.TrimSpace(r.FormValue("credentials_scopes"))
	var uris []string
	for _, u := range strings.Split(urisRaw, "\n") {
		if u = strings.TrimSpace(u); u != "" {
			uris = append(uris, u)
		}
	}
	h.oidcStorage.UpdateClient(r.Context(), id, name, iconURL, newSecret, credentialsScopes, uris)
	h.db.ExecContext(r.Context(), `UPDATE oidc_clients SET policy_id=? WHERE client_id=?`, policyID, id)
	http.Redirect(w, r, h.adminBase+"/clients", http.StatusFound)
}

var reservedClaims = map[string]bool{
	"sub": true, "iss": true, "aud": true, "exp": true, "iat": true,
	"auth_time": true, "nonce": true, "acr": true, "amr": true, "azp": true,
	"at_hash": true, "c_hash": true, "jti": true,
}

func (h *Handlers) GetClientTest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	type check struct {
		Label string `json:"label"`
		OK    bool   `json:"ok"`
		Note  string `json:"note,omitempty"`
	}
	type result struct {
		ClientID string  `json:"client_id"`
		Name     string  `json:"name"`
		AuthURL  string  `json:"auth_url"`
		Checks   []check `json:"checks"`
	}

	var name, secret, redirectsRaw string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT name, COALESCE(client_secret,''), COALESCE(redirect_uris,'[]') FROM oidc_clients WHERE client_id=?`, id,
	).Scan(&name, &secret, &redirectsRaw)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var redirectURIs []string
	json.Unmarshal([]byte(redirectsRaw), &redirectURIs)

	var policyName string
	h.db.QueryRowContext(r.Context(),
		`SELECT p.name FROM policies p JOIN policy_clients pc ON pc.policy_id=p.id WHERE pc.client_id=?`, id,
	).Scan(&policyName)

	claimList, _ := h.claims.List(r.Context(), id)

	checks := []check{
		{Label: "Client secret configured", OK: secret != "", Note: func() string {
			if secret == "" {
				return "Set a client secret on this client."
			}
			return ""
		}()},
		{Label: "Redirect URI configured", OK: len(redirectURIs) > 0, Note: func() string {
			if len(redirectURIs) == 0 {
				return "Add at least one redirect URI."
			}
			return ""
		}()},
		{Label: "Access policy", OK: true, Note: func() string {
			if policyName != "" {
				return "Restricted to policy: " + policyName
			}
			return "Open to all users (no policy assigned)."
		}()},
		{Label: "Custom claims", OK: true, Note: func() string {
			if len(claimList) > 0 {
				return fmt.Sprintf("%d claim(s) configured.", len(claimList))
			}
			return "No custom claims (groups claim always included)."
		}()},
	}

	authURL := ""
	if len(redirectURIs) > 0 {
		authURL = h.baseURL + "/oauth/authorize?client_id=" + id +
			"&redirect_uri=" + redirectURIs[0] +
			"&response_type=code&scope=openid+profile+email&prompt=login"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result{ClientID: id, Name: name, AuthURL: authURL, Checks: checks})
}

func (h *Handlers) GetClientClaims(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var clientName string
	h.db.QueryRowContext(r.Context(), `SELECT name FROM oidc_clients WHERE client_id=?`, id).Scan(&clientName)
	if clientName == "" {
		http.NotFound(w, r)
		return
	}
	claimList, _ := h.claims.List(r.Context(), id)
	h.render(w, r, "admin_client_claims.html", map[string]interface{}{
		"ClientID":   id,
		"ClientName": clientName,
		"Claims":     claimList,
	})
}

func (h *Handlers) PostCreateClaim(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	key := strings.TrimSpace(r.FormValue("claim_key"))
	sourceType := r.FormValue("value_source")
	literal := strings.TrimSpace(r.FormValue("literal_value"))
	if key == "" || reservedClaims[key] {
		http.Redirect(w, r, h.adminBase+"/clients/"+id+"/claims", http.StatusFound)
		return
	}
	valueSource := sourceType
	if sourceType == "literal" {
		valueSource = "literal:" + literal
	}
	h.claims.Create(r.Context(), id, key, valueSource)
	h.auditLog.Log(r.Context(), "client.claim_added", "", "", r.RemoteAddr, id+"/"+key)
	http.Redirect(w, r, h.adminBase+"/clients/"+id+"/claims", http.StatusFound)
}

func (h *Handlers) PostDeleteClaim(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	claimID := chi.URLParam(r, "claimID")
	h.claims.Delete(r.Context(), claimID)
	h.auditLog.Log(r.Context(), "client.claim_removed", "", "", r.RemoteAddr, id+"/"+claimID)
	http.Redirect(w, r, h.adminBase+"/clients/"+id+"/claims", http.StatusFound)
}

func (h *Handlers) GetIntegrations(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin_integrations.html", map[string]interface{}{
		"BaseURL": h.baseURL,
	})
}

type AuditEntry struct {
	Event       string
	User        string
	UserName    string
	UserID      string
	HasAvatar   bool
	Actor       string
	IP          string
	Detail      string
	Method      string
	MethodClass string
	Time        string
	Date        string
	Kind        string
	EventPrefix string
}

func (h *Handlers) auditQuery(ctx context.Context, days int, eventFilter, userFilter string, limit int) ([]AuditEntry, error) {
	base := `SELECT a.event,
			COALESCE(u.email, au.email, a.user_id, ''),
			COALESCE(u.display_name, au.email, ''),
			COALESCE(a.user_id, ''),
			(u.avatar_data IS NOT NULL AND LENGTH(u.avatar_data) > 0),
			COALESCE(act.email, aa.email, a.actor_id, ''),
			COALESCE(a.ip,''), COALESCE(a.detail,''), a.created_at
		FROM audit_log a
		LEFT JOIN users u ON u.id = a.user_id
		LEFT JOIN admin_users au ON au.id = a.user_id
		LEFT JOIN admin_users aa ON aa.id = a.actor_id
		LEFT JOIN users act ON act.id = a.actor_id`

	var conds []string
	var args []interface{}
	if days > 0 {
		conds = append(conds, "a.created_at >= ?")
		args = append(args, time.Now().AddDate(0, 0, -days).Unix())
	}
	if eventFilter != "" {
		conds = append(conds, "a.event LIKE ?")
		args = append(args, eventFilter+"%")
	}
	if userFilter != "" {
		like := "%" + userFilter + "%"
		conds = append(conds, "(COALESCE(u.email,au.email,a.user_id,'') LIKE ? OR a.ip LIKE ?)")
		args = append(args, like, like)
	}

	q := base
	for i, c := range conds {
		if i == 0 {
			q += " WHERE " + c
		} else {
			q += " AND " + c
		}
	}
	q += " ORDER BY a.created_at DESC"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := h.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		rows.Scan(&e.Event, &e.User, &e.UserName, &e.UserID, &e.HasAvatar, &e.Actor, &e.IP, &e.Detail, &ts)
		t := time.Unix(ts, 0)
		e.Time = t.Format("15:04:05")
		e.Date = t.Format("2006-01-02")
		e.Kind = eventKind(e.Event)
		e.EventPrefix = eventCategory(e.Event)
		e.Method, e.MethodClass = loginMethod(e.Event)
		entries = append(entries, e)
	}
	return entries, nil
}

func (h *Handlers) GetAudit(w http.ResponseWriter, r *http.Request) {
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n >= 0 {
			days = n
		}
	}
	eventFilter := r.URL.Query().Get("event")

	entries, err := h.auditQuery(r.Context(), days, eventFilter, "", 2000)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}

	type AuditGroup struct {
		Date    string
		Entries []AuditEntry
	}

	var groups []AuditGroup
	groupIdx := map[string]int{}
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	for _, e := range entries {
		var label string
		switch e.Date {
		case today:
			label = "Today"
		case yesterday:
			label = "Yesterday"
		default:
			t, _ := time.Parse("2006-01-02", e.Date)
			label = t.Format("Jan 2, 2006")
		}
		e.Date = label
		if idx, ok := groupIdx[label]; ok {
			groups[idx].Entries = append(groups[idx].Entries, e)
		} else {
			groupIdx[label] = len(groups)
			groups = append(groups, AuditGroup{Date: label, Entries: []AuditEntry{e}})
		}
	}

	h.render(w, r, "admin_audit.html", map[string]interface{}{
		"Groups":      groups,
		"TotalEvents": len(entries),
		"ActiveDays":  days,
		"EventFilter": eventFilter,
	})
}

func (h *Handlers) GetAuditExport(w http.ResponseWriter, r *http.Request) {
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n >= 0 {
			days = n
		}
	}
	eventFilter := r.URL.Query().Get("event")

	entries, err := h.auditQuery(r.Context(), days, eventFilter, "", 0)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
	fmt.Fprintf(w, "date,time,event,user,actor,ip,detail\n")
	for _, e := range entries {
		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(e.Date), csvEscape(e.Time),
			csvEscape(e.Event), csvEscape(e.User),
			csvEscape(e.Actor), csvEscape(e.IP),
			csvEscape(e.Detail),
		)
	}
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func (h *Handlers) GetSettings(w http.ResponseWriter, r *http.Request) {
	get := func(key, fallback string) string {
		return h.settings.Get(r.Context(), key, fallback)
	}
	data := map[string]interface{}{
		"AllowedDomains":             get("allowed_email_domains", h.envDefaults.AllowedDomains),
		"SessionTTL":                 get("session_ttl_hours", intStr(h.envDefaults.SessionTTLHours)),
		"SMTPHost":                   get("smtp_host", h.envSMTP.Host),
		"SMTPPort":                   get("smtp_port", intStr(h.envSMTP.Port)),
		"SMTPUsername":               get("smtp_username", h.envSMTP.Username),
		"SMTPFrom":                   get("smtp_from", h.envSMTP.From),
		"SMTPTLS":                    get("smtp_tls", h.envSMTP.TLS),
		"AuditRetentionDays":         get("audit_retention_days", "90"),
		"RegistrationMode":           get("registration_mode", h.envDefaults.RegistrationMode),
		"RegistrationAllowedDomains": get("registration_allowed_domains", h.envDefaults.RegistrationAllowedDomains),
		"RedirectAllowedHosts":       get("redirect_allowed_hosts", ""),
		"PasswordRequireUppercase":   get("password_require_uppercase", "0") == "1",
		"PasswordRequireNumber":      get("password_require_number", "0") == "1",
		"PasswordRequireSymbol":      get("password_require_symbol", "0") == "1",
		"EmailLogoURL":               get("email_logo_url", ""),
		"EmailSenderName":            get("email_sender_name", ""),
		"EmailAccentColor":           get("email_accent_color", ""),
		"LoginLogoURL":               get("login_logo_url", ""),
		"LoginAppName":               get("login_app_name", ""),
		"LoginTagline":               get("login_tagline", ""),
		"BaseURL":                    h.baseURL,
	}
	if r.URL.Query().Get("saved") == "1" {
		data["Success"] = "Settings saved."
	}
	h.render(w, r, "admin_settings.html", data)
}

func (h *Handlers) PostSettings(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	set := func(key, val string) {
		h.settings.Set(r.Context(), key, strings.TrimSpace(val))
	}
	set("allowed_email_domains", r.FormValue("allowed_email_domains"))
	set("session_ttl_hours", r.FormValue("session_ttl_hours"))
	set("registration_mode", r.FormValue("registration_mode"))
	set("registration_allowed_domains", r.FormValue("registration_allowed_domains"))
	set("redirect_allowed_hosts", r.FormValue("redirect_allowed_hosts"))
	if ml := strings.TrimSpace(r.FormValue("password_min_length")); ml != "" {
		if n, err := strconv.Atoi(ml); err == nil && n >= 8 && n <= 128 {
			h.settings.Set(r.Context(), "password_min_length", ml)
		}
	}
	if r.FormValue("password_require_uppercase") == "1" {
		h.settings.Set(r.Context(), "password_require_uppercase", "1")
	} else {
		h.settings.Set(r.Context(), "password_require_uppercase", "0")
	}
	if r.FormValue("password_require_number") == "1" {
		h.settings.Set(r.Context(), "password_require_number", "1")
	} else {
		h.settings.Set(r.Context(), "password_require_number", "0")
	}
	if r.FormValue("password_require_symbol") == "1" {
		h.settings.Set(r.Context(), "password_require_symbol", "1")
	} else {
		h.settings.Set(r.Context(), "password_require_symbol", "0")
	}
	set("email_logo_url", r.FormValue("email_logo_url"))
	set("email_sender_name", r.FormValue("email_sender_name"))
	set("email_accent_color", r.FormValue("email_accent_color"))
	set("login_logo_url", r.FormValue("login_logo_url"))
	set("login_app_name", r.FormValue("login_app_name"))
	set("login_tagline", r.FormValue("login_tagline"))
	set("smtp_host", r.FormValue("smtp_host"))
	set("smtp_port", r.FormValue("smtp_port"))
	set("smtp_username", r.FormValue("smtp_username"))
	set("smtp_from", r.FormValue("smtp_from"))
	set("smtp_tls", r.FormValue("smtp_tls"))
	if pw := r.FormValue("smtp_password"); pw != "" {
		h.settings.Set(r.Context(), "smtp_password", pw)
	}
	if rd := strings.TrimSpace(r.FormValue("audit_retention_days")); rd != "" {
		if n, err := strconv.Atoi(rd); err == nil && n >= 0 {
			h.settings.Set(r.Context(), "audit_retention_days", rd)
			if n > 0 {
				cutoff := time.Now().AddDate(0, 0, -n).Unix()
				h.db.ExecContext(r.Context(), `DELETE FROM audit_log WHERE created_at < ?`, cutoff)
			}
		}
	}
	http.Redirect(w, r, h.adminBase+"/settings?saved=1", http.StatusSeeOther)
}

func (h *Handlers) GetAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := h.admins.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	currentID := h.adminIDFromRequest(r)
	type row struct {
		ID          string
		Email       string
		DisplayName string
		CreatedAt   string
		IsSelf      bool
	}
	var rows []row
	for _, a := range admins {
		rows = append(rows, row{
			ID:          a.ID,
			Email:       a.Email,
			DisplayName: a.DisplayName,
			CreatedAt:   time.Unix(a.CreatedAt, 0).Format("2006-01-02"),
			IsSelf:      a.ID == currentID,
		})
	}
	h.render(w, r, "admin_admins.html", map[string]interface{}{
		"Admins":     rows,
		"AdminCount": len(rows),
		"Error":      r.URL.Query().Get("err"),
	})
}

func (h *Handlers) PostCreateAdmin(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if email == "" || password == "" {
		http.Redirect(w, r, h.adminBase+"/admins?err=missing", http.StatusSeeOther)
		return
	}
	if password != confirm {
		http.Redirect(w, r, h.adminBase+"/admins?err=mismatch", http.StatusSeeOther)
		return
	}
	if err := h.passwordPolicy(r.Context()).Check(password); err != nil {
		http.Redirect(w, r, h.adminBase+"/admins?err="+encodeMsg(err.Error()), http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Redirect(w, r, h.adminBase+"/admins?err=server", http.StatusSeeOther)
		return
	}
	if err := h.admins.Create(r.Context(), email, hash, displayName); err != nil {
		http.Redirect(w, r, h.adminBase+"/admins?err=exists", http.StatusSeeOther)
		return
	}
	h.auditLog.Log(r.Context(), "admin.admin_created", "", h.adminIDFromRequest(r), r.RemoteAddr, email)
	http.Redirect(w, r, h.adminBase+"/admins", http.StatusSeeOther)
}

func (h *Handlers) PostDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	currentID := h.adminIDFromRequest(r)
	if id == currentID {
		http.Redirect(w, r, h.adminBase+"/admins?err=self", http.StatusSeeOther)
		return
	}
	if h.admins.Count(r.Context()) <= 1 {
		http.Redirect(w, r, h.adminBase+"/admins?err=last", http.StatusSeeOther)
		return
	}
	target, _ := h.admins.GetByID(r.Context(), id)
	if target == nil {
		http.Redirect(w, r, h.adminBase+"/admins", http.StatusSeeOther)
		return
	}
	h.admins.Delete(r.Context(), id)
	h.auditLog.Log(r.Context(), "admin.admin_deleted", "", currentID, r.RemoteAddr, target.Email)
	http.Redirect(w, r, h.adminBase+"/admins", http.StatusSeeOther)
}

func (h *Handlers) PostMakeUserAdmin(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	userID := chi.URLParam(r, "id")
	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil || user == nil {
		http.NotFound(w, r)
		return
	}
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if password == "" {
		http.Redirect(w, r, h.adminBase+"/users/"+userID+"?err=admin_missing", http.StatusSeeOther)
		return
	}
	if password != confirm {
		http.Redirect(w, r, h.adminBase+"/users/"+userID+"?err=admin_mismatch", http.StatusSeeOther)
		return
	}
	if err := h.passwordPolicy(r.Context()).Check(password); err != nil {
		http.Redirect(w, r, h.adminBase+"/users/"+userID+"?err="+encodeMsg(err.Error()), http.StatusSeeOther)
		return
	}
	existing, _ := h.admins.GetByEmail(r.Context(), user.Email)
	if existing != nil {
		http.Redirect(w, r, h.adminBase+"/users/"+userID+"?err=admin_exists", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Redirect(w, r, h.adminBase+"/users/"+userID+"?err=admin_server", http.StatusSeeOther)
		return
	}
	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Email
	}
	if err := h.admins.Create(r.Context(), user.Email, hash, displayName); err != nil {
		http.Redirect(w, r, h.adminBase+"/users/"+userID+"?err=admin_server", http.StatusSeeOther)
		return
	}
	h.auditLog.Log(r.Context(), "admin.admin_created", userID, h.adminIDFromRequest(r), r.RemoteAddr, user.Email)
	http.Redirect(w, r, h.adminBase+"/users/"+userID+"?success=admin_promoted", http.StatusSeeOther)
}

func (h *Handlers) profilePageData(r *http.Request) map[string]interface{} {
	adminID := h.adminIDFromRequest(r)
	admin, _ := h.admins.GetByID(r.Context(), adminID)
	passkeys, _ := h.passkeys.ListCredentials(r.Context(), "admin:"+adminID)
	var totpEnabled bool
	h.db.QueryRowContext(r.Context(), `SELECT totp_enabled FROM admin_users WHERE id=?`, adminID).Scan(&totpEnabled)
	return map[string]interface{}{
		"Admin":        admin,
		"AdminID":      adminID,
		"TOTPEnabled":  totpEnabled,
		"Passkeys":     passkeys,
		"SessionCount": h.adminSess.CountByAdmin(r.Context(), adminID),
		"APIKey":       h.admins.GetAPIKey(r.Context(), adminID),
	}
}

func (h *Handlers) GetProfile(w http.ResponseWriter, r *http.Request) {
	data := h.profilePageData(r)
	if msg := r.URL.Query().Get("success"); msg != "" {
		successMsgs := map[string]string{
			"password":         "Password updated.",
			"display_name":     "Display name updated.",
			"sessions_revoked": "All other sessions have been revoked.",
			"totp_enrolled":    "Authenticator app enrolled.",
			"totp_removed":     "Authenticator app removed.",
			"api_key_rotated":  "API key rotated.",
		}
		if s, ok := successMsgs[msg]; ok {
			data["Success"] = s
		}
	}
	h.render(w, r, "admin_profile.html", data)
}

func (h *Handlers) PostProfileDisplayName(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	name := strings.TrimSpace(r.FormValue("display_name"))
	h.db.ExecContext(r.Context(), `UPDATE admin_users SET display_name=? WHERE id=?`, name, adminID)
	http.Redirect(w, r, h.adminBase+"/profile?success=display_name", http.StatusSeeOther)
}

func (h *Handlers) PostProfileAPIKeyRotate(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	key, err := auth.RandomTokenExport(32)
	if err != nil {
		http.Error(w, "failed to generate key", http.StatusInternalServerError)
		return
	}
	if err := h.admins.SetAPIKey(r.Context(), adminID, key); err != nil {
		http.Error(w, "failed to save key", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.adminBase+"/profile?success=api_key_rotated", http.StatusSeeOther)
}

func (h *Handlers) PostProfileRevokeSessions(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	cookie, _ := r.Cookie(adminCookieName)
	currentSessID := ""
	if cookie != nil {
		currentSessID = cookie.Value
	}
	h.adminSess.DestroyAllExcept(r.Context(), adminID, currentSessID)
	http.Redirect(w, r, h.adminBase+"/profile?success=sessions_revoked", http.StatusSeeOther)
}

func (h *Handlers) PostProfilePassword(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	admin, err := h.admins.GetByID(r.Context(), adminID)
	if err != nil || admin == nil {
		http.Redirect(w, r, h.adminBase+"/login", http.StatusFound)
		return
	}
	current := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	if auth.VerifyPassword(current, admin.PasswordHash) != nil {
		data := h.profilePageData(r)
		data["Error"] = "Current password is incorrect"
		h.render(w, r, "admin_profile.html", data)
		return
	}
	if newPass != confirm {
		data := h.profilePageData(r)
		data["Error"] = "Passwords do not match"
		h.render(w, r, "admin_profile.html", data)
		return
	}
	if err := h.passwordPolicy(r.Context()).Check(newPass); err != nil {
		data := h.profilePageData(r)
		data["Error"] = err.Error()
		h.render(w, r, "admin_profile.html", data)
		return
	}
	hash, err := auth.HashPassword(newPass)
	if err != nil {
		data := h.profilePageData(r)
		data["Error"] = err.Error()
		h.render(w, r, "admin_profile.html", data)
		return
	}
	h.db.ExecContext(r.Context(), `UPDATE admin_users SET password_hash=? WHERE id=?`, hash, adminID)
	http.Redirect(w, r, h.adminBase+"/profile?success=password", http.StatusSeeOther)
}

func (h *Handlers) GetProfileTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	adminID := h.adminIDFromRequest(r)
	admin, _ := h.admins.GetByID(r.Context(), adminID)
	email := ""
	if admin != nil {
		email = admin.Email
	}
	key, err := auth.GenerateSecret("GateKeeper Admin", email)
	if err != nil {
		http.Error(w, "TOTP generation failed", http.StatusInternalServerError)
		return
	}
	png, err := auth.QRCodePNG(key)
	if err != nil {
		http.Error(w, "QR code generation failed", http.StatusInternalServerError)
		return
	}
	data := h.profilePageData(r)
	data["EnrollTOTP"] = true
	data["Secret"] = key.Secret()
	data["QRCodeB64"] = base64.StdEncoding.EncodeToString(png)
	h.render(w, r, "admin_profile.html", data)
}

func (h *Handlers) PostProfileTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	secret := r.FormValue("secret")
	code := strings.TrimSpace(r.FormValue("code"))
	_, err := h.totp.ConfirmEnrollment(r.Context(), "admin:"+adminID, secret, code)
	if err != nil {
		data := h.profilePageData(r)
		data["EnrollTOTP"] = true
		data["Secret"] = secret
		data["Error"] = err.Error()
		h.render(w, r, "admin_profile.html", data)
		return
	}
	h.db.ExecContext(r.Context(), `UPDATE admin_users SET totp_enabled=1 WHERE id=?`, adminID)
	http.Redirect(w, r, h.adminBase+"/profile?success=totp_enrolled", http.StatusSeeOther)
}

func (h *Handlers) PostProfileTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	code := strings.TrimSpace(r.FormValue("code"))
	if err := h.totp.Validate(r.Context(), "admin:"+adminID, code); err != nil {
		data := h.profilePageData(r)
		data["Error"] = "Invalid code"
		h.render(w, r, "admin_profile.html", data)
		return
	}
	h.totp.Revoke(r.Context(), "admin:"+adminID)
	h.db.ExecContext(r.Context(), `UPDATE admin_users SET totp_enabled=0 WHERE id=?`, adminID)
	http.Redirect(w, r, h.adminBase+"/profile?success=totp_removed", http.StatusSeeOther)
}

func (h *Handlers) GetProfilePasskey(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin_profile.html", map[string]interface{}{"RegisterPasskey": true})
}

func (h *Handlers) PostProfilePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	adminID := h.adminIDFromRequest(r)
	admin, _ := h.admins.GetByID(r.Context(), adminID)
	if admin == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	waUser, err := h.passkeys.LoadUser(r.Context(), "admin:"+adminID, admin.Email)
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
	h.passkeys.SaveSession(r.Context(), sessID, &adminID, session)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Passkey-Session", sessID)
	json.NewEncoder(w).Encode(options)
}

func (h *Handlers) PostProfilePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	adminID := h.adminIDFromRequest(r)
	admin, _ := h.admins.GetByID(r.Context(), adminID)
	if admin == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sessID := r.Header.Get("X-Passkey-Session")
	sessionData, err := h.passkeys.GetSession(r.Context(), sessID)
	if err != nil {
		http.Error(w, "session expired", http.StatusBadRequest)
		return
	}
	waUser, err := h.passkeys.LoadUser(r.Context(), "admin:"+adminID, admin.Email)
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
		name = "Admin passkey"
	}
	h.passkeys.RegisterCredential(r.Context(), "admin:"+adminID, name, cred)
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) PostProfilePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	id := chi.URLParam(r, "id")
	h.passkeys.DeleteCredential(r.Context(), "admin:"+adminID, id)
	h.auditLog.Log(r.Context(), audit.EventPasskeyRevoked, adminID, "", r.RemoteAddr, "")
	http.Redirect(w, r, h.adminBase+"/profile", http.StatusFound)
}

func (h *Handlers) GetPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.policies.List(r.Context())
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	type PolicyWithClients struct {
		queries.Policy
		Clients []string
	}
	var enriched []PolicyWithClients
	for _, p := range policies {
		rows, _ := h.db.QueryContext(r.Context(), `SELECT name FROM oidc_clients WHERE policy_id=?`, p.ID)
		var clients []string
		if rows != nil {
			for rows.Next() {
				var name string
				rows.Scan(&name)
				clients = append(clients, name)
			}
			rows.Close()
		}
		enriched = append(enriched, PolicyWithClients{Policy: p, Clients: clients})
	}
	h.render(w, r, "admin_policies.html", map[string]interface{}{"Policies": enriched, "BaseURL": h.baseURL})
}

func (h *Handlers) PostCreatePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))
	if name == "" {
		http.Redirect(w, r, h.adminBase+"/policies", http.StatusFound)
		return
	}
	if err := h.policies.Create(r.Context(), name, description); err != nil {
		http.Error(w, "Could not create policy: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pol, _ := h.policies.GetByName(r.Context(), name)
	if pol != nil {
		http.Redirect(w, r, h.adminBase+"/policies/"+pol.ID, http.StatusFound)
		return
	}
	http.Redirect(w, r, h.adminBase+"/policies", http.StatusFound)
}

func (h *Handlers) GetPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	pol, err := h.policies.GetByID(r.Context(), id)
	if err != nil || pol == nil {
		http.NotFound(w, r)
		return
	}
	members, _ := h.policies.GetMembers(r.Context(), id)
	allUsers, _ := h.users.List(r.Context())
	memberSet := map[string]bool{}
	for _, m := range members {
		memberSet[m.ID] = true
	}
	var nonMembers []queries.User
	for _, u := range allUsers {
		if !memberSet[u.ID] {
			nonMembers = append(nonMembers, u)
		}
	}
	clientRows, _ := h.db.QueryContext(r.Context(), `SELECT name FROM oidc_clients WHERE policy_id=?`, id)
	var clientNames []string
	if clientRows != nil {
		for clientRows.Next() {
			var name string
			clientRows.Scan(&name)
			clientNames = append(clientNames, name)
		}
		clientRows.Close()
	}
	var injectUsername string
	h.db.QueryRowContext(r.Context(), `SELECT inject_username FROM policies WHERE id=?`, id).Scan(&injectUsername)
	h.render(w, r, "admin_policy_detail.html", map[string]interface{}{
		"Policy":         pol,
		"Members":        members,
		"NonMembers":     nonMembers,
		"Clients":        clientNames,
		"BaseURL":        h.baseURL,
		"InjectUsername": injectUsername,
	})
}

func (h *Handlers) PostDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.policies.Delete(r.Context(), id)
	http.Redirect(w, r, h.adminBase+"/policies", http.StatusFound)
}

func (h *Handlers) PostAddPolicyMember(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	userID := strings.TrimSpace(r.FormValue("user_id"))
	if userID != "" {
		h.policies.AddMember(r.Context(), id, userID)
	}
	http.Redirect(w, r, h.adminBase+"/policies/"+id, http.StatusFound)
}

func (h *Handlers) PostRemovePolicyMember(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "userID")
	h.policies.RemoveMember(r.Context(), id, userID)
	http.Redirect(w, r, h.adminBase+"/policies/"+id, http.StatusFound)
}

func (h *Handlers) PostPolicyInject(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	username := strings.TrimSpace(r.FormValue("inject_username"))
	password := strings.TrimSpace(r.FormValue("inject_password"))
	if username == "" {
		h.db.ExecContext(r.Context(), `UPDATE policies SET inject_username='', inject_password='' WHERE id=?`, id)
		http.Redirect(w, r, h.adminBase+"/policies/"+id, http.StatusFound)
		return
	}
	var encPass string
	if password != "" {
		enc, err := auth.EncryptSecret([]byte(password), []byte(h.secretKey))
		if err != nil {
			http.Error(w, "Encryption error", http.StatusInternalServerError)
			return
		}
		encPass = enc
	} else {
		h.db.QueryRowContext(r.Context(), `SELECT inject_password FROM policies WHERE id=?`, id).Scan(&encPass)
	}
	h.db.ExecContext(r.Context(), `UPDATE policies SET inject_username=?, inject_password=? WHERE id=?`, username, encPass, id)
	http.Redirect(w, r, h.adminBase+"/policies/"+id, http.StatusFound)
}

func (h *Handlers) PostPolicyInjectClear(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.db.ExecContext(r.Context(), `UPDATE policies SET inject_username='', inject_password='' WHERE id=?`, id)
	http.Redirect(w, r, h.adminBase+"/policies/"+id, http.StatusFound)
}

func (h *Handlers) GetInvites(w http.ResponseWriter, r *http.Request) {
	invites, _ := h.invites.List(r.Context())
	h.render(w, r, "admin_invites.html", map[string]interface{}{
		"Invites": invites,
		"BaseURL": h.baseURL,
	})
}

func (h *Handlers) PostCreateInvite(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	note := strings.TrimSpace(r.FormValue("note"))
	expiryDays := 7
	if d := r.FormValue("expiry_days"); d != "" {
		if n, err := fmt.Sscanf(d, "%d", &expiryDays); n == 0 || err != nil || expiryDays < 1 {
			expiryDays = 7
		}
	}
	adminID := h.adminIDFromRequest(r)
	token, err := h.invites.Create(r.Context(), email, note, adminID, expiryDays)
	if err != nil {
		http.Error(w, "Could not create invite", http.StatusInternalServerError)
		return
	}
	h.auditLog.Log(r.Context(), "invite.created", "", adminID, r.RemoteAddr, email)
	inviteURL := h.baseURL + "/register?invite=" + token
	h.render(w, r, "admin_invites.html", map[string]interface{}{
		"Invites": func() []queries.Invite { inv, _ := h.invites.List(r.Context()); return inv }(),
		"NewLink": inviteURL,
		"BaseURL": h.baseURL,
	})
}

func (h *Handlers) PostRevokeInvite(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.invites.Revoke(r.Context(), id)
	h.auditLog.Log(r.Context(), "invite.revoked", "", "", r.RemoteAddr, id)
	http.Redirect(w, r, h.adminBase+"/invites", http.StatusFound)
}

func (h *Handlers) GetGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.groups.List(r.Context())
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	h.render(w, r, "admin_groups.html", map[string]interface{}{"Groups": groups})
}

func (h *Handlers) PostCreateGroup(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))
	if name == "" {
		http.Redirect(w, r, h.adminBase+"/groups", http.StatusFound)
		return
	}
	if err := h.groups.Create(r.Context(), name, description); err != nil {
		http.Error(w, "Could not create group: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog.Log(r.Context(), "group.created", "", "", r.RemoteAddr, name)
	http.Redirect(w, r, h.adminBase+"/groups", http.StatusFound)
}

func (h *Handlers) GetGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	group, err := h.groups.GetByID(r.Context(), id)
	if err != nil || group == nil {
		http.NotFound(w, r)
		return
	}
	members, _ := h.groups.GetMembers(r.Context(), id)
	nonMembers, _ := h.groups.ListNotMember(r.Context(), id)
	h.render(w, r, "admin_group_detail.html", map[string]interface{}{
		"Group":      group,
		"Members":    members,
		"NonMembers": nonMembers,
	})
}

func (h *Handlers) PostDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	gr, _ := h.groups.GetByID(r.Context(), id)
	h.groups.Delete(r.Context(), id)
	if gr != nil {
		h.auditLog.Log(r.Context(), "group.deleted", "", "", r.RemoteAddr, gr.Name)
	}
	http.Redirect(w, r, h.adminBase+"/groups", http.StatusFound)
}

func (h *Handlers) PostAddGroupMember(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	userID := strings.TrimSpace(r.FormValue("user_id"))
	if userID != "" {
		h.groups.AddMember(r.Context(), id, userID)
		h.auditLog.Log(r.Context(), "group.member_added", userID, "", r.RemoteAddr, id)
	}
	http.Redirect(w, r, h.adminBase+"/groups/"+id, http.StatusFound)
}

func (h *Handlers) PostRemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "userID")
	h.groups.RemoveMember(r.Context(), id, userID)
	h.auditLog.Log(r.Context(), "group.member_removed", userID, "", r.RemoteAddr, id)
	http.Redirect(w, r, h.adminBase+"/groups/"+id, http.StatusFound)
}

func (h *Handlers) PostAddUserToGroup(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	userID := chi.URLParam(r, "id")
	groupID := chi.URLParam(r, "groupID")
	h.groups.AddMember(r.Context(), groupID, userID)
	h.auditLog.Log(r.Context(), "group.member_added", userID, "", r.RemoteAddr, groupID)
	http.Redirect(w, r, h.adminBase+"/users/"+userID, http.StatusFound)
}

func (h *Handlers) PostRemoveUserFromGroup(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	userID := chi.URLParam(r, "id")
	groupID := chi.URLParam(r, "groupID")
	h.groups.RemoveMember(r.Context(), groupID, userID)
	h.auditLog.Log(r.Context(), "group.member_removed", userID, "", r.RemoteAddr, groupID)
	http.Redirect(w, r, h.adminBase+"/users/"+userID, http.StatusFound)
}

// GetWebhooks renders the webhooks management page.
func (h *Handlers) GetWebhooks(w http.ResponseWriter, r *http.Request) {
	whs, _ := h.webhooks.ListWebhooks(r.Context())
	h.render(w, r, "admin_webhooks.html", map[string]interface{}{"Webhooks": whs})
}

// PostCreateWebhook creates a new webhook.
func (h *Handlers) PostCreateWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	whType := r.FormValue("type")
	whURL := strings.TrimSpace(r.FormValue("url"))
	if whType == "email" {
		whURL = strings.TrimSpace(r.FormValue("email_to"))
	}
	wh := queries.Webhook{
		Name:     strings.TrimSpace(r.FormValue("name")),
		Type:     whType,
		URL:      whURL,
		Token:    strings.TrimSpace(r.FormValue("token")),
		ChatID:   strings.TrimSpace(r.FormValue("chat_id")),
		Username: strings.TrimSpace(r.FormValue("username")),
		Password: strings.TrimSpace(r.FormValue("password")),
		Topic:    strings.TrimSpace(r.FormValue("topic")),
		Events:   r.FormValue("events"),
	}
	if wh.Events == "" {
		wh.Events = "all"
	}
	h.webhooks.CreateWebhook(r.Context(), wh)
	http.Redirect(w, r, h.adminBase+"/webhooks", http.StatusFound)
}

// PostEditWebhook updates an existing webhook.
func (h *Handlers) PostEditWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	events := r.FormValue("events")
	if events == "" {
		events = "all"
	}
	editType := r.FormValue("type")
	editURL := strings.TrimSpace(r.FormValue("url"))
	if editType == "email" {
		editURL = strings.TrimSpace(r.FormValue("email_to"))
	}
	wh := queries.Webhook{
		ID:       id,
		Name:     strings.TrimSpace(r.FormValue("name")),
		Type:     editType,
		URL:      editURL,
		Token:    strings.TrimSpace(r.FormValue("token")),
		ChatID:   strings.TrimSpace(r.FormValue("chat_id")),
		Username: strings.TrimSpace(r.FormValue("username")),
		Password: strings.TrimSpace(r.FormValue("password")),
		Topic:    strings.TrimSpace(r.FormValue("topic")),
		Events:   events,
	}
	h.webhooks.UpdateWebhook(r.Context(), wh)
	http.Redirect(w, r, h.adminBase+"/webhooks", http.StatusFound)
}

// PostDeleteWebhook removes a webhook.
func (h *Handlers) PostDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h.webhooks.DeleteWebhook(r.Context(), chi.URLParam(r, "id"))
	http.Redirect(w, r, h.adminBase+"/webhooks", http.StatusFound)
}

// PostToggleWebhook toggles the enabled state of a webhook.
func (h *Handlers) PostToggleWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	wh, _ := h.webhooks.GetWebhook(r.Context(), id)
	if wh != nil {
		h.webhooks.SetEnabled(r.Context(), id, !wh.Enabled)
	}
	http.Redirect(w, r, h.adminBase+"/webhooks", http.StatusFound)
}

// PostTestWebhook sends a test notification to a webhook.
func (h *Handlers) PostTestWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	err := h.notifier.SendTest(r.Context(), id)
	whs, _ := h.webhooks.ListWebhooks(r.Context())
	if err != nil {
		h.render(w, r, "admin_webhooks.html", map[string]interface{}{"Webhooks": whs, "TestError": err.Error(), "TestedID": id})
		return
	}
	h.render(w, r, "admin_webhooks.html", map[string]interface{}{"Webhooks": whs, "TestOK": true, "TestedID": id})
}

// GetNotifications renders the notification log page and resets the unread counter.
func (h *Handlers) GetNotifications(w http.ResponseWriter, r *http.Request) {
	now := fmt.Sprintf("%d", time.Now().Unix())
	h.settings.Set(r.Context(), "notifications_last_viewed", now)
	raw, _ := h.webhooks.ListNotifications(r.Context(), 200)
	type NotifRow struct {
		Event       string
		User        string
		IP          string
		Method      string
		MethodClass string
		Category    string
		Time        string
	}
	var rows []NotifRow
	for _, n := range raw {
		user := n.UserID
		if user != "" {
			var display string
			h.db.QueryRowContext(r.Context(), `SELECT COALESCE(NULLIF(display_name,''), email) FROM users WHERE id=?`, user).Scan(&display)
			if display != "" {
				user = display
			}
		}
		method, methodClass := loginMethod(n.Event)
		rows = append(rows, NotifRow{
			Event:       n.Event,
			User:        user,
			IP:          n.IP,
			Method:      method,
			MethodClass: methodClass,
			Category:    eventCategory(n.Event),
			Time:        time.Unix(n.CreatedAt, 0).Format("15:04:05"),
		})
	}
	h.render(w, r, "admin_notifications.html", map[string]interface{}{"Notifications": rows})
}

func (h *Handlers) GetSocialSettings(w http.ResponseWriter, r *http.Request) {
	get := func(key, fallback string) string {
		return h.settings.Get(r.Context(), key, fallback)
	}
	data := map[string]interface{}{
		"BaseURL":         h.baseURL,
		"GitHubEnabled":   get("social_github_enabled", "0"),
		"GitHubClientID":  get("social_github_client_id", h.envDefaults.GitHubClientID),
		"GoogleEnabled":   get("social_google_enabled", "0"),
		"GoogleClientID":  get("social_google_client_id", h.envDefaults.GoogleClientID),
		"DiscordEnabled":  get("social_discord_enabled", "0"),
		"DiscordClientID": get("social_discord_client_id", h.envDefaults.DiscordClientID),
	}
	if r.URL.Query().Get("saved") == "1" {
		data["Success"] = "Settings saved."
	}
	h.render(w, r, "admin_social.html", data)
}

func (h *Handlers) PostSocialSettings(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	set := func(key, val string) {
		h.settings.Set(r.Context(), key, strings.TrimSpace(val))
	}
	boolField := func(key string) string {
		if r.FormValue(key) == "1" {
			return "1"
		}
		return "0"
	}
	set("social_github_enabled", boolField("social_github_enabled"))
	set("social_github_client_id", r.FormValue("social_github_client_id"))
	if v := r.FormValue("social_github_client_secret"); v != "" {
		set("social_github_client_secret", v)
	}
	set("social_google_enabled", boolField("social_google_enabled"))
	set("social_google_client_id", r.FormValue("social_google_client_id"))
	if v := r.FormValue("social_google_client_secret"); v != "" {
		set("social_google_client_secret", v)
	}
	set("social_discord_enabled", boolField("social_discord_enabled"))
	set("social_discord_client_id", r.FormValue("social_discord_client_id"))
	if v := r.FormValue("social_discord_client_secret"); v != "" {
		set("social_discord_client_secret", v)
	}
	http.Redirect(w, r, h.adminBase+"/social?saved=1", http.StatusSeeOther)
}

func (h *Handlers) GetNotificationsAPI(w http.ResponseWriter, r *http.Request) {
	notifs, _ := h.webhooks.ListNotifications(r.Context(), 8)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifs)
}

func (h *Handlers) cachedHasUpdate(ctx context.Context) bool {
	h.updateCache.mu.Lock()
	defer h.updateCache.mu.Unlock()
	if h.updateCache.result != nil && time.Since(h.updateCache.fetchedAt) < time.Hour {
		return h.updateCache.result.HasUpdate
	}
	return false
}

// GetVersionCheck returns the current and latest release versions, cached for 1 hour.
func (h *Handlers) GetVersionCheck(w http.ResponseWriter, r *http.Request) {
	h.updateCache.mu.Lock()
	defer h.updateCache.mu.Unlock()

	if h.updateCache.result != nil && time.Since(h.updateCache.fetchedAt) < time.Hour {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.updateCache.result)
		return
	}

	result := &updateResult{Current: h.version}

	if strings.Contains(h.version, "dev") {
		h.updateCache.result = result
		h.updateCache.fetchedAt = time.Now()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequestWithContext(r.Context(), "GET",
		"https://api.github.com/repos/chr0nzz/gatekeeper/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var gh struct {
			TagName string `json:"tag_name"`
			HTMLURL string `json:"html_url"`
			Body    string `json:"body"`
		}
		if json.NewDecoder(resp.Body).Decode(&gh) == nil {
			result.Latest = strings.TrimPrefix(gh.TagName, "v")
			result.URL = gh.HTMLURL
			result.Body = gh.Body
			result.HasUpdate = compareVersions(result.Latest, result.Current) > 0
		}
	}

	h.updateCache.result = result
	h.updateCache.fetchedAt = time.Now()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var va, vb int
		if i < len(pa) {
			fmt.Sscanf(pa[i], "%d", &va)
		}
		if i < len(pb) {
			fmt.Sscanf(pb[i], "%d", &vb)
		}
		if va != vb {
			if va > vb {
				return 1
			}
			return -1
		}
	}
	return 0
}

func intStr(n int) string {
	if n == 0 {
		return "587"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
