package admin

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/chr0nzz/gatekeeper/internal/audit"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"github.com/chr0nzz/gatekeeper/internal/db/queries"
	"github.com/chr0nzz/gatekeeper/internal/mailer"
	gkmiddleware "github.com/chr0nzz/gatekeeper/internal/middleware"
	oidcstore "github.com/chr0nzz/gatekeeper/internal/oidc"
	"github.com/chr0nzz/gatekeeper/internal/templates"
)

const adminCookieName = "gk_admin"

// Handlers holds all admin handler dependencies.
type Handlers struct {
	db          *sql.DB
	users       *queries.UserStore
	admins      *queries.AdminStore
	adminSess   *queries.AdminSessionStore
	sessions       *auth.SessionStore
	totp           *auth.TOTPStore
	passkeys       *auth.PasskeyStore
	trustedDevices *auth.TrustedDeviceStore
	oidcStorage *oidcstore.Storage
	mailer      *mailer.Mailer
	resetStore  *auth.PasswordResetStore
	settings    *queries.SettingsStore
	auditLog    *audit.Logger
	renderer    *templates.Renderer
	baseURL     string
	version     string
	envSMTP     mailer.Settings
	envDefaults EnvDefaults
}

// EnvDefaults holds env var fallback values for settings that are managed in the UI.
type EnvDefaults struct {
	AllowedDomains  string
	SessionTTLHours int
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
	baseURL, version string,
	envSMTP mailer.Settings,
	envDefaults EnvDefaults,
) *Handlers {
	return &Handlers{
		db: db, users: users, admins: admins, adminSess: adminSess,
		sessions: sessions, totp: totp, passkeys: passkeys,
		trustedDevices: trustedDevices,
		oidcStorage: oidcStorage, mailer: m, resetStore: resetStore,
		settings: settings, auditLog: auditLog, renderer: renderer,
		baseURL: baseURL, version: version, envSMTP: envSMTP, envDefaults: envDefaults,
	}
}

func (h *Handlers) adminIDFromRequest(r *http.Request) string {
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
			http.Redirect(w, r, "/admin/setup", http.StatusFound)
			return
		}
		if h.adminIDFromRequest(r) == "" {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handlers) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["CSRFToken"] = h.csrfToken(r)
	data["ActivePage"] = activePageFor(name)
	data["AdminEmail"] = h.adminEmailFromRequest(r)
	data["AppVersion"] = h.version
	var userCount, clientCount int
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users`).Scan(&userCount)
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM oidc_clients`).Scan(&clientCount)
	data["SidebarUserCount"] = userCount
	data["SidebarClientCount"] = clientCount
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
	case "admin_clients.html":
		return "clients"
	case "admin_audit.html":
		return "audit"
	case "admin_settings.html":
		return "settings"
	case "admin_profile.html":
		return "profile"
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
	r.Post("/logout", h.PostLogout)

	r.Group(func(r chi.Router) {
		r.Use(h.requireAdmin)
		r.Get("/", h.GetDashboard)
		r.Get("/api/activity", h.GetActivityData)
		r.Get("/api/search", h.GetSearch)
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
		r.Get("/clients", h.GetClients)
		r.Post("/clients", h.PostCreateClient)
		r.Post("/clients/{id}/delete", h.PostDeleteClient)
		r.Post("/clients/{id}/edit", h.PostEditClient)
		r.Get("/clients/{id}/icon", h.GetClientIcon)
		r.Get("/audit", h.GetAudit)
		r.Get("/settings", h.GetSettings)
		r.Post("/settings", h.PostSettings)
		r.Get("/profile", h.GetProfile)
		r.Post("/profile/password", h.PostProfilePassword)
		r.Get("/profile/totp/enroll", h.GetProfileTOTPEnroll)
		r.Post("/profile/totp/enroll", h.PostProfileTOTPEnroll)
		r.Post("/profile/totp/disable", h.PostProfileTOTPDisable)
		r.Get("/profile/passkey", h.GetProfilePasskey)
		r.Post("/profile/passkey/begin", h.PostProfilePasskeyBegin)
		r.Post("/profile/passkey/finish", h.PostProfilePasskeyFinish)
	})
}

func (h *Handlers) GetSetup(w http.ResponseWriter, r *http.Request) {
	if h.admins.Exists(r.Context()) {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}
	h.render(w, r, "admin_setup.html", nil)
}

func (h *Handlers) PostSetup(w http.ResponseWriter, r *http.Request) {
	if h.admins.Exists(r.Context()) {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if password != confirm {
		h.render(w, r, "admin_setup.html", map[string]interface{}{"Error": "Passwords do not match"})
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		h.render(w, r, "admin_setup.html", map[string]interface{}{"Error": err.Error()})
		return
	}
	if err := h.admins.Create(r.Context(), email, hash); err != nil {
		h.render(w, r, "admin_setup.html", map[string]interface{}{"Error": "Could not create admin: " + err.Error()})
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (h *Handlers) GetLogin(w http.ResponseWriter, r *http.Request) {
	if !h.admins.Exists(r.Context()) {
		http.Redirect(w, r, "/admin/setup", http.StatusFound)
		return
	}
	h.render(w, r, "admin_login.html", nil)
}

func (h *Handlers) PostLogin(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	admin, err := h.admins.GetByEmail(r.Context(), email)
	if err != nil || admin == nil || auth.VerifyPassword(password, admin.PasswordHash) != nil {
		h.render(w, r, "admin_login.html", map[string]interface{}{"Error": "Invalid credentials"})
		return
	}

	sessID, err := h.adminSess.Create(r.Context(), admin.ID)
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    sessID,
		Path:     "/admin",
		MaxAge:   8 * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (h *Handlers) PostLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(adminCookieName)
	if err == nil {
		h.adminSess.Destroy(r.Context(), cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: "", MaxAge: -1, Path: "/admin"})
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (h *Handlers) GetDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since24h := time.Now().Add(-24 * time.Hour).Unix()
	now := time.Now().Unix()

	var totalUsers, activeUsers, oidcClients int
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&totalUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE disabled=0`).Scan(&activeUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_clients`).Scan(&oidcClients)

	var signIns24h, failed24h, oidcTokens24h, totalAttempts, lockedUsers, no2faUsers int
	var passkeyLogins, totpLogins, otpLogins int
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event IN ('login.success','login.passkey') AND created_at > ?`, since24h).Scan(&signIns24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE (event LIKE '%fail%' OR event LIKE '%failure%') AND created_at > ?`, since24h).Scan(&failed24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_tokens WHERE created_at > ?`, since24h).Scan(&oidcTokens24h)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event IN ('login.success','login.passkey','login.failure') AND created_at > ?`, since24h).Scan(&totalAttempts)
	h.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_id) FROM otp_lockouts WHERE locked_until > ?`, now).Scan(&lockedUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE disabled=0 AND totp_enabled=0`).Scan(&no2faUsers)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event='login.passkey' AND created_at > ?`, since24h).Scan(&passkeyLogins)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event='totp.verified' AND created_at > ?`, since24h).Scan(&totpLogins)
	h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE event='otp.verified' AND created_at > ?`, since24h).Scan(&otpLogins)

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
		{"OIDC token", "clients", pct(oidcTokens24h)},
	}

	type RecentEvent struct {
		Event  string
		User   string
		Detail string
		Time   string
		Kind   string
	}
	rows, _ := h.db.QueryContext(ctx,
		`SELECT a.event, COALESCE(u.email, a.user_id, ''), COALESCE(a.detail,''), a.created_at
		 FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
		 ORDER BY a.created_at DESC LIMIT 8`,
	)
	var recentEvents []RecentEvent
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e RecentEvent
			var ts int64
			rows.Scan(&e.Event, &e.User, &e.Detail, &ts)
			e.Time = time.Unix(ts, 0).Format("15:04:05")
			e.Kind = eventKind(e.Event)
			recentEvents = append(recentEvents, e)
		}
	}

	h.render(w, r, "admin_dashboard.html", map[string]interface{}{
		"TotalUsers":    totalUsers,
		"ActiveUsers":   activeUsers,
		"LockedUsers":   lockedUsers,
		"No2FAUsers":    no2faUsers,
		"OIDCClients":   oidcClients,
		"SignIns24h":    signIns24h,
		"Failed24h":     failed24h,
		"OIDCTokens24h": oidcTokens24h,
		"SuccessRate":   successRate,
		"RecentEvents":  recentEvents,
		"AuthMethods":   authMethods,
		"HasAuthData":   totalMethods > 0,
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
		 WHERE event IN ('login.success','login.passkey','login.failure','otp.failed','totp.failed')
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
			`SELECT id, email FROM users WHERE email LIKE ? LIMIT 8`,
			like,
		)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, email string
				rows.Scan(&id, &email)
				results = append(results, Result{Label: email, Sub: id, Icon: "user", URL: "/admin/users/" + id})
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
				results = append(results, Result{Label: name, Sub: id, Icon: "clients", URL: "/admin/clients"})
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
	case strings.Contains(event, "disabled") || strings.Contains(event, "revoked"):
		return "warn"
	case strings.Contains(event, "success") || strings.Contains(event, "passkey") || strings.Contains(event, "enrolled") || strings.Contains(event, "created") || strings.Contains(event, "verified") || strings.Contains(event, "changed") || strings.Contains(event, "registered"):
		return "ok"
	default:
		return "info"
	}
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

		initials := strings.ToUpper(u.Email[:1])
		if at := strings.Index(u.Email, "@"); at > 1 {
			initials = strings.ToUpper(u.Email[:2])
		}
		status := "active"
		if u.Disabled {
			status = "disabled"
		} else if isLocked {
			status = "locked"
		}
		rows = append(rows, UserRow{User: u, Sessions: sessions, IsLocked: isLocked, Initials: initials, Status: status})
	}
	active := 0
	locked := 0
	disabled := 0
	no2fa := 0
	for _, r := range rows {
		switch r.Status {
		case "active":
			active++
		case "locked":
			locked++
		case "disabled":
			disabled++
		}
		if !r.TOTPEnabled {
			no2fa++
		}
	}
	h.render(w, r, "admin_users.html", map[string]interface{}{
		"Users":    rows,
		"Total":    len(rows),
		"Active":   active,
		"Locked":   locked,
		"Disabled": disabled,
		"No2FA":    no2fa,
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
		if len(password) < 12 {
			h.render(w, r, "admin_user_new.html", map[string]interface{}{"Error": "Password must be at least 12 characters."})
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
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (h *Handlers) renderUserListWithError(w http.ResponseWriter, r *http.Request, msg string) {
	users, _ := h.users.List(r.Context())
	h.render(w, r, "admin_users.html", map[string]interface{}{"Users": users, "Error": msg})
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

	h.render(w, r, "admin_user_detail.html", map[string]interface{}{
		"User":          UserDetail{User: user, Initials: initials, Sessions: sessions, Locked: isLocked, LastSeen: ""},
		"Passkeys":      passkeys,
		"RecoveryCodes": recoveryCodes,
	})
}

func (h *Handlers) PostSetPassword(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	password := r.FormValue("password")
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
	http.Redirect(w, r, "/admin/users/"+id, http.StatusFound)
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
	http.Redirect(w, r, "/admin/users/"+id, http.StatusFound)
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
	http.Redirect(w, r, "/admin/users", http.StatusFound)
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
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (h *Handlers) PostDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	h.sessions.RevokeAll(r.Context(), id)
	h.trustedDevices.RevokeAll(r.Context(), id)
	h.users.Delete(r.Context(), id)
	http.Redirect(w, r, "/admin/users", http.StatusFound)
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
	http.Redirect(w, r, "/admin/users/"+id, http.StatusFound)
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
	http.Redirect(w, r, "/admin/users/"+id, http.StatusFound)
}

func (h *Handlers) PostTogglePasswordless(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	enabled := r.FormValue("enabled") == "1"
	h.users.SetPasswordless(r.Context(), id, enabled)
	http.Redirect(w, r, "/admin/users/"+id, http.StatusFound)
}

func (h *Handlers) GetClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.oidcStorage.ListClients(r.Context())
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	h.render(w, r, "admin_clients.html", map[string]interface{}{"Clients": clients, "BaseURL": h.baseURL})
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
	urisRaw := strings.TrimSpace(r.FormValue("redirect_uris"))
	var uris []string
	for _, u := range strings.Split(urisRaw, "\n") {
		u = strings.TrimSpace(u)
		if u != "" {
			uris = append(uris, u)
		}
	}
	if err := h.oidcStorage.CreateClient(r.Context(), clientID, clientSecret, name, iconURL, uris); err != nil {
		clients, _ := h.oidcStorage.ListClients(r.Context())
		h.render(w, r, "admin_clients.html", map[string]interface{}{"Clients": clients, "Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusFound)
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
	http.Redirect(w, r, "/admin/clients", http.StatusFound)
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
	var uris []string
	for _, u := range strings.Split(urisRaw, "\n") {
		if u = strings.TrimSpace(u); u != "" {
			uris = append(uris, u)
		}
	}
	h.oidcStorage.UpdateClient(r.Context(), id, name, iconURL, newSecret, uris)
	http.Redirect(w, r, "/admin/clients", http.StatusFound)
}

func (h *Handlers) GetAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT a.event,
			COALESCE(u.email, a.user_id, ''),
			COALESCE(act.email, aa.email, a.actor_id, ''),
			COALESCE(a.ip,''), COALESCE(a.detail,''), a.created_at
		FROM audit_log a
		LEFT JOIN users u ON u.id = a.user_id
		LEFT JOIN admin_users aa ON aa.id = a.actor_id
		LEFT JOIN users act ON act.id = a.actor_id
		ORDER BY a.created_at DESC LIMIT 500`,
	)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type AuditEntry struct {
		Event       string
		User        string
		Actor       string
		IP          string
		Detail      string
		Time        string
		Date        string
		Kind        string
		EventPrefix string
	}
	type AuditGroup struct {
		Date    string
		Entries []AuditEntry
	}

	var groups []AuditGroup
	groupIdx := map[string]int{}
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	for rows.Next() {
		var e AuditEntry
		var ts int64
		rows.Scan(&e.Event, &e.User, &e.Actor, &e.IP, &e.Detail, &ts)
		t := time.Unix(ts, 0)
		e.Time = t.Format("15:04:05")
		e.Kind = eventKind(e.Event)
		e.EventPrefix = eventCategory(e.Event)
		rawDate := t.Format("2006-01-02")
		switch rawDate {
		case today:
			e.Date = "Today"
		case yesterday:
			e.Date = "Yesterday"
		default:
			e.Date = t.Format("Jan 2, 2006")
		}
		if idx, ok := groupIdx[e.Date]; ok {
			groups[idx].Entries = append(groups[idx].Entries, e)
		} else {
			groupIdx[e.Date] = len(groups)
			groups = append(groups, AuditGroup{Date: e.Date, Entries: []AuditEntry{e}})
		}
	}
	total := 0
	for _, g := range groups {
		total += len(g.Entries)
	}
	h.render(w, r, "admin_audit.html", map[string]interface{}{"Groups": groups, "TotalEvents": total})
}

func (h *Handlers) GetSettings(w http.ResponseWriter, r *http.Request) {
	get := func(key, fallback string) string {
		return h.settings.Get(r.Context(), key, fallback)
	}
	h.render(w, r, "admin_settings.html", map[string]interface{}{
		"AllowedDomains": get("allowed_email_domains", h.envDefaults.AllowedDomains),
		"SessionTTL":     get("session_ttl_hours", intStr(h.envDefaults.SessionTTLHours)),
		"SMTPHost":       get("smtp_host", h.envSMTP.Host),
		"SMTPPort":       get("smtp_port", intStr(h.envSMTP.Port)),
		"SMTPUsername":   get("smtp_username", h.envSMTP.Username),
		"SMTPFrom":       get("smtp_from", h.envSMTP.From),
		"SMTPTLS":        get("smtp_tls", h.envSMTP.TLS),
		"BaseURL":        h.baseURL,
	})
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
	set("smtp_host", r.FormValue("smtp_host"))
	set("smtp_port", r.FormValue("smtp_port"))
	set("smtp_username", r.FormValue("smtp_username"))
	set("smtp_from", r.FormValue("smtp_from"))
	set("smtp_tls", r.FormValue("smtp_tls"))
	if pw := r.FormValue("smtp_password"); pw != "" {
		h.settings.Set(r.Context(), "smtp_password", pw)
	}
	h.render(w, r, "admin_settings.html", map[string]interface{}{"Success": "Settings saved."})
}

func (h *Handlers) GetProfile(w http.ResponseWriter, r *http.Request) {
	adminID := h.adminIDFromRequest(r)
	admin, _ := h.admins.GetByID(r.Context(), adminID)
	passkeys, _ := h.passkeys.ListCredentials(r.Context(), "admin:"+adminID)
	totpEnabled := false
	if admin != nil {
		var enc string
		h.db.QueryRowContext(r.Context(), `SELECT totp_enabled FROM admin_users WHERE id=?`, adminID).Scan(&totpEnabled)
		_ = enc
	}
	h.render(w, r, "admin_profile.html", map[string]interface{}{
		"Admin":       admin,
		"TOTPEnabled": totpEnabled,
		"Passkeys":    passkeys,
	})
}

func (h *Handlers) PostProfilePassword(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	admin, err := h.admins.GetByID(r.Context(), adminID)
	if err != nil || admin == nil {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}
	current := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	if auth.VerifyPassword(current, admin.PasswordHash) != nil {
		h.render(w, r, "admin_profile.html", map[string]interface{}{"Error": "Current password is incorrect"})
		return
	}
	if newPass != confirm {
		h.render(w, r, "admin_profile.html", map[string]interface{}{"Error": "Passwords do not match"})
		return
	}
	hash, err := auth.HashPassword(newPass)
	if err != nil {
		h.render(w, r, "admin_profile.html", map[string]interface{}{"Error": err.Error()})
		return
	}
	h.db.ExecContext(r.Context(), `UPDATE admin_users SET password_hash=? WHERE id=?`, hash, adminID)
	h.render(w, r, "admin_profile.html", map[string]interface{}{"Success": "Password updated."})
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
	h.render(w, r, "admin_profile.html", map[string]interface{}{
		"EnrollTOTP": true,
		"Secret":     key.Secret(),
		"QRCodeB64":  base64.StdEncoding.EncodeToString(png),
	})
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
		h.render(w, r, "admin_profile.html", map[string]interface{}{
			"EnrollTOTP": true, "Secret": secret, "Error": err.Error(),
		})
		return
	}
	h.db.ExecContext(r.Context(), `UPDATE admin_users SET totp_enabled=1 WHERE id=?`, adminID)
	h.render(w, r, "admin_profile.html", map[string]interface{}{"Success": "Authenticator app enrolled.", "TOTPEnabled": true})
}

func (h *Handlers) PostProfileTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	adminID := h.adminIDFromRequest(r)
	code := strings.TrimSpace(r.FormValue("code"))
	if err := h.totp.Validate(r.Context(), "admin:"+adminID, code); err != nil {
		h.render(w, r, "admin_profile.html", map[string]interface{}{"Error": "Invalid code"})
		return
	}
	h.totp.Revoke(r.Context(), "admin:"+adminID)
	h.db.ExecContext(r.Context(), `UPDATE admin_users SET totp_enabled=0 WHERE id=?`, adminID)
	h.render(w, r, "admin_profile.html", map[string]interface{}{"Success": "Authenticator app removed."})
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
	options, session, err := h.passkeys.WebAuthn().BeginRegistration(waUser)
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

