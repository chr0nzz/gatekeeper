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
	sessions    *auth.SessionStore
	totp        *auth.TOTPStore
	passkeys    *auth.PasskeyStore
	oidcStorage *oidcstore.Storage
	mailer      *mailer.Mailer
	resetStore  *auth.PasswordResetStore
	settings    *queries.SettingsStore
	auditLog    *audit.Logger
	renderer    *templates.Renderer
	baseURL     string
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
	oidcStorage *oidcstore.Storage,
	m *mailer.Mailer,
	resetStore *auth.PasswordResetStore,
	settings *queries.SettingsStore,
	auditLog *audit.Logger,
	renderer    *templates.Renderer,
	baseURL     string,
	envSMTP     mailer.Settings,
	envDefaults EnvDefaults,
) *Handlers {
	return &Handlers{
		db: db, users: users, admins: admins, adminSess: adminSess,
		sessions: sessions, totp: totp, passkeys: passkeys,
		oidcStorage: oidcStorage, mailer: m, resetStore: resetStore,
		settings: settings, auditLog: auditLog, renderer: renderer,
		baseURL: baseURL, envSMTP: envSMTP, envDefaults: envDefaults,
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
	h.renderer.Render(w, name, data)
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
	http.Redirect(w, r, "/admin/users", http.StatusFound)
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
	http.Redirect(w, r, "/admin/users", http.StatusFound)
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
	h.render(w, r, "admin_users.html", map[string]interface{}{"Users": users})
}

func (h *Handlers) PostCreateUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	hash, err := auth.HashPassword(password)
	if err != nil {
		h.render(w, r, "admin_user_new.html", map[string]interface{}{"Error": err.Error()})
		return
	}
	adminID := h.adminIDFromRequest(r)
	id, err := h.users.Create(r.Context(), email, hash, true)
	if err != nil {
		h.render(w, r, "admin_user_new.html", map[string]interface{}{"Error": "Could not create user: " + err.Error()})
		return
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
	h.render(w, r, "admin_user_detail.html", map[string]interface{}{
		"User":          user,
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
	h.render(w, r, "admin_clients.html", map[string]interface{}{"Clients": clients})
}

func (h *Handlers) PostCreateClient(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	name := strings.TrimSpace(r.FormValue("name"))
	urisRaw := strings.TrimSpace(r.FormValue("redirect_uris"))
	var uris []string
	for _, u := range strings.Split(urisRaw, "\n") {
		u = strings.TrimSpace(u)
		if u != "" {
			uris = append(uris, u)
		}
	}
	if err := h.oidcStorage.CreateClient(r.Context(), clientID, clientSecret, name, uris); err != nil {
		clients, _ := h.oidcStorage.ListClients(r.Context())
		h.render(w, r, "admin_clients.html", map[string]interface{}{"Clients": clients, "Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusFound)
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

func (h *Handlers) GetAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, event, user_id, actor_id, ip, detail, created_at FROM audit_log ORDER BY created_at DESC LIMIT 500`,
	)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type entry struct {
		ID        string
		Event     string
		UserID    string
		ActorID   string
		IP        string
		Detail    string
		CreatedAt string
	}
	var entries []entry
	for rows.Next() {
		var e entry
		var userID, actorID, ip, detail sql.NullString
		var ts int64
		if err := rows.Scan(&e.ID, &e.Event, &userID, &actorID, &ip, &detail, &ts); err != nil {
			continue
		}
		e.UserID = userID.String
		e.ActorID = actorID.String
		e.IP = ip.String
		e.Detail = detail.String
		e.CreatedAt = time.Unix(ts, 0).Format("2006-01-02 15:04:05")
		entries = append(entries, e)
	}
	h.render(w, r, "admin_audit.html", map[string]interface{}{"Entries": entries})
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

