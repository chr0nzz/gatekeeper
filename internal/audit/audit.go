package audit

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const (
	EventLoginSuccess      = "login.success"
	EventLoginFailure      = "login.failure"
	EventLoginPasskey      = "login.passkey"
	EventOTPSent           = "otp.sent"
	EventOTPVerified       = "otp.verified"
	EventOTPFailed         = "otp.failed"
	EventTOTPEnrolled      = "totp.enrolled"
	EventTOTPRevoked       = "totp.revoked"
	EventTOTPVerified      = "totp.verified"
	EventTOTPFailed        = "totp.failed"
	EventTOTPRecoveryUsed  = "totp.recovery_used"
	EventPasskeyRegistered = "passkey.registered"
	EventPasskeyRevoked    = "passkey.revoked"
	EventPasswordChanged   = "password.changed"
	EventPasswordResetReq  = "password.reset_requested"
	EventPasswordResetDone = "password.reset_completed"
	EventPasswordResetBad  = "password.reset_invalid"
	EventSessionRevoked    = "session.revoked"
	EventUserCreated       = "user.created"
	EventUserDisabled      = "user.disabled"
	EventUserEnabled       = "user.enabled"
	EventUserDeleted       = "user.deleted"
	EventAdminPasswordSet  = "admin.password_set"
	EventAdminLogin        = "admin.login"
	EventAdminLoginFailed  = "admin.login_failed"
	EventAdminLoginPasskey = "admin.login.passkey"
	EventAdminLogout       = "admin.logout"
)

// Logger writes audit events to the database.
type Logger struct {
	db    *sql.DB
	hooks []func(event, userID, actorID, ip, detail string)
}

// New creates an audit Logger.
func New(db *sql.DB) *Logger {
	return &Logger{db: db}
}

// AddHook registers a function called after each audit event is logged.
func (l *Logger) AddHook(fn func(event, userID, actorID, ip, detail string)) {
	l.hooks = append(l.hooks, fn)
}

// Log writes an audit event. userID and actorID may be empty.
func (l *Logger) Log(ctx context.Context, event, userID, actorID, ip, detail string) {
	l.db.ExecContext(ctx,
		`INSERT INTO audit_log (id, event, user_id, actor_id, ip, detail, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), event,
		nullStr(userID), nullStr(actorID), nullStr(ip), nullStr(detail),
		time.Now().Unix(),
	)
	for _, h := range l.hooks {
		go h(event, userID, actorID, ip, detail)
	}
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
