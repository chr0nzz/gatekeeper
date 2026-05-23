package mailer

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"strconv"
	"time"

	"github.com/wneessen/go-mail"
)

// Settings holds the SMTP configuration used for one send operation.
type Settings struct {
	Host, Username, Password, From, TLS string
	Port                                 int
}

// Loader fetches the current SMTP settings, merging DB overrides with env var defaults.
type Loader func(ctx context.Context) Settings

// Mailer sends transactional emails using live-loaded SMTP settings.
type Mailer struct {
	load Loader
}

// New creates a Mailer. The loader is called on every send so settings can be
// updated in the admin UI without restarting the container.
func New(load Loader) *Mailer {
	return &Mailer{load: load}
}

// NewFromDefaults creates a Mailer using fixed values (for callers without a settings store).
func NewFromDefaults(host string, port int, username, password, from, tlsMode string) *Mailer {
	s := Settings{Host: host, Port: port, Username: username, Password: password, From: from, TLS: tlsMode}
	return &Mailer{load: func(_ context.Context) Settings { return s }}
}

func (m *Mailer) send(ctx context.Context, to, subject, htmlBody string) error {
	s := m.load(ctx)
	msg := mail.NewMsg()
	if err := msg.From(s.From); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("to: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextHTML, htmlBody)

	opts := []mail.Option{
		mail.WithPort(s.Port),
		mail.WithTimeout(10 * time.Second),
	}
	if s.Username != "" {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthPlain), mail.WithUsername(s.Username), mail.WithPassword(s.Password))
	}
	switch s.TLS {
	case "tls":
		opts = append(opts, mail.WithSSLPort(false))
	case "starttls":
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSMandatory))
	default:
		opts = append(opts, mail.WithTLSPortPolicy(mail.NoTLS))
	}
	client, err := mail.NewClient(s.Host, opts...)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	return client.DialAndSend(msg)
}

var otpTmpl = template.Must(template.New("otp").Parse(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px">
<h2>Your login code</h2>
<p>Your one-time login code is:</p>
<p style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#1a1a1a">{{.Code}}</p>
<p>This code expires in 10 minutes and can only be used once.</p>
<p>If you did not request this code, you can safely ignore this email.</p>
</body></html>`))

var resetTmpl = template.Must(template.New("reset").Parse(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px">
<h2>Reset your password</h2>
<p>Click the link below to reset your password. This link expires in 30 minutes.</p>
<p><a href="{{.URL}}" style="background:#16a34a;color:#fff;padding:12px 24px;border-radius:4px;text-decoration:none">Reset password</a></p>
<p>If you did not request a password reset, you can safely ignore this email.</p>
</body></html>`))

var changedTmpl = template.Must(template.New("changed").Parse(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px">
<h2>Your password was changed</h2>
<p>Your GateKeeper account password was just changed.</p>
<p>If you did not make this change, contact your administrator immediately.</p>
</body></html>`))

// SendOTP sends a one-time password to the given address.
func (m *Mailer) SendOTP(ctx context.Context, to, code string) error {
	var buf bytes.Buffer
	if err := otpTmpl.Execute(&buf, map[string]string{"Code": code}); err != nil {
		return err
	}
	return m.send(ctx, to, "Your login code", buf.String())
}

// SendPasswordReset sends a password reset link.
func (m *Mailer) SendPasswordReset(ctx context.Context, to, resetURL string) error {
	var buf bytes.Buffer
	if err := resetTmpl.Execute(&buf, map[string]string{"URL": resetURL}); err != nil {
		return err
	}
	return m.send(ctx, to, "Reset your password", buf.String())
}

// SendPasswordChanged notifies a user that their password was changed.
func (m *Mailer) SendPasswordChanged(ctx context.Context, to string) error {
	var buf bytes.Buffer
	if err := changedTmpl.Execute(&buf, nil); err != nil {
		return err
	}
	return m.send(ctx, to, "Your password was changed", buf.String())
}

// SendRaw sends a plain-text email with the given subject and body.
func (m *Mailer) SendRaw(to, subject, body string) error {
	return m.send(context.Background(), to, subject, "<pre>"+body+"</pre>")
}

// PortFromString converts a string port to int, returning 587 on failure.
func PortFromString(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 587
	}
	return n
}
