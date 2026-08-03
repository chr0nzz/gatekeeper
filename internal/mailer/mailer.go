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
	Port                                int
}

// Branding holds the visual customization applied to outgoing emails.
type Branding struct {
	LogoURL     string
	SenderName  string
	AccentColor string
}

func (b Branding) senderName() string {
	if b.SenderName != "" {
		return b.SenderName
	}
	return "GateKeeper"
}

func (b Branding) accentColor() string {
	if b.AccentColor != "" {
		return b.AccentColor
	}
	return "#2563eb"
}

// Loader fetches the current SMTP settings, merging DB overrides with env var defaults.
type Loader func(ctx context.Context) Settings

// BrandingLoader fetches the current email branding settings.
type BrandingLoader func(ctx context.Context) Branding

// Mailer sends transactional emails using live-loaded SMTP settings.
type Mailer struct {
	load     Loader
	branding BrandingLoader
}

// New creates a Mailer. The loader is called on every send so settings can be
// updated in the admin UI without restarting the container.
func New(load Loader) *Mailer {
	return &Mailer{load: load}
}

// SetBrandingLoader attaches a branding loader to the mailer.
func (m *Mailer) SetBrandingLoader(fn BrandingLoader) {
	m.branding = fn
}

// NewFromDefaults creates a Mailer using fixed values (for callers without a settings store).
func NewFromDefaults(host string, port int, username, password, from, tlsMode string) *Mailer {
	s := Settings{Host: host, Port: port, Username: username, Password: password, From: from, TLS: tlsMode}
	return &Mailer{load: func(_ context.Context) Settings { return s }}
}

func (m *Mailer) loadBranding(ctx context.Context) Branding {
	if m.branding != nil {
		return m.branding(ctx)
	}
	return Branding{}
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
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Your login code</title></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 16px">
  <tr><td align="center">
    <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)">
      <tr><td style="background:{{.AccentColor}};padding:24px 32px;text-align:center">
        {{if .LogoURL}}<img src="{{.LogoURL}}" alt="{{.SenderName}}" height="36" style="display:block;margin:0 auto">
        {{else}}<span style="color:#ffffff;font-size:18px;font-weight:700;letter-spacing:-.3px">{{.SenderName}}</span>{{end}}
      </td></tr>
      <tr><td style="padding:36px 32px">
        <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#111827">Your login code</h1>
        <p style="margin:0 0 28px;font-size:15px;color:#6b7280">Use the code below to complete your sign-in. It expires in 10 minutes.</p>
        <div style="background:#f4f4f5;border-radius:8px;padding:20px;text-align:center;margin-bottom:28px">
          <span style="font-size:40px;font-weight:700;letter-spacing:12px;color:#111827;font-family:'Courier New',monospace">{{.Code}}</span>
        </div>
        <p style="margin:0;font-size:13px;color:#9ca3af">If you did not request this code, you can safely ignore this email.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #f0f0f0;text-align:center">
        <p style="margin:0;font-size:12px;color:#9ca3af">Sent by {{.SenderName}}</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`))

var resetTmpl = template.Must(template.New("reset").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset your password</title></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 16px">
  <tr><td align="center">
    <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)">
      <tr><td style="background:{{.AccentColor}};padding:24px 32px;text-align:center">
        {{if .LogoURL}}<img src="{{.LogoURL}}" alt="{{.SenderName}}" height="36" style="display:block;margin:0 auto">
        {{else}}<span style="color:#ffffff;font-size:18px;font-weight:700;letter-spacing:-.3px">{{.SenderName}}</span>{{end}}
      </td></tr>
      <tr><td style="padding:36px 32px">
        <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#111827">Reset your password</h1>
        <p style="margin:0 0 28px;font-size:15px;color:#6b7280">Click the button below to choose a new password. This link expires in 30 minutes and can only be used once.</p>
        <div style="text-align:center;margin-bottom:28px">
          <a href="{{.URL}}" style="display:inline-block;background:{{.AccentColor}};color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none">Reset password</a>
        </div>
        <p style="margin:0 0 8px;font-size:13px;color:#9ca3af">If the button does not work, copy and paste this link into your browser:</p>
        <p style="margin:0;font-size:12px;color:#6b7280;word-break:break-all">{{.URL}}</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #f0f0f0;text-align:center">
        <p style="margin:0;font-size:12px;color:#9ca3af">If you did not request a password reset, you can safely ignore this email. Sent by {{.SenderName}}</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`))

var changedTmpl = template.Must(template.New("changed").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Password changed</title></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 16px">
  <tr><td align="center">
    <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)">
      <tr><td style="background:{{.AccentColor}};padding:24px 32px;text-align:center">
        {{if .LogoURL}}<img src="{{.LogoURL}}" alt="{{.SenderName}}" height="36" style="display:block;margin:0 auto">
        {{else}}<span style="color:#ffffff;font-size:18px;font-weight:700;letter-spacing:-.3px">{{.SenderName}}</span>{{end}}
      </td></tr>
      <tr><td style="padding:36px 32px">
        <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#111827">Password changed</h1>
        <p style="margin:0 0 16px;font-size:15px;color:#6b7280">Your {{.SenderName}} account password was just changed successfully.</p>
        <p style="margin:0;font-size:15px;color:#6b7280">If you did not make this change, contact your administrator immediately.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #f0f0f0;text-align:center">
        <p style="margin:0;font-size:12px;color:#9ca3af">Sent by {{.SenderName}}</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`))

// SendOTP sends a one-time password to the given address.
func (m *Mailer) SendOTP(ctx context.Context, to, code string) error {
	b := m.loadBranding(ctx)
	var buf bytes.Buffer
	if err := otpTmpl.Execute(&buf, map[string]string{
		"Code":        code,
		"LogoURL":     b.LogoURL,
		"SenderName":  b.senderName(),
		"AccentColor": b.accentColor(),
	}); err != nil {
		return err
	}
	return m.send(ctx, to, "Your login code", buf.String())
}

// SendPasswordReset sends a password reset link.
func (m *Mailer) SendPasswordReset(ctx context.Context, to, resetURL string) error {
	b := m.loadBranding(ctx)
	var buf bytes.Buffer
	if err := resetTmpl.Execute(&buf, map[string]string{
		"URL":         resetURL,
		"LogoURL":     b.LogoURL,
		"SenderName":  b.senderName(),
		"AccentColor": b.accentColor(),
	}); err != nil {
		return err
	}
	return m.send(ctx, to, "Reset your password", buf.String())
}

// SendPasswordChanged notifies a user that their password was changed.
// SendDuplicateRegistration tells an existing account holder that someone tried
// to register with their address, so the signup form need not reveal it.
func (m *Mailer) SendDuplicateRegistration(ctx context.Context, to string) error {
	b := m.loadBranding(ctx)
	var buf bytes.Buffer
	if err := changedTmpl.Execute(&buf, map[string]string{
		"LogoURL":     b.LogoURL,
		"SenderName":  b.senderName(),
		"AccentColor": b.accentColor(),
	}); err != nil {
		return err
	}
	return m.send(ctx, to, "You already have an account", buf.String())
}

func (m *Mailer) SendPasswordChanged(ctx context.Context, to string) error {
	b := m.loadBranding(ctx)
	var buf bytes.Buffer
	if err := changedTmpl.Execute(&buf, map[string]string{
		"LogoURL":     b.LogoURL,
		"SenderName":  b.senderName(),
		"AccentColor": b.accentColor(),
	}); err != nil {
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
