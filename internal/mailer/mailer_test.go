package mailer

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"strings"
	"sync"
	"testing"
)

type mailCaptured struct {
	envelopeFrom string
	envelopeTo   []string
	raw          string
}

func (c mailCaptured) parsed(t *testing.T) *netmail.Message {
	t.Helper()
	msg, err := netmail.ReadMessage(strings.NewReader(c.raw))
	if err != nil {
		t.Fatalf("parse delivered message: %v\n%s", err, c.raw)
	}
	return msg
}

func (c mailCaptured) header(t *testing.T, name string) string {
	t.Helper()
	return c.parsed(t).Header.Get(name)
}

func (c mailCaptured) body(t *testing.T) string {
	t.Helper()
	msg := c.parsed(t)
	var reader io.Reader = msg.Body
	switch strings.ToLower(strings.TrimSpace(msg.Header.Get("Content-Transfer-Encoding"))) {
	case "quoted-printable":
		reader = quotedprintable.NewReader(msg.Body)
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, msg.Body)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return string(out)
}

type mailFakeSMTP struct {
	port int
	mu   sync.Mutex
	msgs []mailCaptured
}

func (s *mailFakeSMTP) delivered() []mailCaptured {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]mailCaptured(nil), s.msgs...)
}

func (s *mailFakeSMTP) only(t *testing.T) mailCaptured {
	t.Helper()
	got := s.delivered()
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 delivered message, got %d", len(got))
	}
	return got[0]
}

// The fake speaks just enough ESMTP for go-mail to complete a plaintext
// delivery, so the tests can inspect the real wire format without a network.
func mailStartSMTP(t *testing.T) *mailFakeSMTP {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	srv := &mailFakeSMTP{port: listener.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go srv.handle(conn)
		}
	}()
	return srv
}

func (s *mailFakeSMTP) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	write := func(line string) bool {
		_, err := io.WriteString(conn, line+"\r\n")
		return err == nil
	}
	if !write("220 fake.test ESMTP ready") {
		return
	}

	var pending mailCaptured
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			if !write("250-fake.test\r\n250-8BITMIME\r\n250 SIZE 10485760") {
				return
			}
		case strings.HasPrefix(upper, "MAIL FROM"):
			pending.envelopeFrom = mailAddrArg(cmd)
			if !write("250 2.1.0 OK") {
				return
			}
		case strings.HasPrefix(upper, "RCPT TO"):
			pending.envelopeTo = append(pending.envelopeTo, mailAddrArg(cmd))
			if !write("250 2.1.5 OK") {
				return
			}
		case strings.HasPrefix(upper, "DATA"):
			if !write("354 Start mail input") {
				return
			}
			data, readErr := mailReadData(reader)
			if readErr != nil {
				return
			}
			pending.raw = data
			s.mu.Lock()
			s.msgs = append(s.msgs, pending)
			s.mu.Unlock()
			pending = mailCaptured{}
			if !write("250 2.0.0 OK") {
				return
			}
		case strings.HasPrefix(upper, "RSET"):
			pending = mailCaptured{}
			if !write("250 2.0.0 OK") {
				return
			}
		case strings.HasPrefix(upper, "QUIT"):
			write("221 2.0.0 Bye")
			return
		default:
			if !write("250 2.0.0 OK") {
				return
			}
		}
	}
}

func mailReadData(reader *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			return b.String(), nil
		}
		b.WriteString(strings.TrimPrefix(trimmed, ".") + "\n")
	}
}

func mailAddrArg(cmd string) string {
	open := strings.Index(cmd, "<")
	closing := strings.LastIndex(cmd, ">")
	if open < 0 || closing < open {
		return strings.TrimSpace(cmd[strings.Index(cmd, ":")+1:])
	}
	return cmd[open+1 : closing]
}

const mailFromAddr = "gatekeeper@example.test"

func mailSettingsFor(srv *mailFakeSMTP) Settings {
	return Settings{Host: "127.0.0.1", Port: srv.port, From: mailFromAddr}
}

func mailNewMailer(srv *mailFakeSMTP) *Mailer {
	return New(func(context.Context) Settings { return mailSettingsFor(srv) })
}

func mailNewBrandedMailer(srv *mailFakeSMTP, b Branding) *Mailer {
	m := mailNewMailer(srv)
	m.SetBrandingLoader(func(context.Context) Branding { return b })
	return m
}

func TestPortFromStringRejectsUnusableValues(t *testing.T) {
	cases := map[string]int{
		"":        587,
		" ":       587,
		"abc":     587,
		"25a":     587,
		"0":       587,
		"-1":      587,
		"-587":    587,
		" 465 ":   587,
		"465.0":   587,
		"1":       1,
		"25":      25,
		"465":     465,
		"587":     587,
		"2525":    2525,
		"65535":   65535,
		"1025000": 1025000,
	}
	for in, want := range cases {
		if got := PortFromString(in); got != want {
			t.Errorf("PortFromString(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestBrandingFallsBackToDefaults(t *testing.T) {
	var empty Branding
	if got := empty.senderName(); got != "GateKeeper" {
		t.Errorf("default sender name = %q, want GateKeeper", got)
	}
	if got := empty.accentColor(); got != "#2563eb" {
		t.Errorf("default accent colour = %q, want #2563eb", got)
	}

	set := Branding{SenderName: "Acme SSO", AccentColor: "#ff0066"}
	if got := set.senderName(); got != "Acme SSO" {
		t.Errorf("configured sender name = %q, want Acme SSO", got)
	}
	if got := set.accentColor(); got != "#ff0066" {
		t.Errorf("configured accent colour = %q, want #ff0066", got)
	}
}

func TestSendOTPDeliversCodeToRequestedRecipient(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewBrandedMailer(srv, Branding{SenderName: "Acme SSO"})

	if err := m.SendOTP(context.Background(), "user@example.test", "739104"); err != nil {
		t.Fatalf("SendOTP: %v", err)
	}

	got := srv.only(t)
	if len(got.envelopeTo) != 1 || got.envelopeTo[0] != "user@example.test" {
		t.Errorf("envelope recipients = %v, want [user@example.test]", got.envelopeTo)
	}
	if got.envelopeFrom != mailFromAddr {
		t.Errorf("envelope sender = %q, want %q", got.envelopeFrom, mailFromAddr)
	}
	if to := got.header(t, "To"); !strings.Contains(to, "user@example.test") {
		t.Errorf("To header = %q, want it to name the recipient", to)
	}
	if subject := got.header(t, "Subject"); subject != "Your login code" {
		t.Errorf("Subject = %q, want %q", subject, "Your login code")
	}
	body := got.body(t)
	if !strings.Contains(body, "739104") {
		t.Errorf("login code missing from body:\n%s", body)
	}
	if !strings.Contains(body, "Acme SSO") {
		t.Errorf("configured sender name missing from body:\n%s", body)
	}
}

func TestSendPasswordResetDeliversUsableLink(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewMailer(srv)
	link := "https://auth.example.test/reset?token=abc123XYZ"

	if err := m.SendPasswordReset(context.Background(), "user@example.test", link); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}

	got := srv.only(t)
	if subject := got.header(t, "Subject"); subject != "Reset your password" {
		t.Errorf("Subject = %q, want %q", subject, "Reset your password")
	}
	body := got.body(t)
	if !strings.Contains(body, `href="https://auth.example.test/reset?token=abc123XYZ"`) {
		t.Errorf("reset link missing from href:\n%s", body)
	}
	if !strings.Contains(body, "token=abc123XYZ") {
		t.Errorf("reset token missing from body:\n%s", body)
	}
}

func TestSendPasswordChangedTellsRecipientToActOnUnexpectedChange(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewMailer(srv)

	if err := m.SendPasswordChanged(context.Background(), "user@example.test"); err != nil {
		t.Fatalf("SendPasswordChanged: %v", err)
	}

	got := srv.only(t)
	if len(got.envelopeTo) != 1 || got.envelopeTo[0] != "user@example.test" {
		t.Errorf("envelope recipients = %v, want [user@example.test]", got.envelopeTo)
	}
	if subject := got.header(t, "Subject"); subject != "Your password was changed" {
		t.Errorf("Subject = %q, want %q", subject, "Your password was changed")
	}
	body := got.body(t)
	if !strings.Contains(body, "Password changed") {
		t.Errorf("body does not announce the change:\n%s", body)
	}
	if !strings.Contains(body, "contact your administrator") {
		t.Errorf("body does not tell the user what to do if it was not them:\n%s", body)
	}
}

func TestSendDuplicateRegistrationUsesItsOwnSubject(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewMailer(srv)

	if err := m.SendDuplicateRegistration(context.Background(), "user@example.test"); err != nil {
		t.Fatalf("SendDuplicateRegistration: %v", err)
	}

	got := srv.only(t)
	if subject := got.header(t, "Subject"); subject != "You already have an account" {
		t.Errorf("Subject = %q, want %q", subject, "You already have an account")
	}
	if len(got.envelopeTo) != 1 || got.envelopeTo[0] != "user@example.test" {
		t.Errorf("envelope recipients = %v, want [user@example.test]", got.envelopeTo)
	}
}

func TestSendRawDeliversSubjectAndBody(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewMailer(srv)

	if err := m.SendRaw("ops@example.test", "GateKeeper alert: lockout", "user u1 locked out"); err != nil {
		t.Fatalf("SendRaw: %v", err)
	}

	got := srv.only(t)
	if subject := got.header(t, "Subject"); subject != "GateKeeper alert: lockout" {
		t.Errorf("Subject = %q", subject)
	}
	if body := got.body(t); !strings.Contains(body, "user u1 locked out") {
		t.Errorf("alert text missing from body:\n%s", body)
	}
}

func TestUnbrandedMailerRendersDefaultBranding(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewMailer(srv)

	if err := m.SendOTP(context.Background(), "user@example.test", "112233"); err != nil {
		t.Fatalf("SendOTP: %v", err)
	}

	body := srv.only(t).body(t)
	if !strings.Contains(body, "GateKeeper") {
		t.Errorf("default sender name missing from body:\n%s", body)
	}
	if !strings.Contains(body, "#2563eb") {
		t.Errorf("default accent colour missing from body:\n%s", body)
	}
	if strings.Contains(body, "<img") {
		t.Errorf("logo rendered even though no logo URL is configured:\n%s", body)
	}
}

func TestHostileBrandingIsEscapedInRenderedEmail(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewBrandedMailer(srv, Branding{
		SenderName:  `Acme"><script>alert('xss')</script>`,
		AccentColor: `#fff;background-image:url(javascript:alert(1))`,
	})

	if err := m.SendOTP(context.Background(), "user@example.test", "445566"); err != nil {
		t.Fatalf("SendOTP: %v", err)
	}

	body := srv.only(t).body(t)
	if strings.Contains(body, "<script>") {
		t.Errorf("hostile sender name injected raw script tag:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("hostile sender name was not html escaped:\n%s", body)
	}
	if strings.Contains(body, "javascript:alert(1)") {
		t.Errorf("hostile accent colour reached the style attribute:\n%s", body)
	}
	if !strings.Contains(body, "ZgotmplZ") {
		t.Errorf("hostile accent colour was not filtered by html/template:\n%s", body)
	}
}

func TestHostileLogoURLIsNeutralised(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewBrandedMailer(srv, Branding{LogoURL: "javascript:alert(document.domain)"})

	if err := m.SendPasswordChanged(context.Background(), "user@example.test"); err != nil {
		t.Fatalf("SendPasswordChanged: %v", err)
	}

	body := srv.only(t).body(t)
	if strings.Contains(body, `src="javascript:`) {
		t.Errorf("javascript logo URL survived into src:\n%s", body)
	}
	if !strings.Contains(body, `src="#ZgotmplZ"`) {
		t.Errorf("javascript logo URL was not replaced by the safe placeholder:\n%s", body)
	}
}

func TestHostileResetLinkIsNeutralisedInHref(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewMailer(srv)

	if err := m.SendPasswordReset(context.Background(), "user@example.test", "javascript:alert(document.domain)"); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}

	body := srv.only(t).body(t)
	if strings.Contains(body, `href="javascript:`) {
		t.Errorf("javascript reset URL survived into href:\n%s", body)
	}
	if !strings.Contains(body, `href="#ZgotmplZ"`) {
		t.Errorf("javascript reset URL was not replaced by the safe placeholder:\n%s", body)
	}
}

func TestRecipientHeaderInjectionIsRejected(t *testing.T) {
	srv := mailStartSMTP(t)
	m := mailNewMailer(srv)

	hostile := []string{
		"user@example.test\r\nBcc: attacker@evil.test",
		"user@example.test\nBcc: attacker@evil.test",
		"user@example.test, attacker@evil.test",
		"not-an-address",
		"",
	}
	for _, to := range hostile {
		if err := m.SendOTP(context.Background(), to, "998877"); err == nil {
			t.Errorf("recipient %q was accepted", to)
		}
	}
	if got := srv.delivered(); len(got) != 0 {
		t.Errorf("hostile recipients produced %d deliveries, want 0", len(got))
	}
}

func TestSendWithoutSMTPHostFailsInsteadOfPanicking(t *testing.T) {
	m := New(func(context.Context) Settings {
		return Settings{Port: 587, From: mailFromAddr}
	})
	ctx := context.Background()

	sends := map[string]func() error{
		"SendOTP":                   func() error { return m.SendOTP(ctx, "user@example.test", "123456") },
		"SendPasswordReset":         func() error { return m.SendPasswordReset(ctx, "user@example.test", "https://x.test/r") },
		"SendPasswordChanged":       func() error { return m.SendPasswordChanged(ctx, "user@example.test") },
		"SendDuplicateRegistration": func() error { return m.SendDuplicateRegistration(ctx, "user@example.test") },
		"SendRaw":                   func() error { return m.SendRaw("user@example.test", "s", "b") },
	}
	for name, send := range sends {
		if err := send(); err == nil {
			t.Errorf("%s with no SMTP host returned nil error", name)
		}
	}
}

func TestNewFromDefaultsUsesTheGivenSettings(t *testing.T) {
	srv := mailStartSMTP(t)
	m := NewFromDefaults("127.0.0.1", srv.port, "", "", mailFromAddr, "")

	if err := m.SendOTP(context.Background(), "user@example.test", "606060"); err != nil {
		t.Fatalf("SendOTP: %v", err)
	}

	got := srv.only(t)
	if got.envelopeFrom != mailFromAddr {
		t.Errorf("envelope sender = %q, want %q", got.envelopeFrom, mailFromAddr)
	}
	if !strings.Contains(got.body(t), "606060") {
		t.Error("login code missing from body")
	}
}
