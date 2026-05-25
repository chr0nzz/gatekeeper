---
title: Webhooks
description: Send notifications to external services when events occur in GateKeeper.
---

Webhooks let GateKeeper push notifications to Discord, Slack, Telegram, ntfy, a generic HTTP endpoint, or an email address whenever an auth or admin event occurs.

## Adding a webhook

Go to `/admin/webhooks` and click **Add webhook**. Choose a type, fill in the required fields, and optionally restrict which events it receives.

By default a webhook receives all events. To restrict it, check only the events you care about in the **Events** section of the dialog.

## Webhook types

### Discord
Paste a Discord webhook URL. GateKeeper sends an embed with a colour-coded status (green for success, yellow for warning, red for failure).

**Required:** Webhook URL from your Discord channel settings.

### Slack
Paste an incoming webhook URL from your Slack app configuration.

**Required:** Webhook URL (starts with `https://hooks.slack.com/`).

### Telegram
GateKeeper uses the Telegram Bot API to send messages to a chat or channel.

**Required:**
- **Bot token** - from BotFather, format `123456:ABC...`
- **Chat ID** - your chat or channel ID (use `@username` or a numeric ID like `-100123456789`)

### ntfy (public)
Posts to the public ntfy.sh service.

**Required:** Topic name (e.g. `my-gatekeeper-alerts`). Messages go to `https://ntfy.sh/{topic}`.

### ntfy (self-hosted)
Posts to your own ntfy instance with optional Basic authentication.

**Required:**
- **URL** - base URL of your ntfy server (e.g. `https://ntfy.example.com`)
- **Topic** - topic name
- **Username / Password** - optional, only if your instance requires auth

### Generic JSON
Posts a JSON object to any HTTP endpoint.

**Payload:**
```json
{
  "event": "login.failure",
  "user_id": "abc123",
  "ip": "1.2.3.4",
  "detail": "",
  "timestamp": 1716000000,
  "source": "gatekeeper"
}
```

**Required:** Webhook URL (must accept POST with `Content-Type: application/json`).

### Email
Sends a plain-text email using the SMTP settings configured in **Settings**.

**Required:** Recipient email address. SMTP must be configured first.

---

## Events

| Category | Event | Description |
|----------|-------|-------------|
| Auth | `login.success` | User logged in with password |
| Auth | `login.failure` | Failed login attempt |
| Auth | `login.passkey` | User logged in with a passkey |
| Auth | `otp.failed` | Email OTP verification failed |
| Auth | `totp.failed` | Authenticator code failed |
| Auth | `totp.recovery_used` | Recovery code consumed |
| Account | `password.changed` | User changed their password |
| Account | `totp.enrolled` | Authenticator app set up |
| Account | `totp.revoked` | Authenticator app removed |
| Account | `passkey.registered` | New passkey added |
| Account | `passkey.revoked` | Passkey removed |
| Account | `password.reset_requested` | Reset link sent |
| Account | `password.reset_completed` | Password reset via link |
| Admin | `user.created` | New user account created |
| Admin | `user.disabled` | Account disabled |
| Admin | `user.enabled` | Account re-enabled |
| Admin | `admin.password_set` | Admin directly set a user password |
| Admin | `session.revoked` | Sessions terminated by admin |

---

## Testing a webhook

Click the arrow button on any webhook row to send a `test.ping` notification immediately. The page shows whether it succeeded or failed.

## Enabling and disabling

Click the toggle button on a webhook row to enable or disable it without deleting it. Disabled webhooks receive no notifications.
