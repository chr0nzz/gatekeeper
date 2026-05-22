---
title: Audit log
description: What gets logged and how to read the audit log.
---

The audit log at `/admin/audit` is an append-only record of every authentication and admin event.

## Reading the log

Each row shows:

- **Time** - `HH:MM:SS` in server local time
- **Event** - dotted code like `login.success` or `totp.failed`
- **User** - email address of the affected user (resolved from internal user ID)
- **Detail** - additional context, e.g. `method=passkey`
- **IP** - originating IP address

## Filtering

**Kind chips** - All / Success / Warn / Fail / Info

**Event type chips:**
- `auth` - login, OTP, TOTP, passkey, password events
- `admin` - admin panel actions
- `oidc` - OIDC token events

**Search** - filters by event code, email, IP, or detail text. The filter icon on any row sets the search to that event.

## Event reference

| Event | Kind | Description |
|---|---|---|
| `login.success` | ok | Password verified and 2FA passed |
| `login.failure` | err | Wrong password or unknown email |
| `login.passkey` | ok | Authenticated via passkey |
| `otp.sent` | info | Email OTP dispatched |
| `otp.verified` | ok | Email OTP accepted |
| `otp.failed` | err | Wrong OTP code |
| `totp.enrolled` | ok | Authenticator app enrolled |
| `totp.verified` | ok | Authenticator code accepted |
| `totp.failed` | err | Wrong authenticator code |
| `totp.recovery_used` | warn | Recovery code consumed |
| `totp.revoked` | warn | TOTP enrollment removed |
| `passkey.registered` | ok | New passkey added |
| `passkey.revoked` | warn | Passkey removed |
| `password.changed` | ok | Password updated |
| `password.reset_requested` | info | Reset link sent |
| `password.reset_completed` | ok | Password reset via link |
| `password.reset_invalid` | err | Invalid or expired reset token used |
| `session.revoked` | warn | Session terminated |
| `user.created` | ok | New user account created |
| `user.disabled` | warn | Account disabled |
| `user.enabled` | ok | Account re-enabled |
| `admin.password_set` | warn | Admin set a user's password directly |
