---
title: Audit log
description: What gets logged and how to read the audit log.
---

Every significant authentication event is recorded in an append-only audit log at `/admin/audit`. The log cannot be modified or deleted through the admin UI.

## Events logged

| Event | What triggered it |
|---|---|
| `login.success` | User completed full authentication |
| `login.failure` | Wrong password or invalid email |
| `login.passkey` | Successful passkey authentication |
| `otp.sent` | OTP email was dispatched |
| `otp.verified` | User entered a correct OTP |
| `otp.failed` | User entered an incorrect OTP |
| `totp.enrolled` | User successfully enrolled TOTP |
| `totp.revoked` | TOTP enrollment removed (by user or admin) |
| `totp.verified` | User entered a correct TOTP code |
| `totp.failed` | User entered an incorrect TOTP code |
| `totp.recovery_used` | A recovery code was consumed |
| `passkey.registered` | A new passkey was added |
| `passkey.revoked` | A passkey was removed |
| `password.changed` | User changed their own password |
| `password.reset_requested` | Forgot-password email was triggered |
| `password.reset_completed` | Password was successfully reset |
| `password.reset_invalid` | A bad or expired reset token was submitted |
| `session.revoked` | Sessions were revoked (by admin or on password change) |
| `user.created` | Admin created a new user |
| `user.disabled` | Admin disabled an account |
| `user.enabled` | Admin re-enabled an account |
| `admin.password_set` | Admin directly set a user's password |

## Columns

- **Time** - timestamp in `YYYY-MM-DD HH:MM:SS` format (server local time)
- **Event** - the event type from the table above
- **User** - the user the event concerns (may be empty for failed logins with unrecognized emails)
- **Actor** - the admin who triggered the event, if applicable
- **IP** - the IP address of the request
- **Detail** - extra context, such as the email address for a failed login attempt

## Retention

The audit log grows indefinitely. GateKeeper does not automatically prune it. If you need to manage log size, you can archive or delete old rows directly in the SQLite database. This does not affect application behavior.
