---
title: Audit log
description: What gets logged and how to read the audit log.
---

The audit log at `/audit` is an append-only record of every authentication and admin event.

## Reading the log

Each row shows:

- **Time** - `HH:MM:SS` in server local time
- **Event** - dotted code like `login.success` or `totp.failed`. For sign-in events, hovering shows the method used: Password, Passkey, Email OTP, TOTP, SSO, Trusted device, Social, or QR code.
- **User** - avatar and display name, or email if no name is set. Hovering shows the email address.
- **App / Site** - what was signed into: the OIDC client's name, or the hostname of a ForwardAuth protected site
- **Detail** - additional context, e.g. failure reason or changed field
- **IP** - originating IP address

## Filtering

**Kind chips** - All / Success / Warn / Fail / Info

**Event type chips:**
- `auth` - login, OTP, TOTP, passkey, password events
- `admin` - admin panel actions (including admin logins)
- `oidc` - OIDC token events

**Date range** - Today / 7 days / 30 days / 90 days / All (default: 30 days)

**Search** - filters by event code, email, IP, or detail text. The filter icon on any row sets the search to that event.

## Retention

Set a retention period in **Settings - Audit log**. Events older than the configured number of days are deleted automatically (runs on startup and once per day). Set to `0` to keep all events forever. Default is 90 days.

## Event reference

### Auth events

| Event | Kind | Description |
|---|---|---|
| `login.success` | ok | Sign-in completed. The detail column holds the method: `password`, `passwordless`, `sso`, or `trusted-device` |
| `login.failure` | err | Wrong password or unknown email |
| `login.passkey` | ok | User authenticated via passkey |
| `login.social` | ok | User authenticated via a social provider |
| `login.qr` | ok | User authenticated by scanning a QR code |
| `login.handoff` | ok | An existing sign-in reached a protected site on another domain |
| `forwardauth.denied` | err | A signed-in user was refused by a site's access policy |
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

### Admin events

| Event | Kind | Description |
|---|---|---|
| `admin.login` | ok | Admin signed in with password |
| `admin.login.passkey` | ok | Admin signed in with passkey |
| `admin.login_failed` | err | Admin login attempt failed |
| `admin.logout` | info | Admin signed out |
| `admin.password_set` | warn | Admin set a user's password directly |
| `user.created` | ok | New user account created |
| `user.disabled` | warn | Account disabled |
| `user.enabled` | ok | Account re-enabled |
| `user.deleted` | warn | User account permanently deleted |
