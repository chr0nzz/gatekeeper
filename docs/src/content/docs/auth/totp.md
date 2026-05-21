---
title: TOTP (authenticator app)
description: Set up and use Google Authenticator, Authy, or any TOTP-compatible app.
---

TOTP (Time-based One-Time Password) is a standard (RFC 6238) for generating short-lived codes using a secret key and the current time. Authenticator apps like Google Authenticator, Authy, and 1Password implement this standard.

When TOTP is enrolled, it replaces email OTP as the second factor. Instead of waiting for an email, the user opens their authenticator app and enters the 6-digit code shown there.

## Enrollment

1. Go to `/profile/totp/enroll`.
2. Scan the QR code with your authenticator app. If you cannot scan it, expand "Can't scan?" and enter the key manually.
3. Enter the 6-digit code currently shown in your app to confirm that enrollment worked.
4. GateKeeper displays 8 one-time recovery codes. Save these somewhere safe - a password manager is ideal. They are not shown again.

GateKeeper does not store the TOTP secret until you confirm enrollment with a valid code. This prevents half-finished enrollments from locking you out.

## Logging in with TOTP

After your password is verified, GateKeeper redirects you to `/login/totp` instead of the email OTP page. Enter the 6-digit code from your authenticator app.

GateKeeper accepts codes from the current 30-second window and the previous one. This handles small clock differences between your device and the server (known as "clock skew").

After 5 failed attempts within 10 minutes, the account is locked for 10 minutes.

## Recovery codes

If you lose access to your authenticator app, use one of your recovery codes at `/login/totp/recovery`. Each code works once and is permanently invalidated after use.

The admin can see how many recovery codes you have left at `/admin/users/:id`. They cannot see the codes themselves.

## Disabling TOTP

Go to `/profile/totp/disable` and enter a valid code from your authenticator app. This confirms it is you and not someone who just has your session cookie.

Admins can also disable TOTP for any user from the admin panel, without needing the authenticator code.
