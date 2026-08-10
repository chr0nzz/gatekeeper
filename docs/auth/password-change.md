---
title: Password change
description: How users change their password while logged in.
---

Logged-in users can change their password at `/profile/password`.

## What's required

To change your password, you need:

1. Your current password (so someone who steals your session cookie cannot change your password).
2. The new password, entered twice to confirm.
3. If you have a TOTP authenticator app enrolled, your current 6-digit code is also required.

## What happens after a successful change

- All sessions except the current one are invalidated. This means any other device or browser where you were logged in will be signed out.
- GateKeeper sends a notification email to your address confirming the change.
- The event is recorded in the audit log.

## Forced password change

When an admin creates an account or directly sets a password, the user is required to change it on their next login. The application redirects them to `/profile/password?forced=1` before they can access anything else.

## Minimum password length

The requirements come from your [password policy](/security/password-policy) and are enforced on the server. The `minlength` attribute on the form reflects the same configured minimum, but it is a convenience hint only and is not what enforces the rule.
