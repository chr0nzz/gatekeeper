---
title: Passwordless OTP
description: Let users log in with just their email and a one-time code.
---

Passwordless mode lets a user log in without a password. They enter their email, receive a one-time code, and that's it. This is useful for users who find passwords inconvenient and are comfortable with email-based authentication.

## How it works

1. The user visits `/login` and enters their email but no password.
2. If the account has passwordless mode enabled, GateKeeper accepts this and sends an OTP to their email.
3. The user enters the OTP at `/login/otp`.
4. On success, the session is established.

If passwordless mode is not enabled for the account, a missing password is treated as an incorrect password and the login fails.

## Enabling passwordless for a user

Only admins can enable or disable passwordless mode per user. Go to `/admin/users/:id` and click **Enable passwordless**.

Passwordless mode is off by default for all users.

## Security note

Passwordless login shifts trust entirely to the user's email inbox. If their email is compromised, their GateKeeper account is too. For high-security accounts, keep passwordless mode off and require both a password and the OTP.

Passkeys are a stronger alternative to passwordless OTP because they use hardware-backed keys tied to a specific device. See [Passkeys](/auth/passkeys) for details.
