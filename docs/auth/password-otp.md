---
title: Password + email OTP
description: How the default two-step login flow works.
---

The default login flow requires both a correct password and a one-time code sent to the user's email. This is two-factor authentication (2FA) - even if someone steals a user's password, they still cannot log in without also having access to that user's inbox.

## Step 1: password

The user goes to `/login`, enters their email and password, and clicks **Sign in**.

GateKeeper looks up the user by email, checks the password using argon2id (a slow, memory-hard hashing algorithm that makes brute-force attacks expensive), and if it matches, moves on to step 2.

If the password is wrong, the login attempt is rejected and logged in the audit log. The error message deliberately does not distinguish between "email not found" and "wrong password" to avoid confirming whether an account exists.

If the user has a TOTP authenticator app enrolled, they are sent to the TOTP challenge page instead of email OTP. See [TOTP](/auth/totp) for details.

## Step 2: email OTP

GateKeeper generates a 6-digit code using a cryptographically secure random number generator, stores it with a 10-minute expiry, and sends it to the user's email.

A "one-time password" (OTP) is a code that can only be used once and expires after a short time. It adds a second factor because it requires access to the user's email, not just their password.

The user enters the code at `/login/otp`. If it matches and has not expired, the session is established and the user is redirected to their original destination.

## Rate limiting and lockout

To prevent brute-force attacks against the OTP code:

- After 5 failed OTP attempts within 10 minutes, the account is locked out for 10 minutes.
- The lockout resets automatically after the 10-minute window.

## Session establishment

After successful OTP verification, GateKeeper creates a server-side session with a 32-byte random token. The session ID is stored in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. The actual session data (user ID, timestamps) lives in the database, not in the cookie.

The session lasts for `SESSION_TTL_HOURS` hours (default 8) and automatically renews on each request, so active users stay logged in.
