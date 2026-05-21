---
title: First login
description: Log in as admin and set up your first user.
---

## Admin first login

On first startup, GateKeeper creates one admin account using the `ADMIN_EMAIL` and `ADMIN_PASSWORD` values from your environment. This happens exactly once - if an admin already exists, those variables are ignored.

Navigate to `https://auth.example.com/admin/login` and sign in with those credentials.

Change your admin password immediately after first login - the bootstrap password is visible in your environment variables and should be treated as temporary.

## Creating your first user

1. Go to `/admin/users` and click **New user**.
2. Enter an email address and a temporary password (minimum 12 characters).
3. Click **Create**.

The new user will be forced to change their password on first login. This is automatic and cannot be skipped.

## Testing ForwardAuth

1. Make sure GateKeeper is running and Traefik is configured with the `gatekeeper-auth` middleware on at least one service.
2. Visit the protected service in your browser.
3. You should be redirected to `/login?redirect_uri=<original_url>`.
4. Sign in with the user you just created.
5. Complete the OTP verification (check the email).
6. You should be redirected back to the original URL.

## Checking the audit log

Every login attempt, OTP send, and session event is recorded in the audit log at `/admin/audit`. This is a good place to confirm that everything is working.
