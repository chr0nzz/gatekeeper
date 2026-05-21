---
title: First login
description: Create your admin account and configure GateKeeper for the first time.
---

## Step 1 - visit the admin panel

After starting GateKeeper for the first time, go to `/admin` in your browser. Since no admin account exists yet, GateKeeper redirects you to `/admin/setup`.

## Step 2 - create your admin account

Enter your email address and a password (minimum 12 characters). Click **Create admin account**.

This page only appears once. The moment an admin account exists, the setup page redirects to the normal login page and cannot be accessed again.

## Step 3 - configure SMTP

Without SMTP, GateKeeper cannot send one-time login codes or password reset emails, so users cannot log in.

Go to `/admin/settings` and fill in your SMTP details:

- **Host** - your SMTP server address, e.g. `smtp.fastmail.com`
- **Port** - usually `587` for STARTTLS or `465` for TLS
- **Username and password** - your SMTP credentials
- **From address** - the "from" field on outgoing emails, e.g. `noreply@example.com`
- **TLS mode** - `starttls` for port 587, `tls` for port 465

Click **Save settings**. The change takes effect immediately.

## Step 4 - create your first user

Go to `/admin/users` and click **New user**. Enter an email address and a temporary password. The user will be required to change this password on their first login.

## Step 5 - test the login flow

1. Open a private browser window and go to `https://auth.example.com/login`.
2. Sign in with the user credentials you just created.
3. Check the user's email for the one-time code.
4. Enter the code to complete login.

If the email does not arrive, double-check your SMTP settings at `/admin/settings`.

## Step 6 - protect an app with Traefik

See [ForwardAuth setup](/traefik/forwardauth) to configure Traefik to use GateKeeper for a service.
