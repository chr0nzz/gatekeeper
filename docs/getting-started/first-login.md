---
title: First login
description: Create your admin account and configure GateKeeper for the first time.
---

## Step 1 - visit the admin panel

After starting GateKeeper for the first time, open your admin URL (the value of `ADMIN_URL`, e.g. `https://admin.auth.example.com`) in your browser. Since no admin account exists yet, GateKeeper redirects you to `/setup`.

The admin panel runs on its own port and domain, served at the root - there is no `/admin` path prefix. The admin paths below are relative to your admin URL.

## Step 2 - create your admin account

Enter your email address and a password (minimum 12 characters). Click **Create admin account**.

This page only appears once. Once an admin account exists, the setup page redirects to the normal login and cannot be accessed again.

## Step 3 - configure SMTP

Without SMTP, GateKeeper cannot send one-time login codes or password reset emails.

Go to `/settings` and fill in your SMTP details, then click **Save changes**. The change takes effect immediately - no restart needed.

## Step 4 - secure your admin account

Go to `/profile` and:

- Enroll an **authenticator app** (TOTP) for a second factor on admin login
- Register a **passkey** if your device supports it (Touch ID, Face ID, or a hardware key)

## Step 5 - create users

Go to `/users` and click **New user**. Choose:

- **Email + Password** - standard account with a temporary password. The user is required to change it on first login.
- **Email Only** - passwordless account. The user signs in with just their email and a one-time code sent to it.

## Step 6 - test the login flow

Open a private browser window and go to `https://auth.example.com/login`. Sign in with the user credentials you created and verify the full flow works.

## Step 7 - protect your apps

- **ForwardAuth** - add the GateKeeper middleware to Traefik to protect any service. See [ForwardAuth setup](/integrations/traefik-forwardauth).
- **OIDC** - register an OIDC client to let apps like Grafana, Jellyfin, or Traefik Manager use GateKeeper as an identity provider. See [Managing OIDC clients](/admin/managing-clients).

## Navigation shortcuts

| Shortcut | Action |
|---|---|
| `⌘K` / `Ctrl+K` | Command palette - search users, clients, navigate |
| `g d` | Dashboard |
| `g u` | Users |
| `g c` | OIDC Clients |
| `g a` | Audit log |
| `g s` | Settings |
