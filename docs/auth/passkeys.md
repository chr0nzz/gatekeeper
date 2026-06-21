---
title: Passkeys
description: Set up and use passkeys (WebAuthn) for passwordless, phishing-resistant login.
---

A passkey is a cryptographic key stored on your device - your laptop, phone, or a hardware security key. Instead of typing a password and waiting for a code, you authenticate using your device's built-in method: fingerprint, face recognition, or PIN.

Passkeys implement the WebAuthn standard (also called FIDO2). They are phishing-resistant because the key is bound to the specific website it was created for. A passkey created for `auth.example.com` will never work on `auth-example.com`.

## Registering a passkey

You must be logged in to register a passkey (use password + OTP for your first login).

1. Go to `/register/passkey`.
2. Give the passkey a name so you can identify it later (for example, "MacBook" or "iPhone").
3. Click **Register passkey**. Your browser will ask you to use your fingerprint, face, or device PIN.
4. Done.

You can register multiple passkeys - one per device is typical.

## Logging in with a passkey

Go to `/login/passkey` and click **Use passkey**. Your browser will prompt you to choose a passkey and authenticate with your device.

Passkey login counts as both factors - you do not need to complete OTP or TOTP after a successful passkey authentication.

## Requirements

Passkeys require JavaScript. The login and registration pages load a small JavaScript file (`/static/js/passkey.js`) to handle the WebAuthn API calls. No external scripts are loaded.

Your browser must support WebAuthn. All modern browsers (Chrome, Firefox, Safari, Edge) and most recent mobile browsers support it.

## Multiple passkeys

You can register as many passkeys as you want. This is encouraged - register one on each device you regularly use. If one device is lost, the others still work.

Admins can see which passkeys are registered for a user at `/admin/users/:id`. Individual passkeys can also be revoked from there.

## Admin on a subdomain

Passkeys are bound to the host in `BASE_URL`. When the admin panel runs on its own subdomain (for example `admin.auth.example.com` while `BASE_URL` is `https://auth.example.com`), set the `ADMIN_URL` environment variable to that admin address. GateKeeper adds it to the list of allowed passkey origins so admin passkeys register and sign in correctly.

The admin subdomain must sit under the same registrable domain as `BASE_URL` (both under `example.com` in the example above). Passkeys cannot be shared across entirely separate domains, such as `.app` and `.live`.
