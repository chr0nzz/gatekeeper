---
title: Security overview
description: A summary of GateKeeper's security model and the threats it addresses.
---

GateKeeper is designed to be a trustworthy front door for self-hosted services. This page explains the security model and the threats it is designed to address.

## What GateKeeper protects against

**Stolen passwords.** Passwords alone are not enough. GateKeeper requires a second factor (email OTP, TOTP, or passkey) for every login. Even if a user's password is leaked, an attacker cannot log in without also compromising their email, phone, or device.

**Brute-force attacks on login.** After 20 failed login attempts from the same IP address within 15 minutes, all further attempts from that IP are rejected until the window resets. This applies before the password check, so it slows automated credential-stuffing regardless of whether the email is valid.

**Brute-force attacks on OTP and TOTP.** OTP and TOTP codes lock the account after 5 failed attempts within 10 minutes. Accounts unlock automatically after 10 minutes.

**Slow password cracking.** Password hashing uses argon2id with parameters that make each verification take roughly 100-200ms on typical hardware. Even with a full database dump, recovering passwords at scale is not practical.

**Session theft.** Sessions are stored server-side. The cookie only contains an opaque random token. If someone reads your cookie, they can impersonate you until the session expires or is revoked - but they cannot extract other credentials from it.

**Cross-site request forgery (CSRF).** Every state-changing POST request - password change, 2FA enrollment, session revocation, passkey deletion - requires a CSRF token that matches a value set in a cookie. Form submissions from other sites do not carry this token and are rejected.

**Database exposure of OTP codes.** Email OTP codes are stored as HMAC-SHA256 digests keyed with the application secret, not as plaintext. A database dump without the secret key cannot be used to reconstruct or brute-force active codes.

**Database exposure of TOTP secrets.** TOTP secrets are encrypted with AES-256-GCM before being stored. The encryption key is derived from `SECRET_KEY` using SHA-256. A database dump without the key cannot be used to clone authenticator apps.

**Password reset abuse.** Reset tokens are 32 bytes of random data, hashed with argon2id before storage. They expire in 30 minutes and are single-use. Rate limits prevent mass generation of tokens.

**Link preview bots.** Some email clients fetch links automatically to generate previews. GateKeeper's reset tokens are only consumed on a successful POST, not on GET, so a preview bot cannot invalidate a token before the user clicks it.

**Phishing (passkeys).** Passkeys are bound to the specific origin they were created for. A passkey created at `auth.example.com` will not work on a lookalike site.

## What GateKeeper does not protect against

**Compromised server.** If an attacker has shell access to the host, they can read the database, the `SECRET_KEY`, and the session cookies directly. Keep the host secure.

**Email compromise.** Both email OTP and password recovery rely on the user's email inbox. A compromised inbox gives an attacker a path in.

**Compromise of SECRET_KEY.** TOTP secrets and OTP HMACs are keyed with `SECRET_KEY`. If the key is compromised, rotate it immediately and revoke all sessions. Users will need to re-enroll TOTP since the encrypted secrets in the database cannot be decrypted with the new key.

## Defense in depth

No single security control is perfect. GateKeeper layers multiple controls - strong password hashing, HMAC-keyed OTP storage, AES-GCM TOTP encryption, short-lived OTPs, brute-force lockouts, IP-based login rate limiting, secure cookies, CSRF protection, security headers, and audit logging - so that defeating one control is not enough to compromise the system.
