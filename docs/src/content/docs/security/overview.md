---
title: Security overview
description: A summary of GateKeeper's security model and the threats it addresses.
---

GateKeeper is designed to be a trustworthy front door for self-hosted services. This page explains the security model and the threats it is designed to address.

## What GateKeeper protects against

**Stolen passwords.** Passwords alone are not enough. GateKeeper requires a second factor (email OTP, TOTP, or passkey) for every login. Even if a user's password is leaked, an attacker cannot log in without also compromising their email, phone, or device.

**Brute-force attacks.** OTP and TOTP codes are locked after 5 failed attempts in 10 minutes. Password hashing uses argon2id with parameters that make each verification slow enough to be impractical to brute-force.

**Session theft.** Sessions are stored server-side. The cookie only contains an opaque random token. If someone reads your cookie, they can impersonate you until the session expires or is revoked - but they cannot extract other credentials from it.

**Password reset abuse.** Reset tokens are 32 bytes of random data, hashed with argon2id before storage. They expire in 30 minutes and are single-use. Rate limits prevent mass generation of tokens.

**Link preview bots.** Some email clients fetch links automatically to generate previews. GateKeeper's reset tokens are only consumed on a successful POST, not on GET, so a preview bot cannot invalidate a token before the user clicks it.

**Phishing (passkeys).** Passkeys are bound to the specific origin they were created for. A passkey created at `auth.example.com` will not work on a lookalike site.

## What GateKeeper does not protect against

**Compromised server.** If an attacker has shell access to the host, they can read the database, the `SECRET_KEY`, and the session cookies directly. Keep the host secure.

**Email compromise.** Both email OTP and password recovery rely on the user's email inbox. A compromised inbox gives an attacker a path in.

**Session fixation after server compromise.** If an attacker reads `SECRET_KEY`, existing TOTP secrets (which are XOR-encrypted with this key) can be decrypted. Rotate `SECRET_KEY` and revoke all sessions if compromise is suspected.

## Defense in depth

No single security control is perfect. GateKeeper layers multiple controls - strong password hashing, short-lived OTPs, brute-force lockouts, secure cookies, CSRF protection, security headers, and audit logging - so that defeating one control is not enough to compromise the system.
