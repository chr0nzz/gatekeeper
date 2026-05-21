---
title: TOTP security
description: TOTP implementation details, clock skew handling, secret encryption, and recovery codes.
---

## TOTP standard

GateKeeper implements TOTP according to RFC 6238 with these parameters:

| Parameter | Value | Why |
|---|---|---|
| Algorithm | SHA1 | Required for compatibility with Google Authenticator and most apps |
| Digits | 6 | Standard for TOTP; 8-digit codes offer marginally more security but are harder to type |
| Period | 30 seconds | Standard for TOTP |

## Clock skew

TOTP codes are derived from the current time, so if the server clock and the user's device clock differ, a valid code might fail. GateKeeper accepts the code from the current 30-second window and the previous window, giving a tolerance of up to 30 seconds of clock skew.

## Secret storage

TOTP secrets are sensitive because anyone with the secret can generate valid codes indefinitely. GateKeeper encrypts TOTP secrets at rest using XOR with the `SECRET_KEY` before storing them in the database.

This is a simple encryption scheme - not AES-GCM - but it means the secrets are not stored in plaintext. If you need stronger at-rest encryption, consider encrypting the entire SQLite file at the filesystem level using LUKS or dm-crypt.

## Brute-force protection

After 5 failed TOTP attempts within 10 minutes, the account is locked for 10 minutes. This matches the OTP lockout behavior and limits guessing attacks.

## Recovery codes

Recovery codes are 10-character alphanumeric strings formatted as groups separated by hyphens (for example, `aB-3x-Qz-7m-Kp`). They are generated using `crypto/rand`.

Each code is stored as an individual argon2id hash. This means:

- The codes cannot be recovered from the database, even by an admin.
- Verifying a recovery code requires checking each stored hash until one matches - this is intentionally slow to prevent brute-force.
- Once a code is used, it is permanently marked as consumed and cannot be reused.

8 codes are generated per enrollment. The count of unused codes is visible to admins.
