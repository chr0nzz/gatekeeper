---
title: TOTP security
description: TOTP implementation details, clock skew handling, secret encryption, and recovery codes.
---

## TOTP standard

GateKeeper implements TOTP according to RFC 6238 with these parameters:

| Parameter | Value | Why |
|---|---|---|
| Algorithm | SHA1 | Required for compatibility with Google Authenticator and most apps |
| Digits | 6 | Standard for TOTP |
| Period | 30 seconds | Standard for TOTP |

## Clock skew

TOTP codes are derived from the current time, so if the server clock and the user's device clock differ, a valid code might fail. GateKeeper accepts the code from the current 30-second window and the previous window, giving a tolerance of up to 30 seconds of clock skew.

## Secret encryption

TOTP secrets are sensitive - anyone who obtains a secret can generate valid codes indefinitely without the physical device. GateKeeper encrypts every TOTP secret with **AES-256-GCM** before storing it in the database.

How it works:

1. A 32-byte AES key is derived from `SECRET_KEY` using SHA-256. This means the actual key is always 256 bits regardless of how long `SECRET_KEY` is.
2. A random 12-byte nonce is generated for each encryption using `crypto/rand`.
3. The secret is encrypted with AES-GCM. Because GCM is an authenticated encryption mode, any tampering with the stored ciphertext is detected on decryption.
4. The nonce is prepended to the ciphertext, base64-encoded, and stored with a `v2:` version prefix.

**Upgrading from older versions.** If you ran GateKeeper before v0.4.0, existing TOTP secrets were stored with a simpler XOR-based scheme. They are automatically re-encrypted with AES-256-GCM the first time each user successfully logs in with their TOTP code. No manual migration step is needed.

**If SECRET_KEY is compromised.** Rotate `SECRET_KEY` immediately and revoke all sessions. Users who enrolled TOTP with the old key will need to re-enroll, because their encrypted secrets in the database cannot be decrypted with the new key.

## Brute-force protection

After 5 failed TOTP attempts within 10 minutes, the account is locked for 10 minutes. This matches the OTP lockout behavior.

## Recovery codes

Recovery codes are 10-character alphanumeric strings formatted as groups separated by hyphens (for example, `aB-3x-Qz-7m-Kp`). They are generated using `crypto/rand`.

Each code is stored as an individual argon2id hash. This means:

- The codes cannot be recovered from the database, even by an admin.
- Verifying a recovery code requires checking each stored hash until one matches - this is intentionally slow to prevent brute-force.
- Once a code is used, it is permanently marked as consumed and cannot be reused.

8 codes are generated per enrollment. The count of unused codes is visible to admins.
