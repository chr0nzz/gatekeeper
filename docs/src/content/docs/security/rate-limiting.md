---
title: Rate limiting
description: How GateKeeper limits login attempts, OTP requests, and password resets.
---

GateKeeper applies rate limits at several points in the authentication flow to slow down automated attacks.

## Login - IP-based limit

The login endpoint (`POST /login`) tracks failed attempts per client IP address.

| Limit | Window | Action on breach |
|---|---|---|
| 20 failed attempts | 15 minutes | All further attempts from that IP return an error until the window resets |

The counter increments on every response that would have said "Invalid credentials" - wrong password, unknown email, or disabled account. Successful logins do not increment it.

The limit is enforced before any database lookup, so it also slows credential-stuffing attacks where the attacker does not know which emails are registered.

The window is in-memory and resets when the server restarts. There is no persistent block - the window is rolling.

## OTP - issuance limit

To prevent OTP spam and mail server abuse, each user can request at most 3 new OTP codes within a 10-minute window.

| Limit | Window | Action on breach |
|---|---|---|
| 3 OTP requests per user | 10 minutes | Error returned; no code is generated or sent |

## OTP and TOTP - verification lockout

After too many wrong codes are submitted, the account is temporarily locked.

| Limit | Window | Lockout duration |
|---|---|---|
| 5 failed OTP attempts | 10 minutes (sliding) | 10 minutes |
| 5 failed TOTP attempts | 10 minutes (sliding) | 10 minutes |

The window is sliding: it resets when 10 minutes have passed since the first failed attempt in the current window. Lockout state is stored in the database and survives server restarts.

During lockout, even a correct code is rejected. This is intentional - it prevents an attacker from succeeding on the 6th attempt by simply waiting for the right code.

## Password reset - rate limit

Password reset emails are rate-limited to prevent abuse of the mail sender.

| Limit | Scope | Window |
|---|---|---|
| 3 reset emails | Per email address | 1 hour |
| 10 reset emails | Per IP address | 1 hour |

When the limit is hit, the endpoint still responds as if an email was sent - it just silently drops the request. This prevents confirming whether an address is registered.

## What is not rate limited

- Password change (already requires the current password, TOTP if enrolled, and an active session)
- Passkey registration (requires an active session)
- Admin login (protected by the same argon2id hashing cost; consider deploying admin behind an IP allowlist)
