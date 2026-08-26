---
title: Password policy
description: How passwords are hashed, minimum length, and forced reset on first login.
---

## Hashing algorithm

GateKeeper uses **argon2id** for all password hashing. Argon2id is the winner of the Password Hashing Competition and is recommended by OWASP for new applications.

The specific parameters used:

| Parameter | Value |
|---|---|
| Memory | 64 MB |
| Iterations | 3 |
| Parallelism | 4 |
| Output length | 32 bytes |
| Salt length | 16 bytes (random per hash) |

These match the OWASP recommended minimum for argon2id. They mean each password verification takes roughly 100-200ms on typical hardware, which is slow enough to make brute-force attacks impractical.

A new random salt is generated for every hash, so two users with the same password have different hashes in the database.

Each stored hash records the parameters it was created with, so these values can be changed without invalidating existing passwords. Hashes written by versions before v0.9.7 did not record them, and are rewritten in the current format the next time that person signs in.

## Policy settings

The policy is configured under **Settings - Password policy** and applies immediately, with no restart.

| Setting | Default | Range |
|---|---|---|
| Minimum length | 12 | 8 to 128 |
| Require at least one uppercase letter | Off | On or off |
| Require at least one number | Off | On or off |
| Require at least one symbol | Off | On or off |

There is no maximum length.

### Where it applies

The policy is enforced server-side on every path that sets a password:

- Self-registration
- Password reset through the forgot-password email
- A user changing their own password
- An admin creating a user with a temporary password
- An admin setting or resetting a user's password
- Creating an admin account, promoting a user to admin, and the first-run setup page
- An admin changing their own password

The form fields also carry the configured minimum, so the browser shows the same requirement the server enforces.

### Choosing a policy

Length does more for password strength than character rules, so raising the minimum is usually a better move than switching the character requirements on. Requirements like "must contain a symbol" tend to push people toward predictable shapes such as `Password1!`.

The character requirements exist because many organisations have to meet a written standard that names them. If that applies to you, turn on what you need. If it does not, a longer minimum with the requirements left off is the stronger setting.

## Forced password change

When an admin creates a user or directly sets a password, the `force_password_change` flag is set. The user is redirected to `/profile/password` before they can access anything else, and they cannot skip this step.

After the user sets their own password, the flag is cleared.

## Reset token security

Password reset tokens are 32 bytes of cryptographically random data. GateKeeper stores a SHA-256 digest of the token, not the token itself. A plain digest is the right choice here because the token is already 256 bits of randomness, so there is nothing to guess and nothing for a slow hash to protect. Tokens expire in 30 minutes and are single-use.
