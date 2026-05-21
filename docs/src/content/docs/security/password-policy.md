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

## Minimum length

Passwords must be at least **12 characters**. This is enforced server-side on every code path that sets or verifies a password. There is no maximum length.

There is no complexity requirement (uppercase, numbers, symbols). Length is a better predictor of password strength than complexity rules, and complexity requirements tend to produce patterns like `Password1!` that are predictable.

## Forced password change

When an admin creates a user or directly sets a password, the `force_password_change` flag is set. The user is redirected to `/profile/password` before they can access anything else, and they cannot skip this step.

After the user sets their own password, the flag is cleared.

## Reset token security

Password reset tokens are 32 bytes of cryptographically random data. GateKeeper stores the argon2id hash of the token, not the token itself. The hash uses a fixed salt (`gatekeeper-reset-token-salt-v1xx`) applied to the raw random bytes. Tokens expire in 30 minutes and are single-use.
