---
title: Password recovery
description: How the forgot-password flow works, including token security and rate limits.
---

Users who forget their password can request a reset link at `/forgot-password`. The link is sent to their email and expires after 30 minutes.

## The flow

1. User visits `/forgot-password` and enters their email.
2. GateKeeper responds with the same confirmation message regardless of whether the email matches a real account. This prevents an attacker from discovering which emails are registered.
3. If the email does match an account, GateKeeper generates a secure reset token, stores a hash of it in the database, and emails a link to the user.
4. The user clicks the link, which goes to `/reset-password?token=<token>`.
5. GateKeeper validates the token (checks it exists, is unexpired, and has not been used yet) and shows a password reset form.
6. The user sets a new password. GateKeeper marks the token as used, invalidates all existing sessions for that account, and redirects to `/login`.

## Token security

Reset tokens are 32 bytes of cryptographically random data, hex-encoded. GateKeeper stores the argon2id hash of the token, not the token itself. If the database is compromised, the stored hashes cannot be reversed into working tokens.

Tokens expire after 30 minutes. They are single-use: once a POST to `/reset-password` succeeds, the token is permanently invalidated.

A note on link preview bots: some email clients fetch links in emails automatically to generate previews. To prevent these bots from consuming a reset token before the user clicks it, GateKeeper only marks a token as used when the POST request succeeds, not when the GET request views the form.

## Rate limits

To prevent abuse:

- Maximum 3 reset requests per email address per hour.
- Maximum 10 reset requests per IP address per hour.

When a limit is hit, GateKeeper still shows the same generic confirmation message to the user. The actual email is simply not sent.

## Audit log

Every reset request, successful reset, and invalid token attempt is recorded in the audit log with the event type and IP address.
