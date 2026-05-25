---
title: OTP security
description: How email OTPs are generated, stored, rate-limited, and locked out.
---

## Code generation

Email OTPs are 6-digit codes generated using `crypto/rand`, Go's cryptographically secure random number generator. Using `crypto/rand` (rather than the standard `math/rand`) means the codes are unpredictable even if an attacker knows when they were generated.

Each code is associated with a specific user and has a 10-minute expiry. Codes are marked used on first successful verification and cannot be reused.

## Storage

OTP codes are stored as HMAC-SHA256 digests keyed with the application's `SECRET_KEY`, not as plaintext. When verifying a submitted code, GateKeeper computes the HMAC of the submitted value and compares it to the stored digest using a constant-time comparison.

This means a database dump without `SECRET_KEY` cannot be used to reconstruct valid codes or brute-force the 1,000,000-possibility space without also knowing the key.

## Issuance rate limiting

A user can request at most 3 new OTP codes within any 10-minute window. If they request more - for example by repeatedly clicking "resend" - they receive an error and must wait for the window to reset. This prevents using the issuance endpoint to overwhelm a mail server or probe for account existence.

## Verification lockout

To prevent an attacker from guessing a 6-digit code:

- After 5 failed OTP attempts within a 10-minute window, the account is locked for 10 minutes.
- The lockout window slides: it resets when 10 minutes have passed since the first failed attempt.

This limits an attacker to roughly 5 guesses per 10 minutes, making systematic brute-force impractical for the duration the code is valid.

## Email delivery

GateKeeper sends OTPs over SMTP using the configured mail server. The email contains the code and a note that it expires in 10 minutes.

No links are included in OTP emails - only the raw code. This prevents link preview bots from consuming the OTP before the user sees it.
