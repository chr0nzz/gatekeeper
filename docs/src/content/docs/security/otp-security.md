---
title: OTP security
description: How email OTPs are generated, rate-limited, and locked out.
---

## Code generation

Email OTPs are 6-digit codes generated using `crypto/rand`, Go's cryptographically secure random number generator. Using `crypto/rand` (rather than the standard `math/rand`) means the codes are unpredictable even if an attacker knows when they were generated.

Each code is associated with a specific user and has a 10-minute expiry. Codes are stored in plaintext in the database because they are short-lived and are invalidated on first use.

## Single use

Once a code is successfully verified, it is marked as used and cannot be reused. If a user requests a new OTP before the old one expires, both the old and the new code exist in the database, but only the most recent one is presented for validation.

## Rate limiting and lockout

To prevent an attacker from guessing a 6-digit code (1,000,000 possibilities):

- After 5 failed OTP attempts within a 10-minute window, the account is locked for 10 minutes.
- The lockout window slides: it resets when 10 minutes have passed since the first failed attempt.

This limits an attacker to roughly 5 guesses per 10 minutes, making systematic brute-force impractical for the duration the code is valid.

## Email delivery

GateKeeper sends OTPs over SMTP using the configured mail server. The email contains the code and a note that it expires in 10 minutes.

No links are included in OTP emails (only the raw code). This prevents link preview bots from "clicking" the login link and consuming the OTP.
