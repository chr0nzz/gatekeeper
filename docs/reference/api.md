---
title: API endpoints
description: All HTTP endpoints, methods, and their behavior.
---

## Authentication endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/login` | Login form |
| `POST` | `/login` | Submit email + password |
| `GET` | `/login/otp` | OTP entry form |
| `POST` | `/login/otp` | Submit OTP code |
| `GET` | `/login/totp` | TOTP challenge form |
| `POST` | `/login/totp` | Submit TOTP code |
| `GET` | `/login/totp/recovery` | Recovery code entry form |
| `POST` | `/login/totp/recovery` | Submit recovery code |
| `GET` | `/login/passkey` | Passkey login page |
| `POST` | `/login/passkey/begin` | Begin WebAuthn assertion |
| `POST` | `/login/passkey/finish` | Finish WebAuthn assertion |
| `POST` | `/logout` | Destroy session |
| `GET` | `/forgot-password` | Forgot password form |
| `POST` | `/forgot-password` | Request reset email |
| `GET` | `/reset-password` | Reset password form (requires `?token=`) |
| `POST` | `/reset-password` | Submit new password |

## Profile endpoints (require session)

| Method | Path | Description |
|---|---|---|
| `GET` | `/profile/password` | Change password form |
| `POST` | `/profile/password` | Submit password change |
| `GET` | `/profile/totp/enroll` | TOTP enrollment page |
| `POST` | `/profile/totp/enroll` | Confirm TOTP enrollment |
| `GET` | `/profile/totp/recovery-codes` | Recovery codes display |
| `GET` | `/profile/totp/disable` | TOTP disable form |
| `POST` | `/profile/totp/disable` | Confirm TOTP disable |
| `GET` | `/register/passkey` | Passkey registration page |
| `POST` | `/register/passkey/begin` | Begin WebAuthn registration |
| `POST` | `/register/passkey/finish` | Finish WebAuthn registration |

## Reverse proxy integration

| Method | Path | Description |
|---|---|---|
| `GET` | `/auth/verify` | Forward auth verification endpoint. Returns `200` with identity headers on success, or `401` when the session is missing or invalid. Append `?policy=<name>` to enforce an access policy (returns `403` on denial). |

**Response headers on 200:**

| Header | Value |
|---|---|
| `X-Auth-User` | The authenticated user's internal UUID |
| `X-Auth-Email` | The authenticated user's email address |
| `X-Auth-Groups` | Comma-separated group names (omitted when the user has no groups) |

## OIDC provider

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/oauth/jwks` | JSON Web Key Set for token verification |
| `GET` | `/oauth/authorize` | Authorization endpoint |
| `POST` | `/oauth/token` | Token endpoint |
| `GET/POST` | `/oauth/userinfo` | UserInfo endpoint |

## Admin endpoints (require admin session)

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/login` | Admin login form |
| `POST` | `/admin/login` | Submit admin credentials |
| `POST` | `/admin/logout` | Destroy admin session |
| `GET` | `/admin/users` | User list |
| `POST` | `/admin/users` | Create user |
| `GET` | `/admin/users/:id` | User detail |
| `POST` | `/admin/users/:id/password` | Set user password |
| `POST` | `/admin/users/:id/reset-email` | Send reset email |
| `POST` | `/admin/users/:id/disable` | Disable account |
| `POST` | `/admin/users/:id/enable` | Enable account |
| `POST` | `/admin/users/:id/delete` | Delete account |
| `POST` | `/admin/users/:id/revoke-sessions` | Revoke all sessions |
| `POST` | `/admin/users/:id/revoke-totp` | Revoke TOTP enrollment |
| `POST` | `/admin/users/:id/passwordless` | Toggle passwordless mode |
| `GET` | `/admin/clients` | OIDC client list |
| `POST` | `/admin/clients` | Create OIDC client |
| `POST` | `/admin/clients/:id/delete` | Delete OIDC client |
| `GET` | `/admin/audit` | Audit log |
| `GET` | `/admin/settings` | Settings page |

## Static assets

| Path | Description |
|---|---|
| `/static/css/main.css` | Main stylesheet |
| `/static/js/passkey.js` | WebAuthn JavaScript |
