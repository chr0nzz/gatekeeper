---
title: Database schema
description: SQLite table definitions for all GateKeeper tables.
---

GateKeeper uses a single SQLite database. The schema is managed by embedded SQL migration files that run automatically on startup.

## users

```sql
CREATE TABLE users (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    passwordless_enabled INTEGER NOT NULL DEFAULT 0,
    force_password_change INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    disabled    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
```

`totp_secret` stores the XOR-encrypted secret. `password_hash` is null for users with no password set.

## sessions

```sql
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);
```

`data` is a JSON object containing session state (user ID, pending OTP/TOTP flags, redirect URI).

## otps

```sql
CREATE TABLE otps (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    code        TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);
```

## totp_recovery_codes

```sql
CREATE TABLE totp_recovery_codes (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    used_at     INTEGER,
    created_at  INTEGER NOT NULL
);
```

`code_hash` is an argon2id hash. The raw code is never stored.

## passkeys

```sql
CREATE TABLE passkeys (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    name            TEXT NOT NULL,
    credential_id   TEXT NOT NULL UNIQUE,
    credential_data TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    last_used       INTEGER
);
```

`credential_data` is a JSON-serialized `webauthn.Credential` object.

## password_reset_tokens

```sql
CREATE TABLE password_reset_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    redeemed_at INTEGER
);
```

`redeemed_at` is only set on a successful POST reset, not on GET.

## oidc_clients

```sql
CREATE TABLE oidc_clients (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL UNIQUE,
    client_secret   TEXT NOT NULL,
    redirect_uris   TEXT NOT NULL,
    name            TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);
```

`redirect_uris` is a JSON array of strings.

## oidc_signing_keys

```sql
CREATE TABLE oidc_signing_keys (
    id          TEXT PRIMARY KEY,
    private_key TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    rotated_at  INTEGER
);
```

`private_key` is a PEM-encoded RSA private key. `rotated_at` is null for the active key.

## audit_log

```sql
CREATE TABLE audit_log (
    id          TEXT PRIMARY KEY,
    event       TEXT NOT NULL,
    user_id     TEXT,
    actor_id    TEXT,
    ip          TEXT,
    detail      TEXT,
    created_at  INTEGER NOT NULL
);
```

This table is append-only. GateKeeper does not delete or update rows here.

## All timestamps

All `*_at` columns store Unix timestamps (integer seconds since epoch). Use `datetime(created_at, 'unixepoch')` in SQLite to convert to a human-readable form.
