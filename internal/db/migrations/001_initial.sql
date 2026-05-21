CREATE TABLE IF NOT EXISTS users (
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

CREATE TABLE IF NOT EXISTS admin_users (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id          TEXT PRIMARY KEY,
    admin_id    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS otps (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    code        TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS otps_user_id ON otps(user_id);

CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    used_at     INTEGER,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS totp_recovery_user ON totp_recovery_codes(user_id);

CREATE TABLE IF NOT EXISTS passkeys (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    name            TEXT NOT NULL,
    credential_id   TEXT NOT NULL UNIQUE,
    credential_data TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    last_used       INTEGER
);

CREATE INDEX IF NOT EXISTS passkeys_user_id ON passkeys(user_id);

CREATE TABLE IF NOT EXISTS webauthn_sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,
    data        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    redeemed_at INTEGER
);

CREATE INDEX IF NOT EXISTS prt_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS prt_token_hash ON password_reset_tokens(token_hash);

CREATE TABLE IF NOT EXISTS oidc_clients (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL UNIQUE,
    client_secret   TEXT NOT NULL,
    redirect_uris   TEXT NOT NULL,
    name            TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_auth_requests (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    user_id         TEXT,
    redirect_uri    TEXT NOT NULL,
    state           TEXT NOT NULL,
    nonce           TEXT,
    scopes          TEXT NOT NULL,
    code_challenge  TEXT,
    code_challenge_method TEXT,
    response_type   TEXT NOT NULL,
    done            INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_tokens (
    id              TEXT PRIMARY KEY,
    auth_request_id TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    access_token    TEXT NOT NULL UNIQUE,
    refresh_token   TEXT UNIQUE,
    scopes          TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    access_expires  INTEGER NOT NULL,
    refresh_expires INTEGER
);

CREATE INDEX IF NOT EXISTS oidc_tokens_refresh ON oidc_tokens(refresh_token);
CREATE INDEX IF NOT EXISTS oidc_tokens_access ON oidc_tokens(access_token);

CREATE TABLE IF NOT EXISTS oidc_signing_keys (
    id          TEXT PRIMARY KEY,
    private_key TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    rotated_at  INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    event       TEXT NOT NULL,
    user_id     TEXT,
    actor_id    TEXT,
    ip          TEXT,
    detail      TEXT,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_created ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS otp_lockouts (
    user_id     TEXT NOT NULL,
    lockout_type TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    window_start INTEGER NOT NULL,
    PRIMARY KEY (user_id, lockout_type)
);

CREATE TABLE IF NOT EXISTS reset_rate_limits (
    key         TEXT NOT NULL,
    key_type    TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    window_start INTEGER NOT NULL,
    PRIMARY KEY (key, key_type)
);
