CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

ALTER TABLE admin_users ADD COLUMN totp_secret TEXT;
ALTER TABLE admin_users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS admin_passkeys (
    id              TEXT PRIMARY KEY,
    admin_id        TEXT NOT NULL,
    name            TEXT NOT NULL,
    credential_id   TEXT NOT NULL UNIQUE,
    credential_data TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    last_used       INTEGER
);

CREATE TABLE IF NOT EXISTS admin_pending_totp (
    id         TEXT PRIMARY KEY,
    admin_id   TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
