CREATE TABLE IF NOT EXISTS invites (
    id         TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    email      TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    used_at    INTEGER,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS invites_token ON invites(token_hash);
