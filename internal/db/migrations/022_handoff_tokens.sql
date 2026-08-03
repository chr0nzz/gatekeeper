CREATE TABLE IF NOT EXISTS handoff_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    target_host TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS handoff_tokens_expires ON handoff_tokens(expires_at);
