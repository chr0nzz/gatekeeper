CREATE TABLE IF NOT EXISTS trusted_devices (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    user_agent  TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS trusted_devices_user ON trusted_devices(user_id);
