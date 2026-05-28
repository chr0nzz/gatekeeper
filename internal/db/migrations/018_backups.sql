CREATE TABLE IF NOT EXISTS backups (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    storage    TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
