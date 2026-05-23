CREATE TABLE IF NOT EXISTS webhooks (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    url         TEXT NOT NULL DEFAULT '',
    token       TEXT NOT NULL DEFAULT '',
    chat_id     TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL DEFAULT '',
    password    TEXT NOT NULL DEFAULT '',
    topic       TEXT NOT NULL DEFAULT '',
    events      TEXT NOT NULL DEFAULT 'all',
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id           TEXT PRIMARY KEY,
    webhook_id   TEXT NOT NULL,
    webhook_name TEXT NOT NULL,
    event        TEXT NOT NULL,
    status       TEXT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS notif_created ON notifications(created_at);
CREATE INDEX IF NOT EXISTS notif_webhook ON notifications(webhook_id);
