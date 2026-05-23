CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_members (
    policy_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (policy_id, user_id)
);

ALTER TABLE oidc_clients ADD COLUMN policy_id TEXT NOT NULL DEFAULT '';
