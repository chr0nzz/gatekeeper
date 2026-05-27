CREATE TABLE IF NOT EXISTS client_claims (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    claim_key TEXT NOT NULL,
    value_source TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS client_claims_client ON client_claims(client_id);
