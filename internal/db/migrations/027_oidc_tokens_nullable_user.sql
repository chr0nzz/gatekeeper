BEGIN;
CREATE TABLE oidc_tokens_new (
    id              TEXT PRIMARY KEY,
    auth_request_id TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    user_id         TEXT,
    access_token    TEXT NOT NULL UNIQUE,
    refresh_token   TEXT UNIQUE,
    scopes          TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    access_expires  INTEGER NOT NULL,
    refresh_expires INTEGER
);
INSERT INTO oidc_tokens_new (id, auth_request_id, client_id, user_id, access_token, refresh_token, scopes, created_at, access_expires, refresh_expires)
    SELECT id, auth_request_id, client_id, user_id, access_token, refresh_token, scopes, created_at, access_expires, refresh_expires FROM oidc_tokens;
DROP TABLE oidc_tokens;
ALTER TABLE oidc_tokens_new RENAME TO oidc_tokens;
CREATE INDEX oidc_tokens_refresh ON oidc_tokens(refresh_token);
CREATE INDEX oidc_tokens_access ON oidc_tokens(access_token);
COMMIT;
