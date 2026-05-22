ALTER TABLE oidc_clients ADD COLUMN icon_data BLOB;
ALTER TABLE oidc_clients ADD COLUMN icon_mime TEXT NOT NULL DEFAULT '';
