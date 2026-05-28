---
title: Backups
description: Encrypted database backups to local storage or any S3-compatible object store.
---

GateKeeper stores all of its state - users, sessions, OIDC clients, groups, settings - in a single SQLite file. The Backups page lets you snapshot that file on demand or on a schedule, encrypt it, and store it locally or in the cloud.

Manage backups at `/admin/backups`.

## How it works

1. GateKeeper uses SQLite's `VACUUM INTO` statement to create a consistent, read-consistent copy of the database without locking out normal operations.
2. The snapshot is encrypted with AES-256-GCM. The key is derived from your `SECRET_KEY` using SHA-256.
3. The encrypted file is uploaded to your configured storage backend.
4. A record is added to the backup history table so you can see, download, and restore past backups from the UI.

Backups are named by timestamp: `gatekeeper-2025-01-15T14-30-00Z.db.enc`.

## Storage backends

### Local filesystem

Writes the encrypted backup to a directory inside the container. To persist backups across container restarts, bind-mount a host directory to the path you configure:

```yaml
volumes:
  - /host/path/backups:/backups
```

Then set the directory path to `/backups` in the UI.

### S3-compatible

Works with any S3-compatible object store:

| Provider | Notes |
|---|---|
| AWS S3 | Set region to your bucket's region. Path-style: No. |
| Cloudflare R2 | Endpoint: `https://<account-id>.r2.cloudflarestorage.com`. Region: `auto`. Path-style: No. |
| Backblaze B2 | Endpoint: `https://s3.<region>.backblazeb2.com`. Path-style: No. |
| MinIO | Use your MinIO endpoint. Path-style: Yes. |
| Garage | Use your Garage endpoint. Path-style: Yes. |

**Key prefix** organises backup objects inside the bucket. The default `gatekeeper/` keeps backups in their own virtual folder.

## Configuration

| Field | Description |
|---|---|
| Storage type | `Disabled`, `Local filesystem`, or `S3-compatible`. |
| Directory path | (Local) Absolute path inside the container where backups are written. |
| Endpoint URL | (S3) Full URL of the S3 endpoint. |
| Bucket | (S3) Bucket name. |
| Region | (S3) AWS region or `auto` for Cloudflare R2. |
| Access key | (S3) S3 access key ID. |
| Secret key | (S3) S3 secret access key. Leave blank to keep the current value. |
| Key prefix | (S3) Object key prefix. Default: `gatekeeper/`. |
| Path-style addressing | (S3) Use `Yes` for self-hosted stores (MinIO, Garage). Use `No` for AWS, R2, B2. |
| Automatic backups | How often to run automatic backups: manual only, hourly, daily, or weekly. |
| Retention count | How many backups to keep. The oldest are deleted automatically when a new one is created. |

## Running a backup

Click **Back up now** from the Backups page to create an immediate snapshot. The page reloads with the new backup in the history table.

## Restoring a backup

Click **Restore** on any backup in the history table. GateKeeper will:

1. Download the encrypted backup from storage.
2. Decrypt it using your `SECRET_KEY`.
3. Write the decrypted database to `<db-path>.restore` (e.g. `/data/gatekeeper.db.restore`).

To complete the restore:

1. Stop GateKeeper.
2. Rename `/data/gatekeeper.db` to `/data/gatekeeper.db.bak` (keep it as a safety copy).
3. Rename `/data/gatekeeper.db.restore` to `/data/gatekeeper.db`.
4. Start GateKeeper.

All active sessions from the backup are restored. Sessions created after the backup was taken are lost.

:::warning
You must use the same `SECRET_KEY` that was active when the backup was created. A different key cannot decrypt the backup.
:::

## Downloading a backup

Click **Download** on any backup to download the raw encrypted file to your browser. You can decrypt it offline with any AES-256-GCM implementation. The key is the SHA-256 hash of your `SECRET_KEY`.

## Automatic backups

Set **Automatic backups** to a schedule other than "Manual only". The scheduler starts from GateKeeper's launch time - an hourly schedule creates a backup one hour after startup, then every hour after that.

Schedule changes take effect after the next restart.

## Retention

The **Retention count** controls how many backups are kept per storage backend. When a new backup is created and the count exceeds the retention limit, the oldest backups are deleted from both the storage backend and the history table automatically.
