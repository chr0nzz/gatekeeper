---
title: Managing users
description: Create, edit, disable, and delete users from the admin panel.
---

The user management interface is at `/admin/users`.

## Creating a user

Click **New user**, enter an email and a temporary password (minimum 12 characters), and click **Create**. The user is required to change their password on first login.

## User detail page

Click any user's email or **Manage** to go to their detail page. From here you can:

- **Set password** - directly set a new password. The user is required to change it on next login. All their sessions are revoked.
- **Send reset email** - triggers the self-service password reset flow. A reset link is emailed to the user.
- **Revoke all sessions** - immediately signs the user out everywhere.
- **Revoke TOTP enrollment** - removes the user's authenticator app enrollment. They will be asked to re-enroll on next login if your policy requires it.
- **Enable/disable passwordless** - toggles whether the user can log in without a password (email OTP only).
- **Disable/enable account** - a disabled account cannot log in. All existing sessions are revoked on disable.
- **Delete user** - permanently removes the account. All sessions are revoked first.

## TOTP recovery codes

The user detail page shows how many recovery codes the user has remaining. You cannot see the codes themselves - GateKeeper stores only their hashes.

## Passkeys

Registered passkeys are listed on the user detail page with their names and registration dates.

## Audit log

All admin actions (password set, sessions revoked, TOTP revoked, etc.) are recorded in the audit log with the admin's identity.
