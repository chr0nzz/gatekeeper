---
title: Managing users
description: Create, edit, disable, and delete users from the admin panel.
---

## Creating a user

Go to `/admin/users` and click **New user**. Enter an email address and a temporary password (minimum 12 characters). The user will be required to change this password on their first login.

If you have allowed email domains configured in `/admin/settings`, the email must belong to one of those domains.

## User list

The user list at `/admin/users` shows each user's email, whether passwordless mode is enabled, TOTP status, and account status (active or disabled).

## User detail page

Click any user's email to go to their detail page. From here you can:

- **Set password** - directly set a new password. The user must change it on next login. All their sessions are revoked.
- **Send reset email** - sends a self-service password reset link to the user's email.
- **Revoke all sessions** - immediately signs the user out on every device.
- **Revoke TOTP enrollment** - removes the user's authenticator app. They can re-enroll from their profile.
- **Enable/disable passwordless** - toggles whether the user can log in with only an email OTP (no password).
- **Disable/enable account** - a disabled account cannot log in. All existing sessions are revoked on disable.
- **Delete user** - permanently removes the account.

## TOTP recovery codes

The detail page shows how many recovery codes the user has remaining. You cannot see the codes themselves - GateKeeper stores only their argon2id hashes.

## Passkeys

Registered passkeys are listed with their names and registration dates.

## Admin account management

Your own admin account (password, TOTP, passkeys) is managed at `/admin/profile`, linked as "My account" in the sidebar.

## Audit log

All admin actions are recorded in the audit log at `/admin/audit` with the admin's identity and timestamp.
