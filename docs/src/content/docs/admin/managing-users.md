---
title: Managing users
description: Create, edit, disable, and delete users from the admin panel.
---

## Creating a user

Go to `/admin/users` and click **New user**. Enter an email address and choose a sign-in method:

- **Email + Password** - the user gets a temporary password (minimum 12 characters) and is required to change it on first login.
- **Email Only** - creates a passwordless account. The user signs in with just their email address and a one-time code sent to it. No password is set.

If allowed email domains are configured in `/admin/settings`, the email must match one of those domains.

## User list

The user list shows each user's avatar, display name (or email if none is set), 2FA status (TOTP enrolled / email only / none), session count, status (active / locked / disabled), and a copy button for the user ID.

Use the filter chips to narrow to **Active**, **Locked**, **Disabled**, or **No 2FA** users. Type in the search box to filter by email or user ID.

## User detail page

Click any user's row or the arrow icon to go to their detail page. From here you can:

### Account actions

- **Set password** - directly set a new password. All sessions are revoked.
- **Send reset email** - sends a self-service password reset link. Expires in 30 minutes.
- **Revoke all sessions** - immediately signs the user out on every device.
- **Toggle passwordless** - enable or disable email-only sign-in for this user.
- **Reset TOTP** - removes the authenticator enrollment and all recovery codes. The user re-enrolls on next login.

### Danger zone

- **Disable account** - the account cannot log in. Sessions are revoked. Reversible.
- **Enable account** - restores a disabled account. No data is lost.
- **Delete user** - permanently removes the account, sessions, OIDC grants, and credentials. Requires typing the email to confirm.

## Locked accounts

If a user fails OTP verification 5 times in 10 minutes, their account is temporarily locked. The detail page shows a warning banner with an **Unlock now** button if you need to restore access before the automatic lockout expires.

## TOTP recovery codes

The detail page shows how many recovery codes remain. GateKeeper stores only argon2id hashes - the actual codes are not recoverable from the database.

## Passkeys

Registered passkeys are listed on the detail page with name and registration date.

## Admin account

Your own admin account (password, TOTP, passkeys) is managed at `/admin/profile` ("My account" in the sidebar).
