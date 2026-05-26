# Invite links

Invite links let you onboard specific people without opening registration to everyone. Each link is single-use and expires after the period you choose when creating it.

## Creating an invite

Go to **Admin - Invites** and click **New invite**.

| Field | Required | Description |
|-------|----------|-------------|
| Email address | No | Pre-fills the registration form with this address and prevents the user from changing it. Leave blank to allow any email. |
| Note | No | Internal reminder for yourself - not shown to the invitee. |
| Expires after | Yes | How long the link stays valid. Choices are 1, 3, 7, 14, or 30 days. Default is 7 days. |

After clicking **Create invite**, the generated link appears at the top of the page. Copy it and share it with the person you want to invite. The raw token is only shown once - GateKeeper stores only a hash and cannot display it again.

## What the invitee sees

Opening the link takes the user to `/register?invite=<token>`. They see a form with:

- **Email** - pre-filled and locked if you specified an address, or editable if you left it blank.
- **Password** and **Confirm password** - must be at least 8 characters.

On successful registration, the account is created immediately and the user is signed in. The invite link is then marked as used and cannot be reused.

## Invite statuses

| Status | Meaning |
|--------|---------|
| Active | Valid and unused, can still be opened. |
| Used | Registration was completed. |
| Expired | The expiry time passed before anyone used it. |

## Revoking an invite

Click the trash icon next to any active invite to revoke it. The link will stop working immediately. Used and expired invites are kept for audit purposes but cannot be revoked (they are already inactive).

## Audit log

Every invite action is recorded:

| Event | When |
|-------|------|
| `invite.created` | An admin generated an invite. |
| `invite.used` | A user registered with the link. |
| `invite.revoked` | An admin deleted an invite. |
