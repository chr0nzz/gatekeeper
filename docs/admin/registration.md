# User registration

GateKeeper supports four registration modes. The default is **disabled** - only admins can create accounts. Change the mode in **Admin - Settings - Registration**.

## Modes

### Disabled (default)

The `/register` page returns a 404. Only admins can create accounts from the Users page. Invite links still work regardless of this setting.

### Invite only

No self-registration form is shown. Users can only register by following an invite link created by an admin. See [Invite links](/admin/invites).

### Open

Anyone can create an account at `/register`. A "Create account" link appears on the sign-in page. Accounts are active immediately after registration.

### Approval required

Anyone can submit a registration request at `/register`. Accounts are created in a pending state and disabled until an admin approves them. A "Pending approval" banner appears at the top of the Users page when requests are waiting.

## Allowed domains

The **Allowed domains for registration** field restricts which email addresses can self-register. Enter one or more domains separated by commas:

```
example.com, company.org
```

Leave blank to allow any domain. This setting only applies to open and approval modes - it has no effect on invite links, which bypass the domain check.

## Approval queue

When using approval mode, pending requests appear at the top of the Users page. For each request you can:

- **Approve** - activates the account. The user can then sign in immediately.
- **Reject** - deletes the account request permanently.

## Audit log

| Event | When |
|-------|------|
| `user.registered` | A user submitted a registration form. |
| `user.approved` | An admin approved a pending account. |
| `user.rejected` | An admin rejected a pending account. |
