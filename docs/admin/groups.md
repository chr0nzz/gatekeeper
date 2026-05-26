# Groups

Groups let you organize users and expose their membership as a `groups` claim in OIDC tokens. Apps like Grafana and Jellyfin use this claim for role mapping.

## How groups work

When a user authenticates via OIDC, their groups are automatically included in the token:

```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "groups": ["admins", "media"]
}
```

No scope configuration is required - the `groups` claim is always included for users who belong to at least one group (an empty array `[]` is included for users with no groups).

## Creating a group

1. Go to **Admin > Groups**
2. Click **New group**
3. Enter a name - this exact string will appear in the `groups` claim (case-sensitive)
4. Add an optional description
5. Click **Create group**

## Managing members

Open a group to add or remove members. You can also manage a user's group memberships from their profile page under **Admin > Users > [user]**.

## Configuring Grafana role mapping

In Grafana's OAuth configuration, map the `groups` claim to Grafana roles:

```ini
[auth.generic_oauth]
enabled = true
name = GateKeeper
client_id = your-client-id
client_secret = your-client-secret
auth_url = https://auth.example.com/authorize
token_url = https://auth.example.com/oauth/token
api_url = https://auth.example.com/userinfo
scopes = openid email profile
role_attribute_path = contains(groups[*], 'grafana-admins') && 'Admin' || contains(groups[*], 'grafana-editors') && 'Editor' || 'Viewer'
```

## Configuring Jellyfin role mapping

In Jellyfin with the SSO plugin, map the `groups` claim to Jellyfin roles by setting the **Admin Roles** field to the name of your admins group.

## Difference between groups and policies

| | Groups | Policies |
|---|---|---|
| **Purpose** | Role mapping inside apps | Restrict access to apps |
| **Token** | Included as `groups` claim | Not in token |
| **Use case** | Grafana Admin vs Viewer | Only certain users can log into an app |
