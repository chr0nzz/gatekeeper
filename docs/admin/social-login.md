---
title: Social login
description: Let users sign in with GitHub, Google, or Discord.
---

# Social login

GateKeeper supports OAuth2 sign-in via GitHub, Google, and Discord. When a provider is enabled, a **Continue with ...** button appears on the login page. Users can also link or unlink providers from their profile page.

## How it works

1. The user clicks a social login button.
2. GateKeeper redirects to the provider's authorization page.
3. After the user approves, the provider redirects back to GateKeeper with an authorization code.
4. GateKeeper exchanges the code for an access token and fetches the user's profile.
5. GateKeeper looks up the provider identity in its database:
   - **Found** - logs in as the linked user.
   - **Not found, email matches existing user** - links the provider to that account and logs in.
   - **Not found, no match** - creates a new account (if registration is open) or shows an error.

## Configuration

Go to **Admin** > **Settings** > **Social login**.

For each provider you want to enable:

1. Create an OAuth2 application on the provider's developer console (see below).
2. Enter the **Client ID** and **Client secret** in the Settings page.
3. Check **Enable** and save.

### Callback URL

Set the redirect / callback URL in the provider's developer console to:

```
https://your-gatekeeper-domain/auth/social/{provider}/callback
```

Replace `{provider}` with `github`, `google`, or `discord`.

### GitHub

1. Go to **GitHub** > **Settings** > **Developer settings** > **OAuth Apps** > **New OAuth App**.
2. Set **Authorization callback URL** to `https://your-domain/auth/social/github/callback`.
3. Copy the **Client ID** and generate a **Client secret**.

Required scope: `user:email` (GateKeeper requests this automatically).

### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/) > **APIs & Services** > **Credentials** > **Create credentials** > **OAuth client ID**.
2. Choose **Web application**.
3. Add `https://your-domain/auth/social/google/callback` under **Authorized redirect URIs**.
4. Copy the **Client ID** and **Client secret**.

Required scope: `openid email profile` (GateKeeper requests this automatically).

### Discord

1. Go to [Discord Developer Portal](https://discord.com/developers/applications) > **New Application**.
2. Under **OAuth2**, add `https://your-domain/auth/social/discord/callback` as a redirect.
3. Copy the **Client ID** and **Client secret** from the OAuth2 page.

Required scope: `identify email` (GateKeeper requests this automatically).

## Environment variables

You can seed the provider credentials via environment variables. GateKeeper writes them to the settings database on first startup if the setting is not already set. The admin UI takes precedence after that.

| Variable | Description |
|---|---|
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret |
| `GOOGLE_CLIENT_ID` | Google OAuth2 client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth2 client secret |
| `DISCORD_CLIENT_ID` | Discord application client ID |
| `DISCORD_CLIENT_SECRET` | Discord application client secret |

Note: setting env vars does **not** enable the provider. You still need to check **Enable** in the Settings UI and save.

## Linking accounts

Users can connect or disconnect social providers from their profile page (`/`). The **Connected accounts** card shows all enabled providers and their link status.

A provider cannot be disconnected if it is the only login method and the account has no password set.

## Registration behavior

When a social login creates a new user, the [registration mode](/admin/registration) setting applies:

| Mode | Behavior |
|---|---|
| `disabled` or `invite_only` | Error - no account linked, contact admin |
| `open` | Account created automatically |
| `approval` | Account created in pending state, admin must approve |

Domain restrictions from **Allowed domains for registration** also apply.
