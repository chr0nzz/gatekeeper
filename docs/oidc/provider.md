---
title: OIDC provider
description: Use GateKeeper as an OpenID Connect identity provider for any application.
---

GateKeeper is a full OIDC identity provider. Any application that supports OIDC can delegate authentication to it - Traefik Manager, Grafana, Jellyfin, Portainer, or any custom app.

## What this means

Instead of each app managing its own login, they redirect users to GateKeeper. GateKeeper handles authentication (password, passkey, TOTP, email OTP) and returns a verified identity token. Apps never see credentials.

## Endpoints

| Purpose | URL |
|---|---|
| Discovery | `https://auth.example.com/.well-known/openid-configuration` |
| Authorization | `https://auth.example.com/authorize` |
| Token | `https://auth.example.com/oauth/token` |
| Userinfo | `https://auth.example.com/userinfo` |
| JWKS (public keys) | `https://auth.example.com/keys` |
| Issuer | `https://auth.example.com` |

Apps that support OIDC discovery only need the discovery URL - everything else auto-configures.

## Supported flow

**Authorization code + PKCE only.** Implicit flow and client credentials are not supported.

## Supported scopes

| Scope | Claims returned |
|---|---|
| `openid` | `sub` (user ID) |
| `profile` | `preferred_username` (email) |
| `email` | `email`, `email_verified` |
| `offline_access` | Enables refresh tokens |

## Registering a client

1. Go to `/clients` and click **New client**
2. Enter a display name and optionally an icon URL (fetched and cached server-side at save time)
3. Choose a client ID - lowercase, digits, dashes. Public and permanent.
4. Click **Generate** for the client secret. Copy it - it is not shown again.
5. Enter redirect URIs one per line. Must match exactly.

See [Managing OIDC clients](/admin/managing-clients).

## Configuring an app

Most apps work with just the discovery URL, client ID, and client secret:

```
Discovery URL:  https://auth.example.com/.well-known/openid-configuration
Client ID:      your-client-id
Client Secret:  your-client-secret
Scopes:         openid email profile
```

### Python (authlib)

```python
from authlib.integrations.flask_client import OAuth
oauth = OAuth(app)
oauth.register(
    name='gatekeeper',
    server_metadata_url='https://auth.example.com/.well-known/openid-configuration',
    client_id='myapp',
    client_secret='your-client-secret',
    client_kwargs={'scope': 'openid email profile'},
)
```

### Go (go-oidc)

```go
provider, _ := oidc.NewProvider(ctx, "https://auth.example.com")
config := oauth2.Config{
    ClientID:     "myapp",
    ClientSecret: "your-client-secret",
    Endpoint:     provider.Endpoint(),
    RedirectURL:  "https://myapp.example.com/callback",
    Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
}
```

## Login page branding

When a user arrives via `/authorize`, the login page shows the client's display name and icon. Direct `/login` access shows the GateKeeper logo.

## Token lifetimes

| Token | Lifetime |
|---|---|
| Access token | 15 minutes |
| Refresh token | 30 days |
| ID token | 15 minutes |

## Key rotation

Tokens are signed with RS256. Keys rotate every 30 days automatically, checked hourly with no restart required. The previous key stays published for 48 hours so tokens issued just before rotation remain valid. See [OIDC security](/security/oidc-security#signing-keys).

## Trusted devices

After a user passes 2FA, a 30-day trusted device cookie skips 2FA on return logins from the same device. Works for both OIDC and ForwardAuth flows.
