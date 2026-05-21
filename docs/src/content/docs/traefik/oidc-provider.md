---
title: OIDC provider
description: Use GateKeeper as an OpenID Connect identity provider for your applications.
---

OpenID Connect (OIDC) is a login protocol built on top of OAuth 2.0. It lets your applications delegate authentication to GateKeeper the same way apps integrate "Sign in with Google." GateKeeper acts as the identity provider; your applications are the clients.

## Discovery endpoint

GateKeeper publishes its OIDC configuration at:

```
https://auth.example.com/.well-known/openid-configuration
```

Any OIDC-compatible client library can auto-configure from this URL.

## Supported flow

GateKeeper supports the **authorization code flow with PKCE only**. Implicit flow is not supported.

PKCE (Proof Key for Code Exchange) is a security extension that prevents authorization code interception attacks. It is required for all clients, including confidential server-side apps.

## Supported scopes

| Scope | Claims returned |
|---|---|
| `openid` | `sub` (user ID) |
| `profile` | `preferred_username` (email) |
| `email` | `email`, `email_verified` |
| `offline_access` | Enables refresh tokens |

## Registering an OIDC client

1. Go to `/admin/clients` and click **New client**.
2. Choose a client ID (e.g., `myapp`). This is public.
3. Generate a client secret. This must be kept private on your server.
4. Enter the redirect URIs your app will use after authentication (one per line).

## Example: connecting an OIDC client

For a server-side app using a generic OIDC library:

```python
# Python example using authlib
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

```go
// Go example using coreos/go-oidc
provider, _ := oidc.NewProvider(ctx, "https://auth.example.com")
config := oauth2.Config{
    ClientID:     "myapp",
    ClientSecret: "your-client-secret",
    Endpoint:     provider.Endpoint(),
    RedirectURL:  "https://myapp.example.com/callback",
    Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
}
```

## Key rotation

GateKeeper signs OIDC tokens with an RSA-256 key. Keys rotate every 30 days. The previous key is kept active for validation so that tokens issued just before rotation remain valid.

The public keys used to verify tokens are available at `/oauth/jwks`.

## Token lifetimes

| Token | Lifetime |
|---|---|
| Access token | 15 minutes |
| Refresh token | 30 days |
| ID token | 15 minutes |
