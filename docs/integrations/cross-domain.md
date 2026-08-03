---
title: Cross-domain ForwardAuth
description: How GateKeeper authenticates users across apps on different domains or TLDs.
---

The standard Traefik ForwardAuth setup works seamlessly when all your apps share a common parent domain (for example `app.example.com` and `other.example.com` can both receive a cookie set on `.example.com`). When apps live on **completely different domains** (for example `app.example.com` and `app.otherdomain.io`), cookies set by GateKeeper cannot be shared across domains - this is a browser security constraint.

GateKeeper solves this with a single-use handoff token.

## How it works

1. A user visits `app.otherdomain.io`. Traefik sends the verify request to GateKeeper.
2. GateKeeper sees there is no valid session for this host and redirects to `/login?redirect_uri=https://app.otherdomain.io/the-page`.
3. The user logs in on `auth.example.com`. GateKeeper checks the redirect target against its allowlist, then detects that it is outside the shared cookie domain.
4. GateKeeper creates a **handoff token**: a random value stored server-side, recorded against the user and the destination host, and valid for two minutes. The token is only a reference. It carries no session or user data.
5. The browser is sent to `https://app.otherdomain.io/_gk/auth?token=XXX&redirect=/the-page`.
6. Traefik intercepts this request and forwards it to GateKeeper's verify endpoint.
7. GateKeeper redeems the token. Redemption succeeds only once, and only when the requesting host matches the host the token was issued for. GateKeeper then creates a **new session** for that user and sets a `gk_session` cookie scoped to `app.otherdomain.io` (no `Domain` attribute, so the browser scopes it to the exact host).
8. GateKeeper redirects back to `/the-page`. The user is now authenticated on `app.otherdomain.io` and future requests carry the host-scoped session cookie.

## Configuration

Apps on a different domain than GateKeeper must be listed as allowed redirect destinations, otherwise sign-in returns the user to the GateKeeper home page instead of the app.

Add them in the admin panel under **Settings - Access control - Protected app domains**. Changes apply immediately, with no restart:

```
jellyfin.otherdomain.io
.third.net
```

Entries are one per line or comma-separated, and each one covers that domain and all of its subdomains. Listing `otherdomain.io` allows `jellyfin.otherdomain.io` and every other host under it. The forms `.otherdomain.io`, `*.otherdomain.io`, and a pasted URL are all equivalent.

Two groups of hosts are always allowed and never need an entry: your `BASE_URL` and `ADMIN_URL` hosts, and anything under `COOKIE_DOMAIN`.

```bash
BASE_URL=https://auth.example.com
COOKIE_DOMAIN=.example.com   # covers *.example.com without any extra setting
```

The same list can also be pre-seeded with the `REDIRECT_ALLOWED_HOSTS` environment variable, which is useful for automated deployments. Entries from both sources are combined.

## Token security

The handoff token is a reference to a server-side record, not a credential in itself:

- **No session data in the URL** - the token is a random value. Reading it from a log or browser history reveals nothing about the session, and it cannot be turned into a session cookie for the auth domain.
- **Single use** - redemption is an atomic update. The second attempt with the same token always fails, so a captured token cannot be replayed even within its lifetime.
- **Host-bound** - a token issued for `app.otherdomain.io` is rejected if presented from any other host.
- **Short-lived** - unredeemed tokens expire after two minutes and are cleaned up in the background.
- **Kept out of logs** - GateKeeper's own ForwardAuth debug logging records the request path only, never the query string.

## Traefik configuration

The `/_gk/auth` path on each protected app's domain must be reachable by Traefik's ForwardAuth check. No special configuration is needed - the standard `gk-auth` middleware handles this path automatically.

```yaml
http:
  middlewares:
    gk-auth:
      forwardAuth:
        address: "http://gatekeeper:8282/auth/verify"
        authResponseHeaders:
          - X-Auth-User
          - X-Auth-Email
```

Point `address` directly at the GateKeeper container (`gatekeeper:8282`, a private IP, or a Tailscale address), not at the public `auth.example.com`. Routing the ForwardAuth request through the auth domain rewrites `X-Forwarded-Host` and breaks the cross-domain redirect back to the app.

Apply this middleware to routes on any domain, including domains unrelated to `example.com`. GateKeeper handles the cross-domain handoff transparently.
