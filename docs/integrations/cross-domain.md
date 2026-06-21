---
title: Cross-domain ForwardAuth
description: How GateKeeper authenticates users across apps on different domains or TLDs.
---

The standard Traefik ForwardAuth setup works seamlessly when all your apps share a common parent domain (for example `app.example.com` and `other.example.com` can both receive a cookie set on `.example.com`). When apps live on **completely different domains** (for example `app.example.com` and `app.otherdomain.io`), cookies set by GateKeeper cannot be shared across domains - this is a browser security constraint.

GateKeeper solves this with a cross-domain token handoff.

## How it works

1. A user visits `app.otherdomain.io`. Traefik sends the verify request to GateKeeper.
2. GateKeeper sees there is no valid session for this host and redirects to `/login?redirect_uri=https://app.otherdomain.io/the-page`.
3. The user logs in on `auth.example.com`. After authentication, GateKeeper detects that the redirect target is outside the shared cookie domain.
4. Instead of redirecting directly, GateKeeper generates a **cross-domain token** - a short-lived (5-minute), HMAC-SHA256 signed token containing the session ID.
5. The browser is sent to `https://app.otherdomain.io/_gk/auth?token=XXX&redirect=/the-page`.
6. Traefik intercepts this request and forwards it to GateKeeper's verify endpoint.
7. GateKeeper validates the HMAC signature and expiry, extracts the session ID, and sets a `gk_session` cookie scoped to `app.otherdomain.io` (no `Domain` attribute, so the browser scopes it to the exact host).
8. GateKeeper redirects back to `/the-page`. The user is now authenticated on `app.otherdomain.io` and future requests carry the host-scoped session cookie.

## Configuration

No extra configuration is needed if you set `COOKIE_DOMAIN`. GateKeeper automatically detects when a redirect target is outside the shared domain and triggers the cross-domain handoff.

If `COOKIE_DOMAIN` is not set, all apps are treated as same-domain and the cross-domain flow is never used.

```bash
COOKIE_DOMAIN=.example.com   # covers *.example.com
BASE_URL=https://auth.example.com
```

## Token security

Cross-domain tokens are signed with HMAC-SHA256 using `SECRET_KEY`. Properties:

- **Short-lived** - tokens expire after 5 minutes.
- **Single use** - the token contains the session ID but is consumed when the cookie is set.
- **Not replayable** - a token captured in transit cannot be replayed after expiry, and it is tied to the specific session.
- **Transmitted in the URL** - the token appears in the query string and may appear in server logs. The short expiry limits the window an intercepted token is useful.

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
