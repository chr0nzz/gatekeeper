---
title: ForwardAuth setup
description: Configure Traefik to use GateKeeper as a ForwardAuth middleware.
---

Traefik's ForwardAuth feature sends every incoming request to an authentication service before forwarding it to the actual backend. If GateKeeper says the request is authenticated (HTTP 200), Traefik passes it through. If not (HTTP 401), Traefik redirects the browser to the login page.

## How it works

1. A browser sends a request to `app.example.com`.
2. Traefik intercepts it and sends a `GET /auth/verify` request to GateKeeper, including the session cookie.
3. GateKeeper checks the session. If valid, it responds `200` and sets `X-Auth-User` and `X-Auth-Email` headers.
4. Traefik forwards the original request to the app, including those headers. If invalid, Traefik returns a 401 redirect to the login page.
5. After login, GateKeeper redirects back to the original URL via the `redirect_uri` query parameter.

## Docker labels

Add these labels to both the GateKeeper service and any service you want to protect:

```yaml
# On the gatekeeper service - defines the middleware
labels:
  - traefik.http.middlewares.gatekeeper-auth.forwardauth.address=http://gatekeeper:8080/auth/verify
  - traefik.http.middlewares.gatekeeper-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email

# On any protected service - applies the middleware
labels:
  - traefik.http.routers.myapp.middlewares=gatekeeper-auth
```

## File provider (YAML)

If you use Traefik's file provider instead of Docker labels:

```yaml
# traefik/dynamic/gatekeeper.yml
http:
  middlewares:
    gatekeeper-auth:
      forwardAuth:
        address: "http://gatekeeper:8080/auth/verify"
        authResponseHeaders:
          - X-Auth-User
          - X-Auth-Email

  routers:
    myapp:
      rule: "Host(`app.example.com`)"
      middlewares:
        - gatekeeper-auth
      service: myapp-service
```

## Identity headers

When authentication succeeds, GateKeeper sets two headers that Traefik forwards to your app:

- `X-Auth-User` - the user's internal ID (a UUID)
- `X-Auth-Email` - the user's email address

Your app can read these headers to know who is logged in, without needing to talk to GateKeeper directly.

## Logout

Users can log out by POSTing to `/logout` on GateKeeper. Include a logout link in your app that points to `https://auth.example.com/logout`.
