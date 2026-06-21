---
title: Protecting an app with ForwardAuth
description: End-to-end example of protecting a self-hosted application with GateKeeper.
---

This example walks through protecting a self-hosted app (we'll use Grafana) with GateKeeper using Traefik's ForwardAuth middleware.

## What you'll have at the end

- Grafana at `https://grafana.example.com`, accessible only to logged-in GateKeeper users.
- GateKeeper at `https://auth.example.com`, handling all authentication.
- Traefik routing traffic and enforcing auth.

## Full docker-compose.yml

```yaml
services:
  traefik:
    image: traefik:v3
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.le.acme.tlschallenge=true
      - --certificatesresolvers.le.acme.email=you@example.com
      - --certificatesresolvers.le.acme.storage=/letsencrypt/acme.json
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt

  gatekeeper:
    image: ghcr.io/yourorg/gatekeeper:latest
    environment:
      BASE_URL: https://auth.example.com
      SECRET_KEY: your-32-char-secret-here
      ADMIN_EMAIL: admin@example.com
      ADMIN_PASSWORD: change-me
      SMTP_HOST: smtp.example.com
      SMTP_FROM: noreply@example.com
      SMTP_TLS: starttls
    volumes:
      - gk_data:/data
    labels:
      - traefik.enable=true
      - traefik.http.routers.gk.rule=Host(`auth.example.com`)
      - traefik.http.routers.gk.entrypoints=websecure
      - traefik.http.routers.gk.tls.certresolver=le
      - traefik.http.services.gk.loadbalancer.server.port=8282
      - traefik.http.middlewares.gk-auth.forwardauth.address=http://gatekeeper:8282/auth/verify
      - traefik.http.middlewares.gk-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email

  grafana:
    image: grafana/grafana:latest
    environment:
      GF_AUTH_PROXY_ENABLED: "true"
      GF_AUTH_PROXY_HEADER_NAME: X-Auth-Email
      GF_AUTH_PROXY_HEADER_PROPERTY: email
      GF_AUTH_PROXY_AUTO_SIGN_UP: "true"
    labels:
      - traefik.enable=true
      - traefik.http.routers.grafana.rule=Host(`grafana.example.com`)
      - traefik.http.routers.grafana.entrypoints=websecure
      - traefik.http.routers.grafana.tls.certresolver=le
      - traefik.http.routers.grafana.middlewares=gk-auth

volumes:
  gk_data:
  letsencrypt:
```

## How it works

1. A browser visits `grafana.example.com`.
2. Traefik intercepts the request and calls `http://gatekeeper:8282/auth/verify`.
3. If the user has a valid session, GateKeeper returns `200` with `X-Auth-Email` set.
4. Traefik forwards the request to Grafana with the `X-Auth-Email` header.
5. Grafana uses proxy auth to log the user in automatically based on the header.

If the user has no session, GateKeeper returns `401` and Traefik redirects the browser to `/login?redirect_uri=https://grafana.example.com/`.

## Reading identity headers in your own app

If you build your own app, read the `X-Auth-Email` and `X-Auth-User` headers set by GateKeeper to identify the logged-in user:

```python
# Flask example
@app.route('/')
def index():
    user_email = request.headers.get('X-Auth-Email', 'anonymous')
    return f'Hello, {user_email}'
```

```go
// Go example
func handler(w http.ResponseWriter, r *http.Request) {
    email := r.Header.Get("X-Auth-Email")
    fmt.Fprintf(w, "Hello, %s", email)
}
```
