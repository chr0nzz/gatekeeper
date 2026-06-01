---
title: ForwardAuth setup
description: Configure Traefik to use GateKeeper as a ForwardAuth middleware.
---

Traefik's ForwardAuth feature sends every incoming request to an authentication service before forwarding it to the actual backend. If GateKeeper says the request is authenticated (HTTP 200), Traefik passes it through. If not (HTTP 401), Traefik redirects the browser to the login page.

## How it works

1. A browser sends a request to `app.example.com`.
2. Traefik intercepts it and sends a `GET /auth/verify` request to GateKeeper, including the session cookie.
3. GateKeeper checks the session. If valid, it responds `200` with `X-Auth-User` and `X-Auth-Email` headers.
4. Traefik forwards the original request to the app with those headers attached.
5. If the session is invalid, Traefik returns a 401, the browser redirects to `/login?redirect_uri=<original_url>`, and after login the user is sent back.

## Step 1 - define the middleware

Create one file in your Traefik dynamic config directory that defines the `gk-auth` middleware. You only need to do this once.

```yaml
# traefik/dynamic/middlewares-gk-auth.yml
http:
  middlewares:
    gk-auth:
      forwardAuth:
        address: "https://auth.example.com/auth/verify"
        authResponseHeaders:
          - X-Auth-User
          - X-Auth-Email
          - X-Auth-Groups
```

Replace `auth.example.com` with the `BASE_URL` you configured for GateKeeper.

Traefik hot-reloads the dynamic config directory, so no restart is needed after adding this file.

## Step 2 - apply it to a service

In each service's route file, add `gk-auth@file` to the router's middleware list.

```yaml
# traefik/dynamic/myapp.yml
http:
  routers:
    myapp:
      rule: "Host(`app.example.com`)"
      entryPoints:
        - https
      middlewares:
        - gk-auth@file
      tls:
        certResolver: cloudflare
      service: myapp-service
  services:
    myapp-service:
      loadBalancer:
        servers:
          - url: "http://100.0.0.1:8080"
```

The `@file` suffix tells Traefik the middleware comes from the file provider. If your middleware and router are in the same file you can omit it, but `@file` is explicit and always safe.

## Identity headers

When authentication succeeds, GateKeeper sets headers that Traefik forwards to your app:

- `X-Auth-User` - the user's internal UUID
- `X-Auth-Email` - the user's email address
- `X-Auth-Groups` - comma-separated list of group names the user belongs to (omitted if the user has no groups)

Your app can read these to identify who is logged in and what roles they have, without any SDK or API call.

## Credential injection

For apps that require a username and password rather than header-based auth, you can store credentials on the policy and have GateKeeper inject them automatically. Add `Authorization` to `authResponseHeaders` and Traefik will forward the `Authorization: Basic` header to the upstream:

```yaml
http:
  middlewares:
    sonarr-auth:
      forwardAuth:
        address: "https://auth.example.com/auth/verify?policy=sonarr"
        authResponseHeaders:
          - X-Auth-User
          - X-Auth-Email
          - X-Auth-Groups
          - Authorization
```

Set the app credentials on the policy detail page under **Credential injection**. See [Access policies](/admin/policies) for the full setup guide.

```python
# Flask example
@app.route("/")
def index():
    email = request.headers.get("X-Auth-Email", "anonymous")
    return f"Hello, {email}"
```

```go
// Go example
func handler(w http.ResponseWriter, r *http.Request) {
    email := r.Header.Get("X-Auth-Email")
    fmt.Fprintf(w, "Hello, %s", email)
}
```

## Logout

Add a logout link in your app that posts to GateKeeper's logout endpoint:

```html
<form method="POST" action="https://auth.example.com/logout">
  <button type="submit">Sign out</button>
</form>
```

## Protecting GateKeeper itself

Do not apply the `gk-auth` middleware to GateKeeper's own route. Doing so creates a loop where the auth server requires authentication to serve the login page.
