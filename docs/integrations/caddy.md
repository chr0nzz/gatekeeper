---
title: Caddy forward_auth
description: Protect any site with GateKeeper using Caddy's forward_auth directive.
---

Caddy's `forward_auth` directive sends each incoming request to an authentication service before proxying it. If GateKeeper responds 200 the request proceeds. Any other status code causes Caddy to follow the redirect returned by GateKeeper, sending the browser to the login page.

## How it works

1. A browser requests `app.example.com`.
2. Caddy sends a `GET /auth/verify` subrequest to GateKeeper, passing the session cookie.
3. GateKeeper returns 200 with `X-Auth-User`, `X-Auth-Email`, and `X-Auth-Groups` headers.
4. Caddy copies those headers into the upstream request and proxies it.
5. If the session is invalid, GateKeeper returns 401 with a `Location` header. Caddy redirects the browser to the GateKeeper login page.

## Caddyfile

```caddy
# GateKeeper
auth.example.com {
    reverse_proxy localhost:8080
}

# Protected app
app.example.com {
    forward_auth localhost:8080 {
        uri /auth/verify
        copy_headers X-Auth-User X-Auth-Email X-Auth-Groups
    }

    reverse_proxy localhost:8081
}
```

Replace `auth.example.com` with your GateKeeper `BASE_URL` and `app.example.com` with the domain you want to protect. The `forward_auth` block targets GateKeeper directly by address; `uri` specifies the verify path.

## Access policies

Append a `policy` query parameter to enforce a named policy. Only users in that policy are allowed through; everyone else gets a 403.

```caddy
app.example.com {
    forward_auth localhost:8080 {
        uri /auth/verify?policy=my-policy
        copy_headers X-Auth-User X-Auth-Email X-Auth-Groups
    }

    reverse_proxy localhost:8081
}
```

Create and manage policies from the [Access policies](/admin/policies) page in the admin UI.

## Identity headers

GateKeeper sets the following response headers on a successful 200:

| Header | Value |
|---|---|
| `X-Auth-User` | The user's internal UUID |
| `X-Auth-Email` | The user's email address |
| `X-Auth-Groups` | Comma-separated group names (omitted when the user has no groups) |

The `copy_headers` directive forwards these to your backend automatically.

## Logout

Add a logout link in your app that posts to GateKeeper's logout endpoint:

```html
<form method="POST" action="https://auth.example.com/logout">
  <button type="submit">Sign out</button>
</form>
```

## Protecting GateKeeper itself

Do not apply `forward_auth` to the GateKeeper site block. Doing so creates a loop where the auth server requires authentication to serve the login page.
