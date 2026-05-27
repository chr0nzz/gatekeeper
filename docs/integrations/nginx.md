---
title: Nginx auth_request
description: Protect any site with GateKeeper using nginx's auth_request module.
---

Nginx's `auth_request` module sends a subrequest to an authentication server before proxying each request. If GateKeeper responds with HTTP 200 the request proceeds. Any other status code blocks the request and nginx returns 401 to the browser.

## How it works

1. A browser requests `app.example.com`.
2. Nginx sends a `GET /auth/verify` subrequest to GateKeeper, passing the session cookie.
3. GateKeeper returns 200 with `X-Auth-User`, `X-Auth-Email`, and `X-Auth-Groups` headers.
4. Nginx injects those headers into the upstream request and proxies it.
5. If the session is missing or invalid, GateKeeper returns 401. Nginx catches this with `error_page 401` and redirects the browser to the GateKeeper login page.

## Prerequisites

The `auth_request` module ships with most nginx distributions. Check that yours includes it:

```sh
nginx -V 2>&1 | grep auth_request
```

If the module is absent, install the `nginx-extras` package (Debian/Ubuntu) or rebuild nginx with `--with-http_auth_request_module`.

## Configuration

The pattern uses three server blocks:

1. **GateKeeper** - exposed on its own subdomain (`auth.example.com`).
2. **Auth subrequest location** - an internal location that forwards the subrequest to GateKeeper.
3. **Protected app** - your application, guarded by `auth_request`.

```nginx
# GateKeeper
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/ssl/certs/auth.example.com.crt;
    ssl_certificate_key /etc/ssl/private/auth.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Protected app
server {
    listen 443 ssl;
    server_name app.example.com;

    ssl_certificate     /etc/ssl/certs/app.example.com.crt;
    ssl_certificate_key /etc/ssl/private/app.example.com.key;

    location / {
        auth_request     /gk-auth;
        auth_request_set $auth_user   $upstream_http_x_auth_user;
        auth_request_set $auth_email  $upstream_http_x_auth_email;
        auth_request_set $auth_groups $upstream_http_x_auth_groups;

        proxy_set_header X-Auth-User   $auth_user;
        proxy_set_header X-Auth-Email  $auth_email;
        proxy_set_header X-Auth-Groups $auth_groups;

        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host            $host;
        proxy_set_header X-Real-IP       $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location = /gk-auth {
        internal;
        proxy_pass              https://auth.example.com/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length     "";
        proxy_set_header        X-Forwarded-Proto  $scheme;
        proxy_set_header        X-Forwarded-Host   $host;
        proxy_set_header        X-Forwarded-Uri    $request_uri;
    }

    error_page 401 = @login_redirect;
    location @login_redirect {
        return 302 https://auth.example.com/login?redirect_uri=https://$host$request_uri;
    }
}
```

Replace `auth.example.com` with your GateKeeper `BASE_URL` and `app.example.com` with the domain of the app you want to protect.

## Access policies

Append a `policy` query parameter to the verify URL to enforce a named policy. Only users in that policy are allowed through; everyone else gets a 403.

```nginx
location = /gk-auth {
    internal;
    proxy_pass https://auth.example.com/auth/verify?policy=my-policy;
    ...
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

The `auth_request_set` directives in the config above capture these and `proxy_set_header` forwards them to your backend.

## Logout

Add a logout link in your app that posts to GateKeeper's logout endpoint:

```html
<form method="POST" action="https://auth.example.com/logout">
  <button type="submit">Sign out</button>
</form>
```

## Protecting GateKeeper itself

Do not apply `auth_request` to the GateKeeper server block. Doing so creates a loop where the auth server requires authentication to serve the login page.
