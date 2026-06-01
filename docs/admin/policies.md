---
title: Access policies
description: Restrict which users can access specific apps using policies.
---

A policy is a named list of users. Once created, you can attach a policy to an OIDC client or a ForwardAuth route. Only users in the policy can complete authentication for that app - everyone else is denied access.

## Creating a policy

Go to `/admin/policies` and click **New policy**.

Give it a short, descriptive name. The name is used in the `?policy=` URL parameter, so stick to lowercase letters, digits, and dashes (for example `internal-team` or `beta-users`). The description is optional - it is shown on the policies list page.

## Adding users to a policy

Open the policy detail page (`/admin/policies/<id>`). The **Add user** section at the bottom shows a dropdown of all users not already in the policy. Select a user and click **Add**.

To remove a user, click **Remove** next to their name in the members table.

## Attaching a policy to an OIDC client

Open `/admin/clients` and create or edit a client. The **Required policy** field shows a dropdown of all existing policies. Select one and save. Users who are not in that policy will see an "Access denied" screen after authenticating instead of being redirected back to the app.

Leave the field set to "No restriction" to allow all authenticated users.

## Using the policy query parameter with ForwardAuth

When using the Traefik ForwardAuth middleware, append `?policy=<name>` to the verify URL. GateKeeper returns HTTP 403 if the authenticated user is not in the named policy.

### Traefik example

```yaml
http:
  middlewares:
    gk-internal:
      forwardAuth:
        address: "https://auth.example.com/auth/verify?policy=internal-team"
        authResponseHeaders:
          - X-Auth-User
          - X-Auth-Email
```

### Nginx auth_request example

```nginx
location /auth {
    internal;
    proxy_pass https://auth.example.com/auth/verify?policy=internal-team;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}
```

### Caddy forward_auth example

```caddyfile
forward_auth auth.example.com {
    uri /auth/verify?policy=internal-team
    copy_headers X-Auth-User X-Auth-Email
}
```

If no `?policy=` parameter is given, any authenticated user is allowed through.

## Credential injection

Some apps do not support SSO or header-based authentication. They require a username and password every time. Credential injection lets GateKeeper supply those credentials automatically after a successful ForwardAuth check, so users never see the app's own login form.

### How it works

1. Store the app's username and password on the policy detail page under **Credential injection**. The password is encrypted with AES-256-GCM using `SECRET_KEY` before it is written to the database.
2. When `/auth/verify?policy=<name>` returns `200`, GateKeeper sets an `Authorization: Basic <base64>` header on the response.
3. Your reverse proxy is configured to copy that header to the upstream request.
4. The app receives a pre-authenticated request and logs the user in without prompting.

### Setting credentials

Open the policy detail page and scroll to the **Credential injection** card. Enter the username and password for the downstream app and click **Save**. Leave the password blank when updating to keep the current password unchanged.

To remove credentials, click **Clear**.

### Traefik configuration

Add `Authorization` to `authResponseHeaders` so Traefik forwards the injected header to the app:

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

### App setup

Configure the downstream app to accept Basic authentication. In Sonarr, Radarr, and similar apps this is found under **Settings - General - Authentication**. Set the method to **Basic** and enter the same username and password you saved in GateKeeper. The app will see the injected `Authorization` header and skip its own login prompt.

### Nginx and Caddy

Nginx's `auth_request` module does not copy response headers to the upstream automatically. Use `auth_request_set` to capture the header and then `proxy_set_header` to forward it:

```nginx
auth_request_set $auth_cred $upstream_http_authorization;
proxy_set_header Authorization $auth_cred;
```

Caddy's `forward_auth` directive uses `copy_headers`:

```caddyfile
forward_auth auth.example.com {
    uri /auth/verify?policy=sonarr
    copy_headers X-Auth-User X-Auth-Email X-Auth-Groups Authorization
}
```
