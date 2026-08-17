---
title: Sonarr, Radarr, Lidarr, Prowlarr
description: Put GateKeeper in front of the *arr applications with ForwardAuth and no second login.
---

# Sonarr, Radarr, Lidarr and Prowlarr

These applications share a codebase, so they are configured the same way. Put GateKeeper in front with [ForwardAuth](/integrations/traefik-forwardauth), then tell the application that something else already handled authentication so it does not ask again.

Two things need doing, and skipping either one causes a specific, recognisable problem:

1. Set the application's authentication method to `External`, or you get a second login page after GateKeeper.
2. Let `/api` past GateKeeper, or the applications stop talking to each other.

## Step 1 - set the authentication method to External

The dropdown under **Settings → General → Security** does not offer what you need:

| Option | Available | Use with GateKeeper |
|---|---|---|
| None | Blocked. Authentication is mandatory from Radarr v5 onward. | - |
| Basic (Browser pop-up) | Sonarr only. Removed from the others and marked obsolete. | Works, but see below |
| Forms (Login Page) | All of them | Causes a second login |
| **External** | **All of them, but hidden from the dropdown** | **Use this** |

`External` means authentication happens in front of the application. It is a real setting, it is simply not shown in the interface, so it has to be set as an environment variable or in the configuration file.

### With Docker Compose

```yaml
services:
  radarr:
    environment:
      - RADARR__AUTH__METHOD=External
```

The prefix is the application's name, so use `SONARR__AUTH__METHOD`, `LIDARR__AUTH__METHOD` or `PROWLARR__AUTH__METHOD`. Note the double underscores. Restart the container afterwards.

::: warning Do not set AUTH__ENABLED
If `RADARR__AUTH__ENABLED` is set to `true`, the application forces the method back to `Forms` and ignores what you set here. Leave it unset.
:::

### Or in config.xml

Edit `config.xml` in the application's configuration volume and restart:

```xml
<AuthenticationMethod>External</AuthenticationMethod>
```

The interface will then show the authentication dropdown as blank, which is expected.

## Step 2 - let the API past GateKeeper

Prowlarr talks to Radarr, Sonarr and Lidarr using an API key, not a browser session. GateKeeper has no session for those requests, so it answers them with a redirect to the sign-in page and the applications fail to reach each other. The same applies to mobile clients such as nzb360 or LunaSea.

Give each application a second route for `/api` with no ForwardAuth middleware on it:

```yaml
http:
  routers:
    radarr:
      rule: "Host(`radarr.example.com`)"
      entryPoints: [https]
      middlewares:
        - gk-auth@file
      service: radarr
      tls:
        certResolver: cloudflare

    radarr-api:
      rule: "Host(`radarr.example.com`) && PathPrefix(`/api`)"
      entryPoints: [https]
      service: radarr
      tls:
        certResolver: cloudflare

  services:
    radarr:
      loadBalancer:
        servers:
          - url: "http://10.0.0.10:7878"
```

The more specific rule wins, so `/api` skips GateKeeper while every other path is protected.

### Prowlarr needs a wider rule

Prowlarr serves each indexer at `/{id}/api`, with the indexer number first, so `PathPrefix(/api)` never matches it. When Sonarr or Radarr searches through Prowlarr the request goes to something like `/1/api?t=search`, and grabbing a release goes to `/1/download`. Both are caught by GateKeeper and fail unless the rule covers them:

```yaml
    prowlarr-api:
      rule: "Host(`prowlarr.example.com`) && (PathPrefix(`/api`) || PathRegexp(`^/[0-9]+/(api|download)`))"
      entryPoints: [https]
      service: prowlarr
      tls:
        certResolver: cloudflare
```

`PathPrefix(/api)` still covers Prowlarr's own API, which is what the **Settings - Apps** sync uses, and the pattern covers the indexer and download endpoints. `PathRegexp` needs Traefik v3.

The symptom is searches returning nothing and indexer tests failing in Sonarr or Radarr, while Prowlarr's own interface looks healthy.

**This does not expose the API.** These applications require an API key on `/api` regardless of the authentication method, including `External`. Removing GateKeeper from that path hands the check back to the application, it does not remove it.

If the interface loads but activity never updates, add `/signalr` to the same bypass. The live update connection authenticates with a query parameter rather than a header.

## Step 3 - check it

Open the application in a private browser window. You should be asked to sign in once by GateKeeper, then land directly in the application with no second login page.

In Prowlarr, use **Test** on one of the applications under **Settings → Apps**. It should pass.

## If you use Tailscale

**Authentication Required → Disabled for Local Addresses** skips authentication for requests from private addresses. Tailscale addresses are in the shared range `100.64.0.0/10`, which these applications do not count as private by default, so a request proxied over Tailscale is still treated as remote.

To include them, set:

```yaml
- RADARR__AUTH__TRUSTCGNATIPADDRESSES=true
```

This is not needed when the method is `External`, since nothing is asking for credentials in the first place.

## Keep the applications off the network

With `External`, the application trusts that whatever is in front of it did the authenticating. Anything that can reach the container directly gets in without signing in.

- Do not publish the application's port on the host. Reach it through the reverse proxy only.
- Keep the application and the proxy on the same private or Docker network.
- If the network is a tailnet, restrict who can reach those ports with Tailscale ACLs.

## Credential injection, and why it is not used here

GateKeeper can store a username and password on an access policy and send them as an `Authorization: Basic` header, which signs users into applications that accept HTTP Basic. See [Access policies](/admin/policies).

That only works with HTTP Basic. Of these four applications only Sonarr still offers it, and it is marked obsolete there, so it will go the same way. Form based login cannot be filled in this way: it needs a form submission and the application's own session cookie, which a header cannot provide.

`External` is the better answer for all four. It needs no stored credentials, so there is no password in GateKeeper's database to protect or rotate.
