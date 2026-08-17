---
title: Immich
description: Sign in to Immich with GateKeeper, on the web and in the mobile app.
---

# Immich

[Immich](https://immich.app) supports OpenID Connect, so it can use GateKeeper as its identity provider for both the web interface and the iOS and Android apps.

The mobile app receives its authorization code on a custom address, `app.immich:///oauth-callback`, rather than an ordinary web address. GateKeeper accepts that as long as it is registered on the client, which it detects automatically. Nothing extra needs enabling.

::: tip Version
Mobile sign-in needs GateKeeper v0.9.4 or newer. Earlier versions refuse custom schemes and reject the app with `redirect_uri is using a custom schema and is not allowed`. Web sign-in works on any version.
:::

## Step 1 - create the client in GateKeeper

In the admin panel go to **OIDC Clients** and click **New client**.

| Field | Value |
|---|---|
| Name | `Immich` |
| Client ID | `immich` |
| Client secret | Generate one and copy it |

Add **three** redirect URIs, replacing `immich.example.com` with your own address:

```
https://immich.example.com/auth/login
https://immich.example.com/user-settings
app.immich:///oauth-callback
```

All three are required:

- `/auth/login` completes sign-in on the web.
- `/user-settings` is used when an existing Immich account links itself to OAuth.
- `app.immich:///oauth-callback` is the mobile app. Note the three slashes.

If you reach Immich over plain HTTP on a local network, use `http://` in the first two. GateKeeper allows that for a client that also registers a mobile address.

Save the client, then open the **Test** dialog from the client row. **Application type** should read *Native*, which confirms the mobile address was recognised.

## Step 2 - configure Immich

In Immich go to **Administration → Settings → Authentication → OAuth** and set:

| Immich setting | Value |
|---|---|
| Enabled | On |
| Issuer URL | `https://auth.example.com` |
| Client ID | `immich` |
| Client Secret | The secret from step 1 |
| Scope | `openid email profile` |
| ID Token Signed Response Alg | `RS256` |
| Userinfo Signed Response Alg | `none` |
| Button Text | `Sign in with GateKeeper` |
| Auto Register | On |
| Mobile Redirect URI Override | Leave empty |

The issuer is your GateKeeper base URL on its own. Immich appends `.well-known/openid-configuration` during discovery, so do not include that part yourself.

`RS256` and `none` are the defaults and match what GateKeeper does: identity tokens are signed RS256, and the userinfo response is returned as plain JSON rather than a signed token.

Save, then sign out and use the new button on the Immich login page.

## Mobile app

No separate configuration is needed. Once `app.immich:///oauth-callback` is registered on the GateKeeper client, open the Immich app, point it at your server, and choose the OAuth button. The app opens a browser, you sign in to GateKeeper, and the browser hands control back to the app.

### If the app cannot open the custom address

Some devices refuse to hand a custom address back to an app. Immich provides a way around this that does not involve GateKeeper: it serves `/api/oauth/mobile-redirect`, which forwards to `app.immich:///oauth-callback`.

To use it, add that address to the GateKeeper client as a fourth redirect URI:

```
https://immich.example.com/api/oauth/mobile-redirect
```

and set **Mobile Redirect URI Override** in Immich to the same value. Sign-in then travels over ordinary HTTPS the whole way.

## Optional claims

Immich can read extra values from the identity token. GateKeeper supplies these out of the box:

| Claim | Value GateKeeper sends |
|---|---|
| `sub` | The user's GateKeeper ID, which Immich uses to match accounts |
| `email` | The user's email address |
| `email_verified` | Whether the address was confirmed by an emailed code |
| `preferred_username` | The user's email address |
| `groups` | The names of every group the user belongs to |

Immich's **Storage Label Claim** defaults to `preferred_username`, so uploads are filed under the user's email address. Leave it, or point it at a custom claim if you want something shorter.

To send anything else, use **Custom claims** on the GateKeeper client. A claim can carry the user's ID, email, display name, group membership, or a fixed string.

::: warning Role and quota claims
Immich's **Role Claim** expects a single value of `user` or `admin`, and **Storage Quota Claim** expects a number. GateKeeper can only send a fixed string or the full group list for a claim, so neither can be varied per user today. Leave both unset and manage administrators and quotas inside Immich.
:::

## Restricting who can sign in

By default anyone with a GateKeeper account can sign in to Immich, and Auto Register creates an Immich account for them on first use.

To limit it, create an access policy such as `photos`, add the users who should have access, and attach it to the Immich client. Everyone else is stopped at GateKeeper with an access denied page and never reaches Immich. See [Access policies](/admin/policies).

## Troubleshooting

**`redirect_uri is using a custom schema and is not allowed`**

The mobile address is not registered on the client, or GateKeeper is older than v0.9.4. Add `app.immich:///oauth-callback` to the client and confirm the Test dialog reports the application type as *Native*.

**`The requested redirect_uri is missing in the client configuration`**

Immich sent an address that is not on the client. The comparison is exact, so a trailing slash or `http` where you registered `https` will fail. Copy the address out of the error and add it verbatim.

**Signing in returns to the Immich login page**

Immich could not identify the user from the response. Check that the scope is `openid email profile`, since Immich matches accounts on the email address.

**The mobile app opens the browser and then stops**

The device did not pass the custom address back to the app. Use the mobile redirect override described above.
