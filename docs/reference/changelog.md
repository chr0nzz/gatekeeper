---
title: Changelog
description: Version history for GateKeeper.
---

## v0.9.6

:::danger Critical security release
The public key endpoint at `/keys` served the full RSA private signing key. Anyone who fetched it can forge id_tokens for any identity until keys rotate. Upgrade immediately; the upgrade retires all stored keys and generates a fresh one. See the release notes for rotation steps.
:::

### The JWKS endpoint published the private signing key

The unauthenticated `/keys` endpoint, which applications use to verify token signatures, served the private key's full material (`d`, `p`, `q`, `dp`, `dq`, `qi`) alongside the public fields. The structure holding the signing key was reused for the published key set, so the private key was serialised where the public key belonged.

- **Fixed** - the endpoint now publishes only `kty`, `n`, `e`, `kid`, `alg` and `use`, and a test asserts the private fields can never appear.
- **Scope** - the key signs id_tokens only. Sessions, access tokens, refresh tokens and ForwardAuth cookies are opaque database-checked values and cannot be forged with it.
- **Rotation** - upgrading deletes all stored signing keys and generates a fresh one on startup. Applications that cache the key set should be restarted or signed into again.

### The audit log records how you actually signed in

Every sign-in was labelled **Password** unless it used a passkey or a social provider, because the completion step wrote one generic event no matter how the user authenticated. Opening an application while already signed in also wrote that event, so using an app through OIDC showed up as a password login even though nothing was typed.

- **Signing into an app with an existing session** is now labelled **SSO**.
- **Passwordless email-code sign-ins** are labelled **Email OTP**. Only sign-ins that began with a password say Password.
- **Trusted-device sign-ins** are labelled **Trusted device**, and are no longer written twice.
- **Social sign-ins** are no longer written twice, so the dashboard sign-in counts stop double-counting them.
- **QR sign-ins** now get a method label too.
- The audit page has filter chips for the new labels.

Entries written by earlier versions keep their old labels.

### The audit log shows what was signed into

A new **App / Site** column answers the other half of the question. Sign-ins through OIDC show the client's name, such as Immich. Sign-ins that came from a ForwardAuth redirect show the site's hostname, such as `radarr.example.com`.

- **`login.handoff`** - a new event written when an existing sign-in reaches a protected site on another domain, once per site rather than once per request.
- **`forwardauth.denied`** - written when a signed-in user is refused by a site's access policy, with the site and the policy name. Denied access attempts were previously not recorded at all.
- **More room to show it** - the User and Email columns are merged, with the email shown on hover, and the Method column folded into the event, shown on hover too. The method filter chips still work.
- **Admin display names** - audit rows for admins showed their email even when a display name was set. They now show the name, like user rows do.

### Fixed

- **A failed registration sent the wrong email** - Trying to register with an address that already has an account sent a message headed "Password changed", telling the recipient their password had just been changed and to contact their administrator immediately. Nothing had changed. It now says an account already exists and that no action is needed.

---

## v0.9.5

:::warning Security release
An audit of the whole codebase found nine issues, including one that let a second factor be skipped. Upgrading is recommended.
:::

### Security

- **A second factor could be skipped** - A session waiting at the TOTP or email code prompt was treated as signed in by the account pages. Someone holding a password but not the second factor could open the account page, register a passkey, and use it from then on. Every page now sends an unfinished sign-in back to the step it stopped at, and a new authenticator app cannot be enrolled while one is already active.
- **Single-use credentials could be used more than once** - Invites, password reset links, email codes and recovery codes each checked whether they had been used and then marked them used as two separate steps, so two requests arriving together both passed. One invite could open any number of accounts. All four now claim the credential in a single statement that only one request wins.
- **The password reset form could exhaust the server's memory** - It hashed the token with a function that allocates 64MB per call, on an endpoint with no sign-in and no rate limit. Reset tokens are random 256-bit values, so a plain digest is the correct choice and the amplification is gone.
- **The client IP could be forged** - Forwarding headers were trusted from any source, so anyone could set their own address and evade every rate limit and lockout. They are now honoured only when the request arrives from a private, loopback or carrier-grade NAT address, which is where a reverse proxy sits.
- **An invite could be redeemed under a different address** - The address typed into the form overrode the one the invite was issued to, and an invite also skipped the allowed-domains list. An invite is now bound to its address, and the domain list applies to invited registrations too.
- **The sign-in forms had no CSRF token** - Login, email code, TOTP, recovery code and password reset accepted cross-site submissions, which allowed signing a visitor into an attacker's account. All five now carry one.
- **TOTP codes could be replayed** - A code stayed valid for about 90 seconds, so one observed in transit could be used again. Each is now accepted once.
- **Rate limits treated every IPv6 client as one** - The address was cut at the first colon, so all IPv6 addresses collapsed into a single bucket and one user hitting a limit locked out the rest.
- **Password reset emails could vanish** - The message was sent on a task tied to the request, which was cancelled as soon as the browser got its reply.

### Admin API keys are hashed and scoped

An API key could read the whole admin panel, and it was the one bearer credential still written to the database in clear text. Sessions, invites and password reset tokens were already hashed.

- **Hashed at rest** - Only a digest is stored, so a copy of the database no longer yields a working key. The value is shown once when generated and cannot be displayed again.
- **Limited to the statistics endpoints** - A key reaches `/api/dashboard-stats`, `/api/activity`, `/api/auth-methods` and `/api/version-check`, which is what a dashboard needs. Everything else returns `403`, including the user list, the audit log, settings, and the search endpoint that returns email addresses. Signing in with a browser is unchanged.
- **Recorded in the audit log** - Generating a key writes `admin.api_key_rotated`, and using one outside its allowed endpoints writes `admin.api_key_denied`.

Existing keys stop working and need regenerating, since the stored clear-text value no longer matches.

### Application setup in the admin panel

The Integrations page is now split into sections reached from a sidebar rather than one long page, and a new **Applications** section produces the exact values for this server, ready to copy, rather than examples to adapt.

- **Immich** - the three redirect URIs, including the phone app, and the settings to enter in Immich with your issuer already filled in.
- **Sonarr, Radarr, Lidarr** - the environment variable that turns off the app's own login, and both Traefik routes with the right hostname, service name and port for the app you pick.
- **Prowlarr** - the same, with the wider route rule its indexer endpoints need.

Each panel links to the full guide for the explanation and troubleshooting, so the page carries values and the documentation carries the reasoning.

### Client icons

The icon field on an OIDC client said an icon would be detected automatically if the field was left blank. Nothing ever did that, so leaving it blank produced a client with no icon and no indication why.

- **The field says what it does** - Paste a direct link to an image file. The three places a client icon can be set, the new client form on the Clients page, the one on the Dashboard, and the edit form, now carry the same wording. The edit form previously offered no guidance at all.
- **Finding an icon** - [selfh.st/icons](https://selfh.st/icons/) covers most self-hosted applications. Search for the application, copy the image address, and paste it in.
- **Documented limitation** - An icon hosted only on your internal network cannot be used. GateKeeper downloads the image when you save, and outbound requests to private and loopback addresses are refused. See [Managing clients](/admin/managing-clients).

### Documentation

- **[Sonarr, Radarr, Lidarr and Prowlarr](/integrations/servarr)** - How to put GateKeeper in front of them without a second login. These applications no longer offer HTTP Basic, so credential injection does not apply to them, and their authentication has to be set to `External` instead. Also covers the `/api` route the applications use to reach each other, which has to skip ForwardAuth, and the wider rule Prowlarr needs for `/{id}/api`.
- A desktop, tablet and phone mockup on the home page.

---

## v0.9.4

### Mobile app sign-in

- **Custom redirect schemes are accepted** - An application that is not a website, such as the Immich phone app, receives its authorization code on an address like `app.immich:///oauth-callback`. GateKeeper refused those, so mobile sign-in could not complete. A client that registers such an address is now treated as a native application, which permits it. Clients using only `http` or `https` are unchanged, and the address is still matched exactly against the registered list.
- **Plain HTTP still works alongside it** - Native clients are normally held to stricter transport rules, which would have broken web sign-in for anyone reaching their app over plain HTTP on a local network. Those clients keep working.
- **[Immich guide](/integrations/immich)** - A full walkthrough covering the web interface and the mobile app.

### Password policy is enforced everywhere

The password rules in Settings were only applied to passwords users chose themselves. Every administrator path skipped them, and the forms advertised a fixed minimum of 12 characters no matter what was configured.

- **Applied on every path** - Creating a user, setting a user's password, creating an administrator, promoting a user to administrator, the first-run setup, and an administrator changing their own password all check the configured rules. Previously an administrator could set a 12 character password on an account while the policy required 20.
- **Forms show the real minimum** - Every password field now states and enforces the configured length instead of a hardcoded 12.
- **The Settings hint is accurate** - It read "Minimum 8", which looked like the policy in force rather than the lowest value that can be configured.

### Slide-in panels

Dialogs that contain a form now arrive as a panel from the right rather than a box in the middle of the screen. On a wide display the page moves aside to make room instead of dimming, so the list you were working from stays readable. Below 1440px they behave as before, covering the page. Escape closes a panel in both cases.

### Client test dialog

- **The sign-in link works** - It pointed at `/oauth/authorize`, which is not a route this server serves, so opening the auth flow always returned 404. It now uses `/authorize`, and the redirect address is encoded so one containing a query string is no longer mangled.
- **The access policy is reported correctly** - The dialog read the policy from a table that does not exist, so the query silently failed and every client was described as open to all users even when a policy was attached.
- **Passing checks are visible** - The tick used a colour that is not defined in the stylesheet, so successful checks rendered as blank rows.
- **More detail** - The dialog now lists the client's redirect URIs and reports whether it counts as a web or native application.

### OIDC signing key rotation

The documentation has always said the OIDC signing key rotates every 30 days. It did not. The key was generated on first run and then kept forever, because nothing ever triggered a rotation.

- **Rotation now happens** - GateKeeper checks hourly and replaces the signing key once it is 30 days old. No restart needed.
- **Old tokens keep working** - The retired key stays published in the JWKS for another 48 hours, far longer than the 15 minute lifetime of the tokens it signed. After that it is deleted.
- **Visible on the dashboard** - System health now shows when the current key was last rotated and the date it is next due, instead of only claiming that rotation happens.

### Documentation

- **A new home page** with the feature tour, and a [screenshot gallery](/screenshots) of every page in both themes that follows whichever theme you are reading in.
- **Phone and tablet screenshots**, captured by a script that now lives in the repository under `scripts/` along with the demo data it uses.
- **`.env.example`** listing every environment variable, kept honest by a test that fails when one is added to the configuration without being documented.

### Tests and tooling

- **Coverage across the whole application** - The suite grew from 105 tests to over 250 and now covers the user-facing and administrator handlers, audit logging, webhook delivery, mail, and social sign-in, alongside the packages already covered. Several of the bugs above were found by writing them.
- **Linting on every push** - `golangci-lint` and a formatting check run in CI, and the documentation site is type checked and built.
- **Dependency updates** - A Renovate configuration keeps Go modules, npm packages, workflow actions and container base images current, with security updates raised immediately.

---

## v0.9.3

Fixes an OIDC regression introduced in v0.9.2 and moves cross-domain ForwardAuth configuration into the admin UI. Upgrade from v0.9.2 is recommended.

### Bug fixes

- **OIDC sign-in works again (regression in v0.9.2)** - The `/userinfo` response stopped including the `email` claim, so apps could not identify the user and returned them to their own login page, appearing as though nothing happened. v0.9.2 limited claims to a token's recorded scopes, but tokens do not always have their scopes recorded, and those tokens then received no claims at all. Claims are now limited only when the granted scopes are actually known. Anyone running v0.9.2 with OIDC applications should upgrade.
- **TOTP recovery codes no longer hang** - Redeeming a recovery code wrote to the database while a query cursor was still open. GateKeeper uses a single database connection, so the write waited on a connection that could never be released and the request hung until it timed out. This affected all previous versions.

### Protected app domains moved into Settings

Cross-domain ForwardAuth apps need their domain on an allowlist before GateKeeper will return a user to them after signing in. This previously required the `REDIRECT_ALLOWED_HOSTS` environment variable and a restart.

- **Configurable in the admin UI** - Set them under **Settings - Access control - Protected app domains**. Changes apply immediately, with no restart.
- **One consistent entry format** - Each entry covers the domain and all of its subdomains, so `example.net` allows `app.example.net`. Writing `.example.net`, `*.example.net`, or pasting a full URL all mean the same thing. Previously a domain written without a leading dot matched only that exact hostname, which silently failed to cover the app subdomains it was meant to allow.
- The environment variable still works for automated deployments, and entries from both sources are combined.

### Tests and CI

- **Tests run on every push and pull request** - A GitHub Actions workflow builds, vets, checks formatting, and runs the suite with race detection and coverage.
- **Coverage extended across the application** - The suite now also covers password and OTP handling, TOTP enrollment, validation, lockout and recovery codes, backup encryption, configuration validation, database migrations and restore, CSRF, template parsing, and the OIDC claim and redirect rules. Two of the bugs fixed above were found by these tests.
- Template tests guard against regressions that are otherwise invisible until a page breaks: page-scoped variables used inside a range block, inline scripts missing a CSP nonce, and inline event handlers that a nonce-based policy blocks.

---

## v0.9.2

A security release. An independent audit of the codebase produced 14 findings, all of which are fixed here. Two of them change behaviour you will notice, so read the upgrade notes at the end.

### Cross-domain sign-in hardened (critical)

- **Handoff tokens no longer carry a session** - When signing in to an app on a different domain, GateKeeper previously put a signed copy of the session identifier in the redirect URL. Anyone who saw that URL, in a server log or browser history, could reuse the session. The handoff is now a random one-time token stored server-side. It can be redeemed exactly once, only by the host it was issued for, and it expires after two minutes. The receiving app gets a brand new session of its own.
- **Redirect targets are checked against an allowlist** - `redirect_uri` was previously followed wherever it pointed, so a crafted login link could send an authenticated user, and their handoff token, to an attacker's site. Relative paths are always allowed. Absolute URLs must match your `BASE_URL`, `ADMIN_URL`, `COOKIE_DOMAIN`, or the new **Protected app domains** list in Settings (also settable with `REDIRECT_ALLOWED_HOSTS`). Anything else falls back to the home page.
- **Handoff tokens are kept out of logs** - The ForwardAuth debug line now records only the request path, never the query string that carries the token.

### QR sign-in hardened (high)

- **One code, one session** - An approved QR code could previously be polled repeatedly, and each poll issued another session. A code is now claimed atomically and works exactly once.
- **Bound to the browser that showed it** - Claiming a code requires a cookie set on the device that displayed it, so an approval obtained by sending someone an approval link cannot be collected by the sender. The approval form is also CSRF protected.

### Admin panel and account security

- **Command palette escapes user data (high)** - A display name containing markup was inserted into the admin command palette without escaping, so any user could run script in an admin's browser and escalate privileges. All values are now escaped at the point of insertion.
- **Content-Security-Policy no longer allows inline script** - `script-src` uses a per-response nonce instead of `'unsafe-inline'`, so injected script is refused by the browser even if it ever reaches a page.
- **Admin login is rate limited** - Repeated failures from one address are now throttled before the expensive password hash runs, which closes both an online guessing path and a way to exhaust server memory.
- **Trusted devices are opt-in** - Passing two-factor authentication no longer silently marks the browser trusted for 30 days. There is now a "Trust this device for 30 days" checkbox, and a trust token only works in the browser it was issued to.

### Data at rest

- **Session and trusted-device tokens are hashed** - The database stores only a hash, so a copy of the database no longer yields usable sign-in credentials.
- **Third-party credentials are encrypted** - SMTP passwords, S3 keys, social login secrets, and webhook tokens are encrypted with AES-256-GCM, matching how injected policy passwords were already handled.
- **Retired TOTP secrets are re-enrolled** - Secrets still stored in the pre-v0.4.0 format were recoverable from a database read. They are now cleared instead of reused, and the user is asked to set up their authenticator again.

### Outbound requests and OIDC

- **Requests to internal addresses are blocked** - Client icon URLs and webhook endpoints could be pointed at loopback, private, or cloud metadata addresses. Both now resolve and check the destination on every connection and redirect.
- **Icons are served as images only** - Fetched icon data is sniffed and rejected unless it is really an image, so the public icon endpoint cannot return arbitrary fetched content.
- **`end_session` validates its redirect** - `post_logout_redirect_uri` must now match a registered client redirect URI or a trusted host.
- **`email_verified` reflects reality** - The claim previously always reported true. It now reports whether the user actually confirmed their address by completing an email code. Where the granted scopes are recorded on a token, `email` and `profile` claims are limited to those scopes; tokens without recorded scopes still receive the standard claims so existing integrations keep working.
- **Client secrets compare in constant time.**

### Bug fixes

- **TOTP recovery codes no longer hang** - Redeeming a recovery code wrote to the database while a query cursor was still open. GateKeeper uses a single database connection, so the write waited on a connection that could never be released and the request hung until it timed out. Found by the new test suite.

### Tests

- The repository now has a Go test suite covering these changes: single-use and host-bound handoff tokens, redirect allowlisting, QR single-use and browser binding (including a concurrent-claim race), token hashing, rate limiting, settings encryption, CSP nonce handling, and the internal-address blocklist. It also covers password and OTP handling, TOTP enrollment and recovery, backup encryption, configuration validation, migrations and restore, template parsing, and the OIDC claim and redirect rules. Run it with `go test ./...`.
- Tests run automatically on every push and pull request via GitHub Actions, with race detection, vet, and formatting checks.

### Upgrade notes

- **Everyone is signed out once.** Session and trusted-device tokens are now hashed, so tokens issued before the upgrade no longer match. Sign in again.
- **Cross-domain ForwardAuth needs configuration.** If a protected app is on a different domain than `COOKIE_DOMAIN`, sign-in returns the user to the GateKeeper home page instead of the app until that domain is allowed. v0.9.3 adds a **Protected app domains** field in Settings for this; on v0.9.2 it is set with the `REDIRECT_ALLOWED_HOSTS` environment variable.

- **Users on very old TOTP enrollments must re-enroll.** Only affects secrets created before v0.4.0. They sign in with an email code and set up their authenticator again.

---

## v0.9.1

### Security

- **Documentation build dependency** - Bumped `vite` to `6.4.3` to resolve two advisories flagged by Dependabot: a `server.fs.deny` bypass on Windows alternate paths (high) and an NTLMv2 hash disclosure via `launch-editor` on Windows (medium). This only affects the documentation site's build tooling, not the GateKeeper server.

### ForwardAuth debugging

- **Debug logging** - Set `LOG_LEVEL=debug` to log the `X-Forwarded-Host`, proto, and URI each ForwardAuth verify receives, plus the target each login redirect resolves to. This pinpoints reverse-proxy header issues, such as a middleware `address` routed through the auth domain that rewrites `X-Forwarded-Host`. See [Traefik ForwardAuth - Troubleshooting](/integrations/traefik-forwardauth#troubleshooting-login-redirects-back-to-the-auth-domain).

---

## v0.9.0

### Split public and admin ports

The admin panel now runs on a dedicated port (`ADMIN_PORT`, default `8283`) separate from the public login and OIDC endpoints (`PORT`, default `8282`). Point your reverse proxy at port `8283` for the admin panel and restrict that route to your private network. The public port handles login, OIDC, ForwardAuth, and user-facing pages.

The admin panel is now served at the root of its port, so you can give it its own domain (e.g. `admin.auth.example.com`) with no `/admin` path prefix. Set `ADMIN_URL` to that domain so admin passkeys work. To keep a path prefix, set `ADMIN_BASE_PATH=/admin`.

### Admin passkeys on a subdomain

The admin panel can use passkeys when it runs on its own subdomain (e.g. `admin.auth.example.com`). Set `ADMIN_URL` and GateKeeper adds that origin to the WebAuthn allowed origins so registration and login work. The admin subdomain must sit under the same registrable domain as `BASE_URL`. See [Passkeys - Admin on a subdomain](/auth/passkeys#admin-on-a-subdomain).

### Backup restore and upload

- **One-step restore** - Restoring a backup now completes automatically on the next restart. GateKeeper detects the staged database on startup, swaps it in, and clears stale write-ahead-log files. The old flow that required manually renaming files inside the container is gone.
- **Upload a backup** - A new **Upload backup** button on the Backups page restores from a backup file you downloaded earlier, even if it is no longer in storage. The file is decrypted with your `SECRET_KEY` and validated before staging. See [Backups - Restoring a backup](/admin/backups#restoring-a-backup).

### Bug fixes

- **QR sign-in into proxied apps** - Signing in with a QR code now correctly returns you to a ForwardAuth-protected app on another domain. The QR flow now performs the same cross-domain session handoff as password login, instead of dropping you on your profile page.
- **Admin panel icons and avatars** - OIDC client icons and user avatars now load on the admin panel when it runs on its own port or domain. Their routes were previously only registered on the public port.

---

## v0.8.0

### QR code sign-in

- **Scan to sign in** - A new QR code tab on the login page lets you sign in to any device by scanning a code with your phone. Approve the login on your phone and the PC session is created automatically. No password or email code needed on the secondary device. See [QR code sign-in](/auth/qr-login).
- **One-time tokens** - Each QR code encodes a short-lived token (5 minute TTL) that is deleted from the database once used or expired. Expired codes reload automatically after a short pause.

### Credential injection

- **Per-policy auto-login** - Store a username and password on any access policy. When `/auth/verify` approves a request, GateKeeper returns an `Authorization: Basic` header that your reverse proxy forwards to the upstream app. The app receives a pre-authenticated request and skips its own login prompt - the same pattern as Authentik's outpost proxy. See [Access policies - Credential injection](/admin/policies#credential-injection).
- **Encrypted storage** - Injected passwords are encrypted with AES-256-GCM using a key derived from `SECRET_KEY` before being written to the database.
- **Traefik, Nginx, and Caddy support** - The integrations page documents how to configure each reverse proxy to forward the injected `Authorization` header.

### Admin API key

- **Personal API key** - Each admin account can generate a personal API key from the My Account page. Send it as `X-Api-Key` to authenticate server-side API requests without a browser session. Useful for dashboards and monitoring scripts. See [Admin API key](/admin/api-key).
- **Rotate on demand** - Keys can be rotated at any time from the profile page. The old key is invalidated immediately.

### Bug fixes

- **Passkey OIDC redirect** - Logging in with a passkey during an OIDC flow now correctly redirects back to the app after authentication. Previously the `oidc_request` token was lost during the passkey finish step, leaving the user on their profile page instead.

---

## v0.7.0

### Backup and restore

- **Encrypted backups** - Snapshot the database on demand or automatically (hourly, daily, or weekly). Each backup is encrypted with AES-256-GCM using a key derived from `SECRET_KEY`. See [Backups](/admin/backups).
- **Local storage** - Write backups to a directory inside the container. Mount a host volume to persist them across restarts.
- **S3-compatible storage** - Upload backups to any S3-compatible object store: AWS S3, Cloudflare R2, Backblaze B2, MinIO, Garage, and others. No SDK dependency - uses a minimal AWS Signature v4 implementation.
- **Retention policy** - Keep the last N backups. Older ones are deleted from storage automatically when a new backup is created.
- **Download and restore** - Download any backup from the Backups page or trigger an in-place restore. The restore decrypts the backup and writes a `.restore` file; a restart completes the swap.

### Password policy

- **Configurable password rules** - Set a minimum password length (8-72) and require uppercase letters, numbers, or symbols from Settings. Rules apply at registration, password change, and password reset. Defaults to 8-character minimum with no complexity requirements.

### OIDC improvements

- **Client test button** - Test any OIDC client directly from the Clients page. Shows a checklist of config details and opens a live auth flow with `prompt=login` so you can verify the full round-trip without wiring up the app.
- **Groups claim in userinfo** - The `groups` array is now included in the `/userinfo` endpoint response in addition to the ID token. Apps like Grafana that call `/userinfo` after the token exchange now receive group membership correctly.

### Audit log

- **Server-side event filter** - Filter the audit log by event category (Login, User, Admin, Invites) via URL params. Filters persist across page loads and are applied server-side, removing the 1000-row client-side cap.
- **CSV export** - Export the full filtered result set as a CSV file with no row limit. The export respects the active day range and event category filter.

### Bug fixes

- **Dashboard sign-in activity** - Social logins (`login.social`) and admin logins (`admin.login`, `admin.login.passkey`) are now counted in the sign-in stats and activity chart on the dashboard.

---

## v0.6.0

### Multiple admin accounts

- **Admin accounts** - Create and manage multiple admin accounts from the new Admins page. Each admin has a display name, email, and password. The currently signed-in admin is shown with a "you" indicator. Deleting your own account or the last remaining account is blocked.
- **Promote user to admin** - Any regular user can be promoted to an admin account directly from their user detail page. Sets a separate admin password and creates an independent admin account using the user's email and display name.
- **Admin profile redesign** - The My Account page is redesigned to match the user detail layout. Includes display name editing, active session count, and a "Revoke all other sessions" action.

### Login page branding

- **Login page branding** - Set an app name, tagline, and logo URL from Settings. The app name replaces "GateKeeper" in the sign-in heading. The tagline appears below the heading. The logo replaces the GateKeeper mark on the login, registration, and password reset pages. OIDC client icons still take priority over the logo when signing in via a specific client.

### Email branding

- **Email templates** - All outgoing emails (login codes, password resets, password change notifications) now use a clean branded layout. Set a sender name, logo URL, and accent color from Settings. The header background and CTA button color both use the accent color. Defaults to "GateKeeper" as the sender name and blue (`#2563eb`) as the accent.

### Reverse proxy integrations

- **Nginx auth_request** - Full configuration guide for protecting sites with nginx's `auth_request` module. See [Nginx auth_request](/integrations/nginx).
- **Caddy forward_auth** - Full Caddyfile guide for protecting sites with Caddy's `forward_auth` directive. See [Caddy forward_auth](/integrations/caddy).
- **X-Auth-Groups header** - The `/auth/verify` endpoint now returns an `X-Auth-Groups` header containing a comma-separated list of the authenticated user's group names. All three reverse proxy integrations (Traefik, Nginx, Caddy) forward this header to the upstream application.

---

## v0.5.0

### Social login

- **Social login** - Sign in with GitHub, Google, or Discord. Enable each provider from Settings with an OAuth2 client ID and secret. A "Continue with..." button appears on the login page for each enabled provider. On first sign-in, GateKeeper auto-links the provider to an existing account if the email matches. Users can connect and disconnect providers from their profile page. See [Social login](/admin/social-login).

### Groups

- **Groups** - Create named groups and assign users to them. Group membership is automatically included as a `groups` claim in all OIDC tokens, enabling role mapping in apps like Grafana and Jellyfin without any scope configuration. Manage group members from the Groups page or directly from a user's profile page. See [Groups](/admin/groups) for Grafana and Jellyfin config examples.

### User self-registration

- **Registration modes** - Choose between disabled, invite-only, open, and approval-required modes from Settings. In open mode anyone can create an account immediately. In approval mode accounts are held in a pending queue until an admin approves or rejects them from the Users page. A "Create account" link appears on the sign-in page when registration is open or approval-mode. Domain restrictions can limit which email domains are allowed to self-register. See [Registration](/admin/registration).

### Invite links

- **Invite links** - Generate single-use registration links from the Invites page. Each link can be tied to a specific email address (pre-filling and locking the registration form) or left open for any address. Links expire after 1, 3, 7, 14, or 30 days. The raw token is shown once at creation time; only a SHA-256 hash is stored. See [Invites](/admin/invites).

### OIDC improvements

- **RP-initiated logout** - Signing out of an OIDC client (e.g., Grafana) now also clears the GateKeeper session cookie. The `post_logout_redirect_uri` parameter is honoured so users land back on the correct page.
- **Token introspection** - The `/oauth/introspect` endpoint (RFC 7662) is supported. APIs and services can verify bearer tokens server-side by calling the endpoint with their client credentials. See [Managing clients](/admin/managing-clients).
- **Client credentials flow** - Enable machine-to-machine auth per client by setting a list of allowed scopes on the client.
- **Custom claims** - Inject extra fields into tokens on a per-client basis. Map user ID, email, display name, group membership, or a literal string to any claim key. Manage from the claims icon on the OIDC Clients page. See [Custom claims](/admin/custom-claims). Services call `POST /oauth/token` with `grant_type=client_credentials` and receive an access token with `sub` set to the client ID. See [Managing clients](/admin/managing-clients).

### Dashboard

- **Live stats** - The sign-ins, failed attempts, and OIDC token counts on the dashboard now refresh every 30 seconds without a full page reload.

---

## v0.4.0

### Security hardening

- **AES-256-GCM for TOTP secrets** - TOTP secrets are now encrypted with AES-256-GCM before storage. The encryption key is derived from `SECRET_KEY` using SHA-256. Existing secrets encrypted with the older XOR scheme are migrated automatically on next login - no action required.
- **HMAC-SHA256 for OTP codes** - Email OTP codes are no longer stored as plaintext. They are stored as HMAC-SHA256 digests keyed with `SECRET_KEY`. A database dump without the key cannot reconstruct active codes.
- **CSRF protection on all user endpoints** - All authenticated state-changing POST requests (password change, 2FA enrollment, session revocation, passkey deletion, name and avatar update) now validate a CSRF token. Previously only the admin panel validated CSRF.
- **Login rate limiting** - The login endpoint now enforces an IP-based rate limit of 20 failed attempts per 15-minute window. Excess attempts receive an error before any password check.
- **OTP issuance rate limit** - Each user can request at most 3 OTP codes per 10-minute window, preventing email flooding.
- **Tightened Content-Security-Policy** - Added `object-src 'none'`, `base-uri 'self'`, `connect-src 'self'`, and `frame-ancestors 'none'`. Added `https://www.gravatar.com` to `img-src`.


### User home redesign

- **New user home layout** - The authenticated home page (`/`) is fully redesigned. It shows a header with the GateKeeper logo, email, and theme toggle; a page head with avatar, display name, and inline name edit; three stat cards (sign-in methods, passkeys, sessions); a sign-in methods card; a passkeys card; and an active sessions card.
- **Session management** - Users can view all active sessions (device, browser, IP, last seen, time ago) and revoke individual sessions or all sessions except the current one directly from the home page.

## v0.3.0

- **Webhooks** - Send push notifications to Discord, Slack, Telegram, ntfy (public and self-hosted), generic JSON endpoints, or email when auth and admin events occur. Configure per-webhook event subscriptions and test delivery inline from the Webhooks page.
- **Access policies** - Create named policies and assign users to them. Attach a policy to an OIDC client to restrict which users can complete authorization, or reference it via `?policy=<name>` on `/auth/verify` for ForwardAuth routes. Policy ForwardAuth URL shown with copy button on the policies page.
- **Admin audit logging** - Admin sign-in (password and passkey), sign-out, failed login attempts, and user deletion are now recorded in the audit log alongside all other events.
- **Audit log retention** - Set a retention period in Settings. Events older than the configured number of days are deleted automatically on startup and daily. Default is 90 days; set to 0 to keep all events.
- **Audit log date filter** - Filter by Today, 7 days, 30 days, 90 days, or All time directly from the toolbar.
- **User profile** - Users can set a display name and pull in a Gravatar avatar from their home screen. The image is fetched server-side and cached in the database so the browser never contacts Gravatar directly.
- **Avatars everywhere** - Display name and avatar appear in the admin user list, user detail page, audit log rows, and dashboard recent events.
- **Dashboard redesign** - Real sparklines from the database on the sign-ins, failed attempts, and OIDC traffic cards. New cards for active sessions, 2FA adoption, and audit log stats. Auth methods card with 24h / 7d / 30d range toggle.
- **Command palette fixes** - `⌘K` / `Ctrl+K` palette now has working keyboard navigation (arrow keys, Enter). All pages including Policies, Webhooks, and Integrations appear in the navigate list. Searching users matches display name in addition to email.
- **New user modal** - Creating a user from the Users page now opens an inline modal instead of navigating to a separate page.
- **Policies table** - Policies page redesigned to match the OIDC clients table layout with description, member count, and used-by columns.
- **System health section** - Consolidates configuration warnings (locked accounts, users without 2FA, OIDC signing key status).

## v0.2.0

- **OIDC provider** - Full authorization code + PKCE flow. Apps can now use GateKeeper as a proper OIDC identity provider (Traefik Manager, Termix, Grafana, Jellyfin, etc.)
- **OIDC client icons** - Add an icon URL per client. Icons are fetched and cached server-side at save time; the login page loads them from GateKeeper, not external servers.
- **Login page branding** - When signing in via OIDC, the login page shows the app name and cached icon instead of the GateKeeper logo.
- **Client editing** - Edit name, icon, redirect URIs, and optionally rotate the secret of any OIDC client without deleting and recreating it.
- **OIDC endpoint reference** - The clients page now shows all endpoint URLs (authorization, token, userinfo, JWKS, discovery) with copy buttons.
- **Secret generator** - One-click cryptographically random secret generation in the new/edit client dialogs.
- **Trusted device tokens** - After passing 2FA, a 30-day `gk_trust` cookie is set. Users on trusted devices skip the second factor until it expires.
- **Cross-domain ForwardAuth** - HMAC-signed short-lived tokens allow GateKeeper to set per-host cookies for apps on different TLDs.
- **Interactive dashboard chart** - Sign-in activity chart with 24h / 7d / 30d range toggle and hover tooltips backed by real data.
- **Real auth method breakdown** - Dashboard shows live percentages for passkey, TOTP, email OTP, and OIDC logins in the last 24 hours.
- **Command palette** - `⌘K` / `Ctrl+K` opens a search palette. Type to search users and clients by name. Keyboard shortcuts `g d/u/c/a/s` navigate between sections.
- **Audit log improvements** - Event type filter chips (auth / admin / oidc), kind filter (success / warn / fail / info), per-row filter button, correct event count.
- **Mobile navigation** - Bottom navigation bar on screens under 760px.
- **Admin sidebar** - Live user and client counts, version number in the footer.
- **New user sign-in methods** - Create users as "Email + Password" or "Email Only" (passwordless) directly from the new user form.
- **OIDC post-login redirect** - After authenticating via OIDC, GateKeeper correctly completes the auth request and redirects back to the app with an authorization code.
- **Theme persistence** - Dark/light/auto preference now survives full page navigation (was blocked by CSP preventing the inline bootstrap script).

## v0.1.0

Initial release.

- Password + email OTP login
- Passwordless email OTP mode (per-user, admin-configurable)
- TOTP enrollment with QR code and recovery codes
- Passkey (WebAuthn) registration and authentication
- Password recovery via email with rate-limited, single-use tokens
- Authenticated password change with session invalidation
- Forced password change on admin-created accounts
- Traefik ForwardAuth middleware (`/auth/verify`)
- OIDC provider with authorization code + PKCE flow
- OIDC scopes: `openid`, `email`, `profile`, `offline_access`
- RS256 signing with 30-day key rotation
- First-run setup page at `/admin/setup` - no env vars needed for admin credentials
- Admin UI for user and OIDC client management
- Admin profile page - change password, enroll TOTP, register passkeys
- All runtime settings (SMTP, session TTL, allowed domains) configurable in the admin UI
- Append-only audit log
- SQLite persistence with embedded migrations
- Docker multi-stage build (golang:1.26-alpine)
- Astro Starlight documentation site
