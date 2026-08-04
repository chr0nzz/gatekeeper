---
title: Screenshots
description: The GateKeeper sign-in page, user portal, and admin panel.
---

# Screenshots

GateKeeper ships light and dark themes, and remembers the choice per browser. **The screenshots below follow whichever theme you are reading this page in** - switch it with the toggle in the header to see the other one.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/screenshots/showcase-dark.gif">
  <source media="(prefers-color-scheme: light)" srcset="/screenshots/showcase-light.gif">
  <img class="screenshot" alt="A tour of the GateKeeper admin panel" src="/screenshots/showcase-dark.gif">
</picture>

## Sign-in

Password, email code, and QR code sign-in sit together in one control, with passkeys and any enabled social providers below. When an app starts the sign-in through OIDC, its name and icon replace the GateKeeper branding.

<img class="screenshot dark-only" src="/screenshots/login-dark.png" alt="GateKeeper sign-in page">
<img class="screenshot light-only" src="/screenshots/login-light.png" alt="GateKeeper sign-in page">

## User portal

Users manage their own account here: display name and avatar, sign-in methods, enrolled passkeys, and every active session with the option to sign the others out.

<img class="screenshot dark-only" src="/screenshots/user-home-dark.png" alt="User portal">
<img class="screenshot light-only" src="/screenshots/user-home-light.png" alt="User portal">

## Dashboard

Live sign-in activity, failed attempts, OIDC token counts, two-factor adoption, and a system health panel that surfaces anything needing attention.

<img class="screenshot dark-only" src="/screenshots/admin-dashboard-dark.png" alt="Admin dashboard">
<img class="screenshot light-only" src="/screenshots/admin-dashboard-light.png" alt="Admin dashboard">

## Users

Create and manage accounts, approve pending registrations, promote a user to admin, and see each person's sign-in methods at a glance.

<img class="screenshot dark-only" src="/screenshots/admin-users-dark.png" alt="Users page">
<img class="screenshot light-only" src="/screenshots/admin-users-light.png" alt="Users page">

## OIDC clients

Register the apps that delegate login to GateKeeper. Each client holds its redirect URIs, icon, custom claims, and an optional access policy.

<img class="screenshot dark-only" src="/screenshots/admin-clients-dark.png" alt="OIDC clients page">
<img class="screenshot light-only" src="/screenshots/admin-clients-light.png" alt="OIDC clients page">

## Access policies

Policies decide who reaches which app. Attach one to an OIDC client or reference it from a ForwardAuth route, and optionally store credentials for apps that have no SSO of their own.

<img class="screenshot dark-only" src="/screenshots/admin-policies-dark.png" alt="Access policies page">
<img class="screenshot light-only" src="/screenshots/admin-policies-light.png" alt="Access policies page">

## Groups

Group membership is published as a `groups` claim in every OIDC token, which is what apps like Grafana and Jellyfin use for role mapping.

<img class="screenshot dark-only" src="/screenshots/admin-groups-dark.png" alt="Groups page">
<img class="screenshot light-only" src="/screenshots/admin-groups-light.png" alt="Groups page">

## Audit log

An append-only record of every authentication and admin event, filterable by category, outcome, sign-in method, and date range, and exportable as CSV.

<img class="screenshot dark-only" src="/screenshots/admin-audit-dark.png" alt="Audit log">
<img class="screenshot light-only" src="/screenshots/admin-audit-light.png" alt="Audit log">

## Settings

SMTP, session lifetime, registration mode, password policy, protected app domains, and branding. Changes apply immediately with no restart.

<img class="screenshot dark-only" src="/screenshots/admin-settings-dark.png" alt="Settings page">
<img class="screenshot light-only" src="/screenshots/admin-settings-light.png" alt="Settings page">

## Backups

Encrypted snapshots on demand or on a schedule, stored locally or in any S3-compatible bucket, and restored or uploaded from the same page.

<img class="screenshot dark-only" src="/screenshots/admin-backups-dark.png" alt="Backups page">
<img class="screenshot light-only" src="/screenshots/admin-backups-light.png" alt="Backups page">
