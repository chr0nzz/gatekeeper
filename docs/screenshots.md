---
title: Screenshots
description: The GateKeeper sign-in page, user portal, and admin panel in light and dark themes.
---

# Screenshots

Every page follows the theme you pick, and the choice is remembered per browser. Each view below is shown in dark first, then light.

## Sign-in

The sign-in page offers password, email code, and QR code in one place, with passkeys and any enabled social providers below. When an app starts the sign-in through OIDC, its name and icon replace the GateKeeper branding.

![Sign-in page, dark theme](/screenshots/login-dark.png)
![Sign-in page, light theme](/screenshots/login-light.png)

## User portal

Users manage their own account here: display name and avatar, sign-in methods, enrolled passkeys, and every active session with the option to sign others out.

![User portal, dark theme](/screenshots/user-home-dark.png)
![User portal, light theme](/screenshots/user-home-light.png)

## Dashboard

Live sign-in activity, failed attempts, OIDC token counts, two-factor adoption, and a system health panel that surfaces anything needing attention.

![Admin dashboard, dark theme](/screenshots/admin-dashboard-dark.png)
![Admin dashboard, light theme](/screenshots/admin-dashboard-light.png)

## Users

Create and manage accounts, approve pending registrations, promote a user to admin, and see each person's sign-in methods at a glance.

![Users page, dark theme](/screenshots/admin-users-dark.png)
![Users page, light theme](/screenshots/admin-users-light.png)

## OIDC clients

Register the apps that delegate login to GateKeeper. Each client holds its redirect URIs, icon, custom claims, and an optional access policy.

![OIDC clients page, dark theme](/screenshots/admin-clients-dark.png)
![OIDC clients page, light theme](/screenshots/admin-clients-light.png)

## Access policies

Policies decide who reaches which app. Attach one to an OIDC client or reference it from a ForwardAuth route, and optionally store credentials for apps that have no SSO of their own.

![Policies page, dark theme](/screenshots/admin-policies-dark.png)
![Policies page, light theme](/screenshots/admin-policies-light.png)

## Groups

Group membership is published as a `groups` claim in every OIDC token, which is what apps like Grafana and Jellyfin use for role mapping.

![Groups page, dark theme](/screenshots/admin-groups-dark.png)
![Groups page, light theme](/screenshots/admin-groups-light.png)

## Audit log

An append-only record of every authentication and admin event, filterable by category, outcome, sign-in method, and date range, and exportable as CSV.

![Audit log, dark theme](/screenshots/admin-audit-dark.png)
![Audit log, light theme](/screenshots/admin-audit-light.png)

## Settings

SMTP, session lifetime, registration mode, password policy, protected app domains, and branding. Changes apply immediately with no restart.

![Settings page, dark theme](/screenshots/admin-settings-dark.png)
![Settings page, light theme](/screenshots/admin-settings-light.png)

## Backups

Encrypted snapshots on demand or on a schedule, stored locally or in any S3-compatible bucket, and restored or uploaded from the same page.

![Backups page, dark theme](/screenshots/admin-backups-dark.png)
![Backups page, light theme](/screenshots/admin-backups-light.png)
