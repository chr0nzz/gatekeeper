---
layout: home

hero:
  name: GateKeeper
  text: Self-hosted authentication
  tagline: Protect your apps with OIDC, ForwardAuth, passkeys, TOTP, and email OTP. Single container, zero config files.
  image:
    src: /favicon.svg
    alt: GateKeeper
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/installation
    - theme: alt
      text: GitHub
      link: https://github.com/chr0nzz/gatekeeper

features:
  - icon:
      src: /icons/oidc.svg
    title: OIDC Identity Provider
    details: Any app that supports OIDC can delegate login to GateKeeper. Works with Grafana, Jellyfin, Portainer, Traefik Manager, and any standard OIDC client.
  - icon:
      src: /icons/shield.svg
    title: Traefik ForwardAuth
    details: Protect apps at the reverse proxy level without touching their code. GateKeeper sits in front and verifies every request.
  - icon:
      src: /icons/lock.svg
    title: Passkeys & TOTP
    details: Passwordless login with passkeys (fingerprint, face, hardware key), TOTP authenticator apps, and email OTP - all configurable per user.
  - icon:
      src: /icons/layout.svg
    title: Admin UI
    details: Manage users, OIDC clients, access policies, webhooks, and settings from a browser. No CLI or config files required.
  - icon:
      src: /icons/file.svg
    title: Audit Log
    details: Append-only record of every authentication and admin event with full filtering, retention controls, and date ranges.
  - icon:
      src: /icons/box.svg
    title: Zero Dependencies
    details: Single binary, single SQLite file, single Docker container. First-run setup page - no env vars needed for the admin account.
---
