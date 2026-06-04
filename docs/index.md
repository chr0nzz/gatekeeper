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
      svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1.5 1.5M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1.5-1.5"/></svg>'
    title: OIDC Identity Provider
    details: Any app that supports OIDC can delegate login to GateKeeper. Works with Grafana, Jellyfin, Portainer, Traefik Manager, and any standard OIDC client.
  - icon:
      svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v7c0 5 3.5 9 8 10 4.5-1 8-5 8-10V5z"/></svg>'
    title: Traefik ForwardAuth
    details: Protect apps at the reverse proxy level without touching their code. GateKeeper sits in front and verifies every request.
  - icon:
      svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
    title: Passkeys & TOTP
    details: Passwordless login with passkeys (fingerprint, face, hardware key), TOTP authenticator apps, and email OTP - all configurable per user.
  - icon:
      svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>'
    title: Admin UI
    details: Manage users, OIDC clients, access policies, webhooks, and settings from a browser. No CLI or config files required.
  - icon:
      svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>'
    title: Audit Log
    details: Append-only record of every authentication and admin event with full filtering, retention controls, and date ranges.
  - icon:
      svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96 12 12.01l8.73-5.05M12 22.08V12"/></svg>'
    title: Zero Dependencies
    details: Single binary, single SQLite file, single Docker container. First-run setup page - no env vars needed for the admin account.
---
