import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'GateKeeper',
  description: 'Self-hosted authentication server with OIDC, passkeys, TOTP, and a full admin UI.',

  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
  ],

  vite: {
    server: {
      allowedHosts: ['gatekeeper.xyzlab.dev'],
    },
  },

  themeConfig: {
    logo: '/favicon.svg',
    siteTitle: 'GateKeeper',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'Installation', link: '/getting-started/installation' },
      { text: 'Security', link: '/security/overview' },
      { text: 'Reference', link: '/reference/env-vars' },
      {
        text: 'v0.9.1',
        items: [
          { text: 'Changelog', link: '/reference/changelog' },
          { text: 'GitHub', link: 'https://github.com/chr0nzz/gatekeeper' },
        ],
      },
    ],

    sidebar: [
      {
        text: 'Getting started',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Installation', link: '/getting-started/installation' },
          { text: 'Configuration', link: '/getting-started/configuration' },
          { text: 'First login', link: '/getting-started/first-login' },
          { text: 'Install as an app (PWA)', link: '/getting-started/pwa' },
        ],
      },
      {
        text: 'Sign-in methods',
        items: [
          { text: 'Password + email OTP', link: '/auth/password-otp' },
          { text: 'Passwordless (email OTP)', link: '/auth/passwordless' },
          { text: 'TOTP (authenticator app)', link: '/auth/totp' },
          { text: 'TOTP recovery codes', link: '/auth/totp-recovery' },
          { text: 'Passkeys', link: '/auth/passkeys' },
          { text: 'QR code sign-in', link: '/auth/qr-login' },
          { text: 'Password recovery', link: '/auth/password-recovery' },
          { text: 'Password change', link: '/auth/password-change' },
          { text: 'Your profile', link: '/auth/profile' },
        ],
      },
      {
        text: 'OIDC provider',
        items: [
          { text: 'Overview', link: '/oidc/provider' },
          { text: 'Managing clients', link: '/admin/managing-clients' },
          { text: 'Custom claims', link: '/admin/custom-claims' },
        ],
      },
      {
        text: 'Admin guide',
        items: [
          { text: 'Managing users', link: '/admin/managing-users' },
          { text: 'Audit log', link: '/admin/audit-log' },
          { text: 'Settings', link: '/admin/settings' },
          { text: 'Access policies', link: '/admin/policies' },
          { text: 'Groups', link: '/admin/groups' },
          { text: 'Invite links', link: '/admin/invites' },
          { text: 'User registration', link: '/admin/registration' },
          { text: 'Social login', link: '/admin/social-login' },
          { text: 'Webhooks', link: '/admin/webhooks' },
          { text: 'Notification log', link: '/admin/notifications' },
          { text: 'Backups', link: '/admin/backups' },
          { text: 'API key', link: '/admin/api-key' },
        ],
      },
      {
        text: 'Integrations',
        items: [
          { text: 'Traefik ForwardAuth', link: '/integrations/traefik-forwardauth' },
          { text: 'Nginx auth_request', link: '/integrations/nginx' },
          { text: 'Caddy forward_auth', link: '/integrations/caddy' },
          { text: 'Cross-domain ForwardAuth', link: '/integrations/cross-domain' },
          { text: 'Protecting an app (example)', link: '/integrations/example-app' },
          { text: 'OIDC client examples', link: '/integrations/oidc-client-examples' },
        ],
      },
      {
        text: 'Security',
        items: [
          { text: 'Security overview', link: '/security/overview' },
          { text: 'Password policy', link: '/security/password-policy' },
          { text: 'Session security', link: '/security/session-security' },
          { text: 'OTP security', link: '/security/otp-security' },
          { text: 'TOTP security', link: '/security/totp-security' },
          { text: 'Rate limiting', link: '/security/rate-limiting' },
          { text: 'OIDC security', link: '/security/oidc-security' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Environment variables', link: '/reference/env-vars' },
          { text: 'Database schema', link: '/reference/database-schema' },
          { text: 'API endpoints', link: '/reference/api' },
          { text: 'Changelog', link: '/reference/changelog' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/chr0nzz/gatekeeper' },
    ],

    search: {
      provider: 'local',
    },

    editLink: {
      pattern: 'https://github.com/chr0nzz/gatekeeper/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
  },
})
