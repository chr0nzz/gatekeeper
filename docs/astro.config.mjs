import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://auth.example.com',
  integrations: [
    sitemap(),
    starlight({
      title: 'GateKeeper Docs',
      defaultLocale: 'root',
      locales: { root: { label: 'English', lang: 'en' } },
      customCss: ['./src/styles/custom.css'],
      social: [],
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Installation', link: '/getting-started/installation' },
            { label: 'Configuration', link: '/getting-started/configuration' },
            { label: 'First login', link: '/getting-started/first-login' },
          ],
        },
        {
          label: 'Authentication',
          items: [
            { label: 'Password + email OTP', link: '/auth/password-otp' },
            { label: 'Passwordless OTP', link: '/auth/passwordless' },
            { label: 'Password recovery', link: '/auth/password-recovery' },
            { label: 'Password change', link: '/auth/password-change' },
            { label: 'TOTP (authenticator app)', link: '/auth/totp' },
            { label: 'TOTP recovery codes', link: '/auth/totp-recovery' },
            { label: 'Passkeys', link: '/auth/passkeys' },
          ],
        },
        {
          label: 'Traefik integration',
          items: [
            { label: 'ForwardAuth setup', link: '/traefik/forwardauth' },
            { label: 'OIDC provider', link: '/traefik/oidc-provider' },
          ],
        },
        {
          label: 'Admin guide',
          items: [
            { label: 'Managing users', link: '/admin/managing-users' },
            { label: 'Managing OIDC clients', link: '/admin/managing-clients' },
            { label: 'Audit log', link: '/admin/audit-log' },
            { label: 'Settings', link: '/admin/settings' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'Security overview', link: '/security/overview' },
            { label: 'Password policy', link: '/security/password-policy' },
            { label: 'Session security', link: '/security/session-security' },
            { label: 'OTP security', link: '/security/otp-security' },
            { label: 'TOTP security', link: '/security/totp-security' },
            { label: 'OIDC security', link: '/security/oidc-security' },
          ],
        },
        {
          label: 'Integrations',
          items: [
            { label: 'Protecting an app', link: '/integrations/example-app' },
            { label: 'OIDC client examples', link: '/integrations/oidc-client-examples' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'API endpoints', link: '/reference/api' },
            { label: 'Environment variables', link: '/reference/env-vars' },
            { label: 'Database schema', link: '/reference/database-schema' },
            { label: 'Changelog', link: '/reference/changelog' },
          ],
        },
      ],
    }),
  ],
});
