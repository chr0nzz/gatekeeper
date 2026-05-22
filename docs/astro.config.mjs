import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://auth.example.com',
  integrations: [
    sitemap(),
    starlight({
      title: 'GateKeeper',
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
          label: 'Sign-in methods',
          items: [
            { label: 'Password + email OTP', link: '/auth/password-otp' },
            { label: 'Passwordless (email OTP)', link: '/auth/passwordless' },
            { label: 'TOTP (authenticator app)', link: '/auth/totp' },
            { label: 'TOTP recovery codes', link: '/auth/totp-recovery' },
            { label: 'Passkeys', link: '/auth/passkeys' },
            { label: 'Password recovery', link: '/auth/password-recovery' },
            { label: 'Password change', link: '/auth/password-change' },
          ],
        },
        {
          label: 'OIDC provider',
          items: [
            { label: 'Overview', link: '/oidc/provider' },
            { label: 'Managing clients', link: '/admin/managing-clients' },
          ],
        },
        {
          label: 'Admin guide',
          items: [
            { label: 'Managing users', link: '/admin/managing-users' },
            { label: 'Audit log', link: '/admin/audit-log' },
            { label: 'Settings', link: '/admin/settings' },
          ],
        },
        {
          label: 'Integrations',
          items: [
            { label: 'Traefik ForwardAuth', link: '/integrations/traefik-forwardauth' },
            { label: 'Protecting an app (example)', link: '/integrations/example-app' },
            { label: 'OIDC client examples', link: '/integrations/oidc-client-examples' },
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
          label: 'Reference',
          items: [
            { label: 'Environment variables', link: '/reference/env-vars' },
            { label: 'Database schema', link: '/reference/database-schema' },
            { label: 'API endpoints', link: '/reference/api' },
            { label: 'Changelog', link: '/reference/changelog' },
          ],
        },
      ],
    }),
  ],
});
