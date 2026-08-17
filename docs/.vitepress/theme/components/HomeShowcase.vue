<script setup>
import { withBase } from 'vitepress'
import TiltIn from './TiltIn.vue'

const sections = [
  {
    kicker: 'Sign-in',
    title: 'Six ways in, one page',
    desc: 'Password with an emailed code, passwordless codes, an authenticator app, a passkey, a QR code scanned with your phone, or GitHub, Google and Discord. When an app starts the sign-in, its own name and icon appear on the page.',
    img: 'login',
    link: '/auth/passkeys',
  },
  {
    kicker: 'Dashboard',
    title: 'See what is happening right now',
    desc: 'Live sign-in activity, failed attempts, token counts and two-factor adoption, with a health panel that surfaces the accounts and settings that need attention.',
    img: 'admin-dashboard',
    link: '/screenshots',
  },
  {
    kicker: 'OIDC',
    title: 'An identity provider for every app',
    desc: 'Register a client and any app that speaks OpenID Connect can hand sign-in to GateKeeper. Authorization code with PKCE, RS256 tokens, group claims for role mapping, and custom claims per client. Mobile apps work too.',
    img: 'admin-clients',
    link: '/oidc/provider',
  },
  {
    kicker: 'Policies',
    title: 'Decide who reaches which app',
    desc: 'Named policies control access per application, whether it signs in through OIDC or sits behind your reverse proxy. For apps with no sign-in of their own, stored credentials are injected on the way through.',
    img: 'admin-policies',
    link: '/admin/policies',
  },
  {
    kicker: 'Audit log',
    title: 'An append-only record of everything',
    desc: 'Every authentication and admin event, filterable by category, outcome, sign-in method and date, and exportable as CSV. Failed sign-ins record why they failed and which address was tried.',
    img: 'admin-audit',
    link: '/admin/audit-log',
  },
  {
    kicker: 'Backups',
    title: 'Encrypted snapshots, restored in a click',
    desc: 'Scheduled or on-demand snapshots encrypted with AES-256-GCM, stored locally or in any S3-compatible bucket. Restoring stages the database and completes on the next restart.',
    img: 'admin-backups',
    link: '/admin/backups',
  },
]

const extras = [
  { title: 'Passkeys', desc: 'Sign in with Touch ID, Face ID or a hardware key. No password, no code.', link: '/auth/passkeys' },
  { title: 'QR code sign-in', desc: 'Scan with your phone and approve. The other device signs in on its own.', link: '/auth/qr-login' },
  { title: 'ForwardAuth', desc: 'Protect any app at Traefik, Nginx or Caddy without touching its code.', link: '/integrations/traefik-forwardauth' },
  { title: 'Groups', desc: 'Group membership rides along in every token for role mapping in your apps.', link: '/admin/groups' },
  { title: 'Social login', desc: 'GitHub, Google and Discord, linked automatically when the email matches.', link: '/admin/social-login' },
  { title: 'Invite links', desc: 'Single-use registration links with an expiry, tied to an address or open.', link: '/admin/invites' },
  { title: 'Webhooks', desc: 'Send auth events to Discord, Slack, Telegram, ntfy or any HTTP endpoint.', link: '/admin/webhooks' },
  { title: 'Admin API key', desc: 'A personal key per admin for dashboards and scripts, sent as a header.', link: '/admin/api-key' },
]

const phones = ['login', 'admin-dashboard', 'admin-users']
</script>

<template>
  <section id="features" class="hs-wrap">
    <div class="hs-head">
      <h2 class="hs-heading">Features</h2>
      <p class="hs-sub">Everything needed to put a single sign-in in front of what you run.</p>
    </div>

    <div
      v-for="(s, i) in sections"
      :key="s.kicker"
      class="hs-row"
      :class="{ 'hs-row-flip': i % 2 === 1 }"
    >
      <div class="hs-copy">
        <span class="hs-kicker">{{ s.kicker }}</span>
        <h3 class="hs-title">{{ s.title }}</h3>
        <p class="hs-desc">{{ s.desc }}</p>
        <a class="hs-link" :href="withBase(s.link)">Explore {{ s.kicker }} <span class="hs-arrow">&rarr;</span></a>
      </div>
      <div class="hs-shot">
        <TiltIn :angle="8" :lift="44" :from-scale="0.96" :fade="0">
          <img class="screenshot light-only" :src="withBase(`/screenshots/${s.img}-light.png`)" :alt="s.title" loading="lazy" />
          <img class="screenshot dark-only" :src="withBase(`/screenshots/${s.img}-dark.png`)" :alt="s.title" loading="lazy" />
        </TiltIn>
      </div>
    </div>

    <div class="hs-extras">
      <span class="hs-kicker">More in the box</span>
      <h3 class="hs-title">It keeps going</h3>
      <div class="hs-extras-grid">
        <a v-for="e in extras" :key="e.title" class="hs-extra" :href="withBase(e.link)">
          <span class="hs-extra-title">{{ e.title }}</span>
          <span class="hs-extra-desc">{{ e.desc }}</span>
        </a>
      </div>
    </div>

    <div class="hs-mobile">
      <span class="hs-kicker">On your phone</span>
      <h3 class="hs-title">The whole thing fits in a pocket</h3>
      <p class="hs-desc hs-mobile-desc">
        Every page adapts down to a phone, and both the user portal and the admin panel install to the
        home screen as their own app. Same light and dark themes.
      </p>
      <TiltIn :angle="8" :lift="44" :from-scale="0.96" :fade="0">
        <div class="hs-phones">
          <div v-for="p in phones" :key="p" class="hs-phone">
            <div class="hs-phone-screen">
              <img :src="withBase(`/screenshots/${p}-mobile-light.png`)" alt="GateKeeper on a phone" class="light-only" loading="lazy" />
              <img :src="withBase(`/screenshots/${p}-mobile-dark.png`)" alt="GateKeeper on a phone" class="dark-only" loading="lazy" />
              <div class="hs-phone-punch" />
            </div>
          </div>
        </div>
      </TiltIn>
      <a class="hs-link" :href="withBase('/getting-started/pwa')">Install as an app <span class="hs-arrow">&rarr;</span></a>
    </div>
  </section>
</template>

<style scoped>
.hs-wrap {
  max-width: 1152px;
  margin: 0 auto;
  padding: 48px 24px 24px;
  scroll-margin-top: 84px;
}

.hs-head {
  text-align: center;
  max-width: 640px;
  margin: 0 auto 72px;
}

.hs-heading {
  font-size: 32px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
  margin: 0 0 12px;
  border: none;
  padding: 0;
}

.hs-sub {
  font-size: 15px;
  color: var(--vp-c-text-2);
  line-height: 1.6;
  margin: 0;
}

.hs-row {
  display: grid;
  grid-template-columns: 5fr 7fr;
  gap: 48px;
  align-items: center;
  margin-bottom: 88px;
}

.hs-row-flip .hs-copy {
  order: 2;
}

.hs-row-flip .hs-shot {
  order: 1;
}

.hs-kicker {
  display: inline-block;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
  border-radius: 20px;
  padding: 3px 12px;
  margin-bottom: 14px;
}

.hs-title {
  font-size: 24px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
  margin: 0 0 12px;
  border: none;
  padding: 0;
  line-height: 1.25;
}

.hs-desc {
  font-size: 15px;
  line-height: 1.7;
  color: var(--vp-c-text-2);
  margin: 0 0 16px;
}

.hs-link {
  font-size: 14px;
  font-weight: 600;
  color: var(--vp-c-brand-1);
  text-decoration: none;
}

.hs-link:hover .hs-arrow {
  transform: translateX(3px);
}

.hs-arrow {
  display: inline-block;
  transition: transform 0.15s;
}

.hs-shot img {
  width: 100%;
  border-radius: 10px;
  border: 1px solid var(--vp-c-divider);
  display: block;
  box-shadow: 0 18px 50px rgba(0, 0, 0, 0.14);
}

.dark .hs-shot img {
  box-shadow: 0 18px 50px rgba(0, 0, 0, 0.5);
}

.hs-extras {
  text-align: center;
  margin: 0 0 88px;
}

.hs-extras-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 14px;
  margin-top: 28px;
  text-align: left;
}

.hs-extra {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 18px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  background: var(--vp-c-bg-soft);
  text-decoration: none;
  transition: border-color 0.2s;
}

.hs-extra:hover {
  border-color: var(--vp-c-brand-1);
}

.hs-extra-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.hs-extra-desc {
  font-size: 13px;
  line-height: 1.6;
  color: var(--vp-c-text-2);
}

.hs-mobile {
  text-align: center;
  margin-bottom: 40px;
}

.hs-mobile-desc {
  max-width: 620px;
  margin: 0 auto 32px;
}

.hs-phones {
  display: flex;
  justify-content: center;
  align-items: flex-end;
  gap: 24px;
  flex-wrap: wrap;
  margin-bottom: 28px;
}

.hs-phone {
  width: 210px;
  flex-shrink: 0;
}

.hs-phone-screen {
  position: relative;
  border-radius: 26px;
  border: 8px solid var(--vp-c-text-1);
  overflow: hidden;
  background: var(--vp-c-bg);
  box-shadow: 0 20px 46px rgba(0, 0, 0, 0.22);
}

.hs-phone-screen img {
  width: 100%;
  display: block;
}

.hs-phone-punch {
  position: absolute;
  top: 8px;
  left: 50%;
  transform: translateX(-50%);
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--vp-c-text-1);
  opacity: 0.85;
}

@media (max-width: 860px) {
  .hs-row {
    grid-template-columns: 1fr;
    gap: 24px;
    margin-bottom: 64px;
  }

  .hs-row-flip .hs-copy,
  .hs-row-flip .hs-shot {
    order: unset;
  }

  .hs-head {
    margin-bottom: 48px;
  }

  .hs-phone {
    width: 168px;
  }
}
</style>
