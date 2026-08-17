<script setup>
import { withBase } from 'vitepress'
</script>

<template>
  <section class="hh-wrap">
    <div class="hh-brand">
      <img :src="withBase('/favicon.svg')" alt="GateKeeper" width="46" height="46" />
      <span class="hh-name">GateKeeper</span>
    </div>
    <h1 class="hh-headline">One sign-in for everything you self-host</h1>
    <p class="hh-tagline">
      An authentication server in a single container. Protect any app with OIDC or your reverse proxy,
      and sign in with passkeys, an authenticator, an emailed code, or your phone.
    </p>
    <div class="hh-actions">
      <a class="hh-btn hh-btn-brand" :href="withBase('/getting-started/installation')">Get Started</a>
      <a class="hh-btn" href="#features">Features</a>
      <a class="hh-btn" href="https://github.com/chr0nzz/gatekeeper" target="_blank" rel="noopener noreferrer">GitHub</a>
    </div>
  </section>
</template>

<style scoped>
.hh-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  padding: 72px 24px 8px;
}

.hh-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 20px;
}

.hh-brand img {
  width: 46px;
  height: 46px;
}

.hh-name {
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.01em;
  background: linear-gradient(120deg, var(--vp-c-brand-1), var(--vp-c-brand-2));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.hh-headline {
  font-size: clamp(34px, 6vw, 56px);
  font-weight: 800;
  letter-spacing: -0.02em;
  line-height: 1.1;
  color: var(--vp-c-text-1);
  margin: 0 0 16px;
  max-width: 760px;
}

.hh-tagline {
  font-size: 17px;
  line-height: 1.6;
  color: var(--vp-c-text-2);
  margin: 0 0 28px;
  max-width: 620px;
}

.hh-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  justify-content: center;
}

.hh-btn {
  display: inline-block;
  padding: 9px 22px;
  border-radius: 22px;
  border: 1px solid var(--vp-c-divider);
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;
  color: var(--vp-c-text-1);
  background: var(--vp-c-bg-soft);
  transition: border-color 0.2s, opacity 0.2s;
}

.hh-btn:hover {
  border-color: var(--vp-c-brand-1);
}

.hh-btn-brand {
  background: var(--vp-c-brand-1);
  border-color: var(--vp-c-brand-1);
  color: #ffffff;
}

.hh-btn-brand:hover {
  opacity: 0.88;
}

@media (max-width: 640px) {
  .hh-wrap {
    padding-top: 48px;
  }
}
</style>
