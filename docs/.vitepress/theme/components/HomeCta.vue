<script setup>
import { ref } from 'vue'
import { withBase } from 'vitepress'

const copied = ref(false)
const cmd = 'docker pull ghcr.io/chr0nzz/gatekeeper:latest'

function copy() {
  navigator.clipboard.writeText(cmd)
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}
</script>

<template>
  <section class="cta-wrap">
    <div class="cta-box">
      <h2 class="cta-title">Put a front door on your homelab</h2>
      <p class="cta-sub">One container, a SQLite file, and everything else configured from the admin panel.</p>
      <div class="cta-install">
        <code class="cta-cmd">{{ cmd }}</code>
        <button class="cta-copy" @click="copy" :aria-label="copied ? 'Copied' : 'Copy'">
          <svg v-if="!copied" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 0 1-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 0 1 1.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 0 0-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 0 1-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 0 0-3.375-3.375h-1.5a1.125 1.125 0 0 1-1.125-1.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H9.75"/></svg>
          <svg v-else xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>
        </button>
      </div>
      <p class="cta-support">Free and open source. If it saves you time, a star goes a long way.</p>
      <div class="cta-actions">
        <a class="cta-btn cta-btn-primary" href="https://github.com/chr0nzz/gatekeeper" target="_blank" rel="noopener noreferrer">
          <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 16 16" fill="currentColor"><path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z"/></svg>
          Star on GitHub
        </a>
        <a class="cta-btn" :href="withBase('/getting-started/installation')">Install</a>
        <a class="cta-btn" :href="withBase('/screenshots')">Screenshots</a>
      </div>
    </div>
  </section>
</template>

<style scoped>
.cta-wrap {
  max-width: 1152px;
  margin: 0 auto;
  padding: 8px 24px 48px;
}

.cta-box {
  position: relative;
  overflow: hidden;
  text-align: center;
  border: 1px solid var(--vp-c-divider);
  border-radius: 16px;
  padding: 48px 32px;
  background:
    radial-gradient(ellipse 60% 120% at 20% 0%, rgba(99, 102, 241, 0.08), transparent),
    radial-gradient(ellipse 60% 120% at 80% 100%, rgba(139, 92, 246, 0.08), transparent),
    var(--vp-c-bg-soft);
}

.dark .cta-box {
  background:
    radial-gradient(ellipse 60% 120% at 20% 0%, rgba(99, 102, 241, 0.16), transparent),
    radial-gradient(ellipse 60% 120% at 80% 100%, rgba(139, 92, 246, 0.16), transparent),
    var(--vp-c-bg-soft);
}

.cta-title {
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
  margin: 0 0 10px;
  border: none;
  padding: 0;
}

.cta-sub {
  font-size: 15px;
  color: var(--vp-c-text-2);
  margin: 0 0 20px;
}

.cta-install {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  background: var(--vp-c-bg);
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  padding: 12px 16px;
  max-width: 100%;
  box-sizing: border-box;
  margin: 0 0 24px;
}

.cta-cmd {
  font-family: var(--vp-font-family-mono, monospace);
  font-size: 13px;
  color: var(--vp-c-text-1);
  white-space: nowrap;
  overflow-x: auto;
  min-width: 0;
}

.cta-copy {
  background: none;
  border: none;
  cursor: pointer;
  color: var(--vp-c-text-2);
  padding: 0;
  display: flex;
  align-items: center;
  transition: color 0.15s;
  flex-shrink: 0;
}

.cta-copy:hover {
  color: var(--vp-c-brand-1);
}

.cta-support {
  font-size: 13px;
  color: var(--vp-c-text-2);
  margin: 0 0 18px;
}

.cta-actions {
  display: flex;
  justify-content: center;
  gap: 12px;
  flex-wrap: wrap;
}

.cta-btn {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 9px 22px;
  border-radius: 22px;
  border: 1px solid var(--vp-c-divider);
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;
  color: var(--vp-c-text-1);
  background: var(--vp-c-bg);
  transition: border-color 0.2s, opacity 0.2s;
}

.cta-btn:hover {
  border-color: var(--vp-c-brand-1);
}

.cta-btn-primary {
  background: var(--vp-c-brand-1);
  border-color: var(--vp-c-brand-1);
  color: #ffffff;
}

.cta-btn-primary:hover {
  opacity: 0.88;
}
</style>
