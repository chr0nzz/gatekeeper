<script setup>
import { withBase } from 'vitepress'
import TiltIn from './TiltIn.vue'
</script>

<template>
  <div class="sm-wrap">
    <TiltIn>
      <div class="sm-stage">
        <div class="sm-glow sm-glow-a" />
        <div class="sm-glow sm-glow-b" />
        <div class="sm-glow sm-glow-c" />

        <div class="sm-monitor">
          <div class="sm-monitor-bezel">
            <div class="sm-monitor-screen">
              <img :src="withBase('/screenshots/admin-dashboard-light.png')" alt="The GateKeeper dashboard" class="light-only" />
              <img :src="withBase('/screenshots/admin-dashboard-dark.png')" alt="The GateKeeper dashboard" class="dark-only" />
            </div>
          </div>
          <div class="sm-monitor-neck" />
          <div class="sm-monitor-foot" />
        </div>

        <div class="sm-tablet">
          <div class="sm-tablet-screen">
            <img :src="withBase('/screenshots/admin-dashboard-tablet-light.png')" alt="GateKeeper on a tablet" class="light-only" />
            <img :src="withBase('/screenshots/admin-dashboard-tablet-dark.png')" alt="GateKeeper on a tablet" class="dark-only" />
          </div>
        </div>

        <div class="sm-phone">
          <div class="sm-phone-screen">
            <img :src="withBase('/screenshots/admin-dashboard-mobile-light.png')" alt="GateKeeper on a phone" class="light-only" />
            <img :src="withBase('/screenshots/admin-dashboard-mobile-dark.png')" alt="GateKeeper on a phone" class="dark-only" />
            <div class="sm-phone-punch" />
          </div>
        </div>
      </div>
    </TiltIn>
  </div>
</template>

<style scoped>
.sm-wrap {
  padding: 72px 24px 140px;
  width: 100%;
  overflow: hidden;
}

.sm-stage {
  position: relative;
  max-width: 960px;
  margin: 0 auto;
}

.sm-glow {
  position: absolute;
  pointer-events: none;
  opacity: 0.35;
  z-index: 0;
}

.sm-glow-a { width: 62%; aspect-ratio: 1; left: -4%; bottom: -10%; background: radial-gradient(circle closest-side, rgba(99, 102, 241, 0.45), transparent); }
.sm-glow-b { width: 56%; aspect-ratio: 1; left: 28%; bottom: -12%; background: radial-gradient(circle closest-side, rgba(139, 92, 246, 0.45), transparent); }
.sm-glow-c { width: 62%; aspect-ratio: 1; right: -3%; top: 0; background: radial-gradient(circle closest-side, rgba(56, 189, 248, 0.4), transparent); }

.dark .sm-glow { opacity: 0.75; }

.sm-monitor {
  position: relative;
  margin-left: 9%;
  width: 75%;
  z-index: 1;
}

.sm-monitor-bezel {
  background: #16191d;
  border-radius: 12px;
  padding: 10px;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.2);
}

.dark .sm-monitor-bezel {
  box-shadow: 0 30px 70px rgba(0, 0, 0, 0.55);
}

.sm-monitor-screen {
  border-radius: 5px;
  overflow: hidden;
  aspect-ratio: 1440 / 900;
}

.sm-monitor-screen img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: top left;
  display: block;
}

.sm-monitor-neck {
  width: 12%;
  height: 36px;
  background: #1b1f24;
  margin: 0 auto;
}

.sm-monitor-foot {
  width: 30%;
  height: 12px;
  border-radius: 7px;
  background: #23282e;
  margin: 0 auto;
}

.sm-tablet {
  position: absolute;
  left: 47%;
  bottom: -44px;
  width: 33%;
  background: #16191d;
  border-radius: 16px;
  padding: 8px;
  box-shadow: 0 22px 54px rgba(0, 0, 0, 0.3);
  z-index: 2;
}

.dark .sm-tablet {
  box-shadow: 0 26px 64px rgba(0, 0, 0, 0.6);
}

.sm-tablet-screen {
  border-radius: 10px;
  overflow: hidden;
  aspect-ratio: 820 / 1180;
}

.sm-tablet-screen img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: top left;
  display: block;
}

.sm-phone {
  position: absolute;
  left: 74%;
  bottom: -66px;
  width: 16.5%;
  background: #16191d;
  border-radius: 24px;
  padding: 5px;
  box-shadow: -12px 22px 54px rgba(0, 0, 0, 0.4);
  z-index: 3;
}

.dark .sm-phone {
  box-shadow: -12px 22px 54px rgba(0, 0, 0, 0.68);
}

.sm-phone-screen {
  border-radius: 20px;
  overflow: hidden;
  aspect-ratio: 390 / 844;
  position: relative;
}

.sm-phone-screen img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: top;
  display: block;
}

.sm-phone-punch {
  position: absolute;
  top: 7px;
  left: 50%;
  transform: translateX(-50%);
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #05070a;
}

.light-only,
.dark-only {
  display: block;
}

@media (max-width: 640px) {
  .sm-wrap {
    padding-bottom: 90px;
  }

  .sm-tablet {
    display: none;
  }

  .sm-monitor {
    width: 100%;
    margin-left: 0;
  }

  .sm-phone {
    left: auto;
    right: 0;
    bottom: -48px;
    width: 24%;
    border-radius: 18px;
    padding: 3px;
  }

  .sm-phone-screen {
    border-radius: 15px;
  }

  .sm-phone-punch {
    width: 5px;
    height: 5px;
    top: 5px;
  }
}
</style>
