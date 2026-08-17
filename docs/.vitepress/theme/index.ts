import { h } from 'vue'
import DefaultTheme from 'vitepress/theme'
import HomeHero from './components/HomeHero.vue'
import HomeShowcase from './components/HomeShowcase.vue'
import HomeCta from './components/HomeCta.vue'
import './style.css'

export default {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'home-hero-before': () => h(HomeHero),
      'home-features-before': () => h(HomeCta),
      'home-features-after': () => h(HomeShowcase),
    })
  },
}
