<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const props = defineProps({
  angle: { type: Number, default: 90 },
  lift: { type: Number, default: 0 },
  fromScale: { type: Number, default: 1 },
  fade: { type: Number, default: 0.2 },
})

const stage = ref(null)
let raf = 0

function update() {
  raf = 0
  const el = stage.value
  if (!el) return
  const rect = el.getBoundingClientRect()
  const vh = window.innerHeight
  const p = Math.min(1, Math.max(0, (vh - rect.top) / (vh * 0.85)))
  const eased = 1 - Math.pow(1 - p, 3)
  if (eased >= 0.999) {
    el.style.transform = 'none'
    el.style.opacity = ''
    return
  }
  const r = 1 - eased
  const scale = 1 - (1 - props.fromScale) * r
  el.style.transform = `rotateX(${(props.angle * r).toFixed(2)}deg) translateY(${(props.lift * r).toFixed(1)}px) scale(${scale.toFixed(4)})`
  el.style.opacity = (props.fade + (1 - props.fade) * eased).toFixed(3)
}

function onScroll() {
  if (!raf) raf = requestAnimationFrame(update)
}

onMounted(() => {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
  update()
  window.addEventListener('scroll', onScroll, { passive: true })
  window.addEventListener('resize', onScroll, { passive: true })
})

onUnmounted(() => {
  window.removeEventListener('scroll', onScroll)
  window.removeEventListener('resize', onScroll)
  if (raf) cancelAnimationFrame(raf)
})
</script>

<template>
  <div class="tilt-wrap">
    <div ref="stage" class="tilt-stage">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.tilt-wrap {
  perspective: 1400px;
}

.tilt-stage {
  transform-origin: 50% 100%;
}
</style>
