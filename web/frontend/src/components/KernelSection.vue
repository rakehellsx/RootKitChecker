<template>
  <div class="kernel-section" :class="{ 'is-open': !collapsed }">
    <div class="section-header" @click="collapsed = !collapsed">
      <!-- 图标 -->
      <div class="section-icon" :style="{ background: iconBg, color: iconColor }">
        <slot name="icon" />
      </div>
      <!-- 标题 -->
      <div class="section-title">{{ title }}</div>
      <!-- 右侧 meta -->
      <div class="section-meta">
        <span
          v-if="count !== undefined"
          class="section-count"
          :class="count > 0 ? 'count-active' : 'count-zero'"
        >
          {{ count }} {{ countLabel || '条' }}
        </span>
        <div class="collapse-btn" :class="{ rotated: !collapsed }">
          <el-icon><ArrowRight /></el-icon>
        </div>
      </div>
    </div>

    <transition name="slide-fade">
      <div class="section-body" v-show="!collapsed">
        <slot />
      </div>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { ArrowRight } from '@element-plus/icons-vue'

const props = defineProps<{
  title: string
  iconColor?: string
  count?: number
  countLabel?: string
  defaultOpen?: boolean
}>()

const collapsed = ref(!(props.defaultOpen ?? false))

const iconBg = computed(() => {
  const c = props.iconColor || '#4361ee'
  const map: Record<string, string> = {
    '#4361ee': '#eef2ff',
    '#ef233c': '#fff0f3',
    '#f77f00': '#fff8f0',
    '#7c3aed': '#f5f0ff',
    '#06d6a0': '#ecfdf5',
    '#0078d4': '#e8f0fe',
    '#ea580c': '#fff7ed',
  }
  return map[c] || '#eef2ff'
})

const iconColor = computed(() => props.iconColor || '#4361ee')
</script>

<style scoped>
.kernel-section {
  background: #ffffff;
  border: 1.5px solid #eaecf4;
  border-radius: 11px;
  overflow: hidden;
  transition: box-shadow 0.2s, border-color 0.2s;
}
.kernel-section.is-open {
  box-shadow: 0 2px 12px rgba(67, 97, 238, 0.07);
  border-color: #c7d2fe;
}

/* ── 头部 ── */
.section-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  cursor: pointer;
  user-select: none;
  transition: background 0.15s;
  background: #fafbff;
}
.kernel-section.is-open .section-header {
  background: #f5f7ff;
  border-bottom: 1px solid #eef0f8;
}
.section-header:hover { background: #f0f4ff; }

.section-icon {
  width: 32px; height: 32px;
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 15px; flex-shrink: 0;
}

.section-title {
  font-size: 13px;
  font-weight: 700;
  color: #1e1e3a;
  flex: 1;
  letter-spacing: 0.1px;
}

.section-meta {
  display: flex;
  align-items: center;
  gap: 8px;
}

.section-count {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 9px;
  border-radius: 10px;
}
.count-active { background: #eef2ff; color: #4361ee; }
.count-zero   { background: #f3f4f6; color: #9ca3af; }

.collapse-btn {
  width: 22px; height: 22px;
  border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
  background: #eef2ff;
  color: #4361ee;
  font-size: 12px;
  transition: transform 0.22s ease, background 0.15s;
}
.collapse-btn.rotated { transform: rotate(90deg); }
.section-header:hover .collapse-btn { background: #dde5ff; }

/* ── 内容区 ── */
.section-body {
  padding: 12px 14px 14px;
}

/* ── 展开动画 ── */
.slide-fade-enter-active { transition: all 0.22s ease; }
.slide-fade-leave-active { transition: all 0.16s ease; }
.slide-fade-enter-from, .slide-fade-leave-to {
  opacity: 0;
  transform: translateY(-6px);
}
</style>
