<template>
  <div class="kernel-section">
    <div class="section-header" @click="collapsed = !collapsed">
      <div class="section-icon" :style="{ background: iconBg, color: iconColor }">
        <slot name="icon" />
      </div>
      <div class="section-title">{{ title }}</div>
      <el-tag v-if="count !== undefined" size="small" class="section-count"
        :type="count > 0 ? 'primary' : 'info'" effect="light">
        {{ count }} {{ countLabel || '条' }}
      </el-tag>
      <el-icon class="collapse-icon" :class="{ rotated: collapsed }">
        <ArrowDown />
      </el-icon>
    </div>
    <div class="section-body" v-show="!collapsed">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { ArrowDown } from '@element-plus/icons-vue'

const props = defineProps<{
  title: string
  iconColor?: string
  count?: number
  countLabel?: string
}>()

const collapsed = ref(false)

const iconBg = computed(() => {
  const c = props.iconColor || '#4361ee'
  // 生成浅色背景
  const map: Record<string, string> = {
    '#4361ee': '#eef2ff',
    '#ef233c': '#fff0f3',
    '#f77f00': '#fff8f0',
    '#7c3aed': '#f5f0ff',
    '#06d6a0': '#ecfdf5',
    '#0078d4': '#e8f0fe',
  }
  return map[c] || '#f0f4ff'
})
</script>

<style scoped>
.kernel-section {
  background: #ffffff;
  border: 1px solid #e8ecf4;
  border-radius: 12px;
  overflow: hidden;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  cursor: pointer;
  user-select: none;
  transition: background 0.15s;
}

.section-header:hover {
  background: #f8f9fc;
}

.section-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  flex-shrink: 0;
}

.section-title {
  font-size: 14px;
  font-weight: 600;
  color: #1a1a2e;
  flex: 1;
}

.section-count {
  font-size: 11px;
}

.collapse-icon {
  font-size: 14px;
  color: #b0b8d8;
  transition: transform 0.2s;
}

.collapse-icon.rotated {
  transform: rotate(-90deg);
}

.section-body {
  padding: 0 16px 14px;
  border-top: 1px solid #f0f2f5;
}
</style>
