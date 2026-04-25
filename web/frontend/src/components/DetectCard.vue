<template>
  <div class="detect-card" :class="cardClass">
    <div class="card-header">
      <div class="card-icon" :class="`icon-${iconType}`">
        <el-icon>
          <Warning v-if="iconType === 'danger' || iconType === 'warning'" />
          <CircleCheck v-else />
        </el-icon>
      </div>
      <div class="card-title-wrap">
        <div class="card-title">{{ title }}</div>
        <div class="card-count" :class="`count-${iconType}`">
          {{ count }} 项{{ count > 0 ? '发现' : '' }}
        </div>
      </div>
      <div class="card-badge" :class="`badge-${iconType}`" v-if="count > 0">
        {{ count }}
      </div>
    </div>

    <div class="card-body">
      <div v-if="count === 0" class="card-safe">
        <el-icon><CircleCheckFilled /></el-icon>
        <span>{{ emptyText }}</span>
      </div>
      <ul v-else class="card-items">
        <li v-for="(item, i) in displayItems" :key="i" class="card-item">
          <el-icon class="item-dot"><Warning /></el-icon>
          <span>{{ item }}</span>
        </li>
        <li v-if="(items||[]).length > maxShow" class="card-more">
          还有 {{ (items||[]).length - maxShow }} 项...
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Warning, CircleCheck, CircleCheckFilled } from '@element-plus/icons-vue'

const props = defineProps<{
  title: string
  count: number
  items?: string[]
  emptyText?: string
  iconType?: 'danger' | 'warning' | 'info'
  maxShow?: number
}>()

const maxShow = computed(() => props.maxShow ?? 5)
const displayItems = computed(() => (props.items || []).slice(0, maxShow.value))
const cardClass = computed(() => {
  if (props.count === 0) return 'card-ok'
  return `card-${props.iconType || 'danger'}`
})
</script>

<style scoped>
.detect-card {
  background: #ffffff;
  border: 1px solid #e8ecf4;
  border-radius: 12px;
  overflow: hidden;
  transition: box-shadow 0.2s, border-color 0.2s;
}

.detect-card:hover {
  box-shadow: 0 4px 16px rgba(0,0,0,0.08);
}

.card-ok {
  border-color: #d1fae5;
}

.card-danger {
  border-color: #fecaca;
  background: #fffafa;
}

.card-warning {
  border-color: #fed7aa;
  background: #fffdf8;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  border-bottom: 1px solid #f0f2f5;
}

.card-icon {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  flex-shrink: 0;
}

.icon-danger  { background: #fff0f3; color: #ef233c; }
.icon-warning { background: #fff8f0; color: #f77f00; }
.icon-info    { background: #e8f0fe; color: #4361ee; }

.card-title-wrap { flex: 1; min-width: 0; }

.card-title {
  font-size: 13px;
  font-weight: 600;
  color: #1a1a2e;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.card-count {
  font-size: 11px;
  margin-top: 1px;
}

.count-danger  { color: #ef233c; }
.count-warning { color: #f77f00; }
.count-info    { color: #4361ee; }

.card-badge {
  font-size: 12px;
  font-weight: 700;
  min-width: 24px;
  height: 24px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 6px;
  flex-shrink: 0;
}

.badge-danger  { background: #fff0f3; color: #ef233c; border: 1px solid #fecaca; }
.badge-warning { background: #fff8f0; color: #f77f00; border: 1px solid #fed7aa; }
.badge-info    { background: #e8f0fe; color: #4361ee; border: 1px solid #c3d4f8; }

.card-body {
  padding: 10px 14px 12px;
}

.card-safe {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #10b981;
  padding: 4px 0;
}

.card-items {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.card-item {
  display: flex;
  align-items: flex-start;
  gap: 5px;
  font-size: 12px;
  color: #4a4a6a;
  line-height: 1.5;
}

.item-dot {
  font-size: 10px;
  color: #ef233c;
  margin-top: 3px;
  flex-shrink: 0;
}

.card-more {
  font-size: 11px;
  color: #8888aa;
  padding-left: 15px;
  font-style: italic;
}
</style>
