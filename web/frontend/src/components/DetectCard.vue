<template>
  <div class="detect-card" :class="cardClass">
    <!-- 左侧颜色条 -->
    <div class="card-stripe" :class="`stripe-${effectiveSeverity}`"></div>

    <div class="card-inner">
      <!-- 头部：图标 + 标题 + 大数字 -->
      <div class="card-header">
        <div class="card-icon-wrap" :class="`icon-bg-${effectiveSeverity}`">
          <el-icon class="card-icon"><component :is="iconComponent" /></el-icon>
        </div>
        <div class="card-title-area">
          <div class="card-title">{{ title }}</div>
          <div class="card-subtitle" :class="`sub-${effectiveSeverity}`">
            <el-icon v-if="count === 0"><CircleCheck /></el-icon>
            <span>{{ count === 0 ? '未发现异常' : `发现 ${count} 项威胁` }}</span>
          </div>
        </div>
        <!-- 大数字徽章 -->
        <div class="big-count" :class="`count-${effectiveSeverity}`">{{ count }}</div>
      </div>

      <!-- 分隔线 -->
      <div class="card-divider"></div>

      <!-- 内容区 -->
      <div class="card-body">
        <div v-if="count === 0" class="card-safe">
          <el-icon><CircleCheckFilled /></el-icon>
          <span>{{ emptyText || '未发现异常' }}</span>
        </div>
        <ul v-else class="card-items">
          <li v-for="(item, i) in displayItems" :key="i" class="card-item">
            <span class="item-bullet" :class="`bullet-${effectiveSeverity}`"></span>
            <span class="item-text">{{ item }}</span>
          </li>
          <li v-if="(items||[]).length > maxShowNum" class="card-more">
            <el-icon><More /></el-icon>还有 {{ (items||[]).length - maxShowNum }} 项...
          </li>
        </ul>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import {
  Warning, CircleCheck, CircleCheckFilled, Hide, Connection,
  Operation, Grid, More, Cpu, Lock, DataLine
} from '@element-plus/icons-vue'

const props = defineProps<{
  title: string
  count: number
  items?: string[]
  emptyText?: string
  severity?: 'critical' | 'high' | 'medium' | 'low'
  icon?: string
  maxShow?: number
}>()

const maxShowNum = computed(() => props.maxShow ?? 5)
const displayItems = computed(() => (props.items || []).slice(0, maxShowNum.value))

const effectiveSeverity = computed(() =>
  props.count === 0 ? 'safe' : (props.severity || 'critical')
)

const cardClass = computed(() => `card-${effectiveSeverity.value}`)

const iconComponent = computed(() => {
  const iconMap: Record<string, any> = {
    hide: Hide, warning: Warning, connection: Connection,
    hook: Operation, module: Grid, irp: DataLine,
    keyboard: Lock, cpu: Cpu, lock: Lock,
  }
  return iconMap[props.icon || 'warning'] || Warning
})
</script>

<style scoped>
.detect-card {
  background: #ffffff;
  border: 1.5px solid #e8ecf4;
  border-radius: 12px;
  overflow: hidden;
  display: flex;
  transition: box-shadow 0.18s, transform 0.18s;
}
.detect-card:hover {
  box-shadow: 0 6px 20px rgba(0,0,0,0.08);
  transform: translateY(-1px);
}

/* ── 左侧颜色条 ── */
.card-stripe { width: 4px; flex-shrink: 0; }
.stripe-critical { background: linear-gradient(180deg,#dc2626,#ef4444); }
.stripe-high     { background: linear-gradient(180deg,#ea580c,#f97316); }
.stripe-medium   { background: linear-gradient(180deg,#2563eb,#60a5fa); }
.stripe-low      { background: linear-gradient(180deg,#6b7280,#9ca3af); }
.stripe-safe     { background: linear-gradient(180deg,#16a34a,#4ade80); }

/* ── 卡片状态背景/边框 ── */
.card-critical { border-color: #fecaca; background: #fffafa; }
.card-high     { border-color: #fed7aa; background: #fff9f5; }
.card-medium   { border-color: #bfdbfe; background: #f8fbff; }
.card-low      { border-color: #e5e7eb; }
.card-safe     { border-color: #bbf7d0; background: #f0fdf4; }

.card-inner { flex: 1; min-width: 0; display: flex; flex-direction: column; }

/* ── 头部 ── */
.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 11px 13px 9px;
}

.card-icon-wrap {
  width: 36px; height: 36px;
  border-radius: 9px;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}
.icon-bg-critical { background: #fee2e2; }
.icon-bg-high     { background: #ffedd5; }
.icon-bg-medium   { background: #dbeafe; }
.icon-bg-low      { background: #f3f4f6; }
.icon-bg-safe     { background: #dcfce7; }

.card-icon { font-size: 17px; }
.card-critical .card-icon { color: #dc2626; }
.card-high     .card-icon { color: #ea580c; }
.card-medium   .card-icon { color: #2563eb; }
.card-low      .card-icon { color: #6b7280; }
.card-safe     .card-icon { color: #16a34a; }

.card-title-area { flex: 1; min-width: 0; }
.card-title {
  font-size: 12.5px; font-weight: 700; color: #1e1e3a;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  margin-bottom: 2px;
}
.card-subtitle {
  display: flex; align-items: center; gap: 3px;
  font-size: 10.5px; font-weight: 500;
}
.sub-critical { color: #dc2626; }
.sub-high     { color: #ea580c; }
.sub-medium   { color: #2563eb; }
.sub-low      { color: #6b7280; }
.sub-safe     { color: #16a34a; }

/* ── 大数字 ── */
.big-count {
  font-size: 28px;
  font-weight: 900;
  line-height: 1;
  flex-shrink: 0;
  min-width: 36px;
  text-align: right;
  letter-spacing: -1px;
}
.count-critical { color: #dc2626; }
.count-high     { color: #ea580c; }
.count-medium   { color: #2563eb; }
.count-low      { color: #6b7280; }
.count-safe     { color: #22c55e; }

/* ── 分隔线 ── */
.card-divider { height: 1px; background: #f0f2f5; margin: 0 13px; }

/* ── 内容区 ── */
.card-body { padding: 8px 13px 11px; flex: 1; }

.card-safe {
  display: flex; align-items: center; gap: 6px;
  font-size: 11.5px; color: #16a34a; padding: 3px 0;
}
.card-safe .el-icon { font-size: 14px; }

.card-items {
  list-style: none; padding: 0; margin: 0;
  display: flex; flex-direction: column; gap: 4px;
}
.card-item {
  display: flex; align-items: flex-start; gap: 7px;
  font-size: 11.5px; color: #374151; line-height: 1.5;
}
.item-bullet {
  width: 5px; height: 5px; border-radius: 50%;
  flex-shrink: 0; margin-top: 5px;
}
.bullet-critical { background: #dc2626; }
.bullet-high     { background: #ea580c; }
.bullet-medium   { background: #2563eb; }
.bullet-low      { background: #9ca3af; }

.item-text {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 11px;
  word-break: break-all;
}

.card-more {
  display: flex; align-items: center; gap: 4px;
  font-size: 11px; color: #9ca3af; padding-left: 12px;
  font-style: italic;
}
</style>
