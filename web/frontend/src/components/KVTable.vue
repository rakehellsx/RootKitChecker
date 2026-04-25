<template>
  <div class="kv-table" v-if="rows && rows.length">
    <div class="kv-row" v-for="(row, i) in rows" :key="i" :class="{ 'kv-even': i % 2 === 0 }">
      <div class="kv-key">
        <span class="key-dot"></span>
        {{ row.key || row.name || row[0] || '-' }}
      </div>
      <div class="kv-val">{{ row.value || row.val || row[1] || '-' }}</div>
    </div>
  </div>
  <div class="kv-empty" v-else>
    <el-icon><InfoFilled /></el-icon>
    <span>暂无数据</span>
  </div>
</template>

<script setup lang="ts">
import { InfoFilled } from '@element-plus/icons-vue'
defineProps<{ rows?: any[] }>()
</script>

<style scoped>
.kv-table {
  display: flex;
  flex-direction: column;
  border: 1.5px solid #eaecf4;
  border-radius: 9px;
  overflow: hidden;
}

.kv-row {
  display: flex;
  align-items: stretch;
  border-bottom: 1px solid #f0f2f5;
  transition: background 0.12s;
}
.kv-row:last-child { border-bottom: none; }
.kv-row:hover { background: #f0f4ff !important; }
.kv-even { background: #fafbff; }

.kv-key {
  flex: 0 0 190px;
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 7px 12px;
  font-size: 11.5px;
  font-weight: 600;
  color: #374151;
  border-right: 1.5px solid #eef0f8;
  word-break: break-all;
  line-height: 1.4;
}

.key-dot {
  width: 5px; height: 5px;
  border-radius: 50%;
  background: #818cf8;
  flex-shrink: 0;
}

.kv-val {
  flex: 1;
  padding: 7px 12px;
  font-size: 11.5px;
  color: #1e1e3a;
  font-family: 'Consolas', 'Monaco', 'Cascadia Code', monospace;
  word-break: break-all;
  line-height: 1.5;
}

.kv-empty {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 16px;
  font-size: 12px;
  color: #b0b8d8;
}
</style>
