<template>
  <div class="kv-table" v-if="rows && rows.length">
    <div class="kv-row" v-for="(row, i) in rows" :key="i">
      <div class="kv-key">{{ row.key || row.name || row[0] || '-' }}</div>
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
  gap: 2px;
  padding: 4px 0;
}

.kv-row {
  display: flex;
  align-items: flex-start;
  border-radius: 6px;
  overflow: hidden;
  border: 1px solid #f0f2f5;
  transition: background 0.15s;
}

.kv-row:hover {
  background: #f8f9fc;
}

.kv-key {
  flex: 0 0 220px;
  padding: 7px 12px;
  font-size: 12px;
  font-weight: 600;
  color: #4a4a6a;
  background: #f8f9fc;
  border-right: 1px solid #e8ecf4;
  word-break: break-all;
}

.kv-val {
  flex: 1;
  padding: 7px 12px;
  font-size: 12px;
  color: #1a1a2e;
  font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
  word-break: break-all;
}

.kv-empty {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 16px;
  font-size: 13px;
  color: #b0b8d8;
}
</style>
