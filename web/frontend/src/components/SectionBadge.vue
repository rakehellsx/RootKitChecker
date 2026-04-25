<template>
  <div class="section-badge" :class="danger && count > 0 ? 'badge-danger' : 'badge-ok'">
    <span v-if="count > 0">
      共发现 <strong>{{ count }}</strong> 条{{ danger ? '（需关注）' : '' }}
    </span>
    <span v-else>未发现异常</span>
  </div>
</template>

<script setup lang="ts">
defineProps<{ count: number; danger?: boolean }>()
</script>

<style scoped>
.section-badge {
  padding: 6px 12px;
  border-radius: 4px;
  font-size: 13px;
  margin-bottom: 10px;
}
.badge-danger { background: rgba(245, 108, 108, 0.12); color: #f56c6c; border: 1px solid rgba(245,108,108,0.3); }
.badge-ok     { background: rgba(103, 194, 58, 0.10);  color: #67c23a; border: 1px solid rgba(103,194,58,0.3); }
</style>
