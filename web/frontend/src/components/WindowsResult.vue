<template>
  <div class="win-result">
    <el-tabs v-model="activeTab" class="result-tabs">

      <!-- ── 检测摘要 ── -->
      <el-tab-pane name="overview">
        <template #label>
          <span class="tab-label"><el-icon><DataBoard /></el-icon>检测摘要</span>
        </template>
        <div class="overview-wrap">
          <div class="detect-grid">
            <DetectCard
              title="隐藏进程" severity="critical"
              icon="hide"
              :count="(data.hidden_processes||[]).length"
              :items="(data.hidden_processes||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
              empty-text="未发现隐藏进程" />
            <DetectCard
              title="进程空洞化" severity="high"
              icon="warning"
              :count="(data.hollow_processes||[]).length"
              :items="(data.hollow_processes||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
              empty-text="未发现进程空洞化" />
            <DetectCard
              title="隐藏网络连接" severity="critical"
              icon="connection"
              :count="(data.hidden_connections||[]).length"
              :items="(data.hidden_connections||[]).map((c:any)=>`${c.local_addr||'?'}:${c.local_port||'?'} → ${c.remote_addr||'?'}:${c.remote_port||'?'}`)"
              empty-text="未发现隐藏连接" />
            <DetectCard
              title="SSDT 钩子" severity="critical"
              icon="hook"
              :count="(data.ssdt_hooks||[]).length"
              :items="(data.ssdt_hooks||[]).map((h:any)=>h.symbol||h.handler||'未知')"
              empty-text="未发现 SSDT 钩子" />
            <DetectCard
              title="隐藏内核模块" severity="critical"
              icon="module"
              :count="(data.hidden_modules||[]).length"
              :items="(data.hidden_modules||[]).map((m:any)=>m.name||m.base||'未知')"
              empty-text="未发现隐藏模块" />
            <DetectCard
              title="驱动 IRP 钩子" severity="high"
              icon="irp"
              :count="(kd.driver_irps||[]).filter((x:any)=>x.hooked).length"
              :items="(kd.driver_irps||[]).filter((x:any)=>x.hooked).map((x:any)=>`${x.driver_name} / ${x.irp_name}`)"
              empty-text="未发现 IRP 钩子" />
          </div>
        </div>
      </el-tab-pane>

      <!-- ── 进程列表 ── -->
      <el-tab-pane name="processes">
        <template #label>
          <span class="tab-label">
            <el-icon><List /></el-icon>进程列表
            <span class="tab-count">{{ (data.processes||[]).length }}</span>
          </span>
        </template>
        <div class="table-pane">
          <div class="table-toolbar">
            <el-input v-model="procSearch" placeholder="搜索进程名 / PID…" clearable size="small" class="search-input">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
          </div>
          <el-table :data="filteredProcs" stripe size="small" class="data-table" border
            :header-cell-style="headerStyle" :row-class-name="procRowClass">
            <el-table-column prop="pid"    label="PID"    width="72"  sortable />
            <el-table-column prop="ppid"   label="PPID"   width="72"  sortable />
            <el-table-column prop="name"   label="进程名" min-width="160" show-overflow-tooltip />
            <el-table-column prop="offset" label="EPROCESS" width="155" />
            <el-table-column prop="threads" label="线程" width="68" sortable />
            <el-table-column prop="create_time" label="创建时间" width="155" show-overflow-tooltip />
            <el-table-column label="状态" width="80" align="center">
              <template #default="{ row }">
                <span class="status-dot" :class="row.active !== false ? 'dot-green' : 'dot-gray'"></span>
                <span class="status-text">{{ row.active !== false ? '活跃' : '已退出' }}</span>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- ── 不活跃进程 ── -->
      <el-tab-pane name="inactive">
        <template #label>
          <span class="tab-label">
            <el-icon><Hide /></el-icon>不活跃进程
            <span v-if="(data.inactive_processes||[]).length" class="tab-count warn">
              {{ (data.inactive_processes||[]).length }}
            </span>
          </span>
        </template>
        <div class="table-pane">
          <div class="pane-tip warn-tip">
            <el-icon><Warning /></el-icon>
            以下进程已终止但仍残留于内存，可能由 Rootkit 注入或异常崩溃导致
          </div>
          <el-table :data="data.inactive_processes||[]" stripe size="small" class="data-table" border
            :header-cell-style="headerStyle">
            <el-table-column prop="pid"       label="PID"    width="80" />
            <el-table-column prop="name"      label="进程名"  min-width="160" show-overflow-tooltip />
            <el-table-column prop="offset"    label="EPROCESS" width="155" />
            <el-table-column prop="exit_time" label="退出时间" width="155" />
          </el-table>
        </div>
      </el-tab-pane>

      <!-- ── 网络连接 ── -->
      <el-tab-pane name="network">
        <template #label>
          <span class="tab-label">
            <el-icon><Connection /></el-icon>网络连接
            <span class="tab-count">{{ (data.network_connections||[]).length }}</span>
          </span>
        </template>
        <div class="table-pane">
          <div class="table-toolbar">
            <el-input v-model="netSearch" placeholder="搜索地址 / 进程…" clearable size="small" class="search-input">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
          </div>
          <el-table :data="filteredNet" stripe size="small" class="data-table" border
            :header-cell-style="headerStyle">
            <el-table-column prop="pid"         label="PID"    width="70" />
            <el-table-column prop="process"     label="进程"   width="130" show-overflow-tooltip />
            <el-table-column prop="proto"       label="协议"   width="70" align="center">
              <template #default="{ row }">
                <span class="proto-tag">{{ row.proto || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="本地" min-width="160">
              <template #default="{ row }">
                <span class="addr-text">{{ row.local_addr || '-' }}</span>
                <span class="port-text" v-if="row.local_port">:{{ row.local_port }}</span>
              </template>
            </el-table-column>
            <el-table-column label="远端" min-width="160">
              <template #default="{ row }">
                <span class="addr-text">{{ row.remote_addr || '-' }}</span>
                <span class="port-text" v-if="row.remote_port">:{{ row.remote_port }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="state" label="状态" width="130" align="center">
              <template #default="{ row }">
                <span class="conn-state" :class="connStateClass(row.state)">{{ row.state || '-' }}</span>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- ── 内核数据 ── -->
      <el-tab-pane name="kernel">
        <template #label>
          <span class="tab-label"><el-icon><Cpu /></el-icon>内核数据</span>
        </template>
        <div class="kernel-pane" v-if="data.windows_kernel_data">

          <KernelSection title="系统信息" icon-color="#4361ee" :default-open="true">
            <template #icon><el-icon><InfoFilled /></el-icon></template>
            <KVTable :rows="kd.os_info||[]" />
          </KernelSection>

          <KernelSection title="内存统计" icon-color="#06d6a0">
            <template #icon><el-icon><DataAnalysis /></el-icon></template>
            <KVTable :rows="kd.statistics||[]" />
          </KernelSection>

          <KernelSection title="已加载驱动" icon-color="#4361ee" :count="(kd.loaded_modules||[]).length">
            <template #icon><el-icon><Grid /></el-icon></template>
            <el-table :data="kd.loaded_modules||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="name" label="模块名" min-width="160" show-overflow-tooltip />
              <el-table-column prop="base" label="基址"   width="155" />
              <el-table-column prop="size" label="大小"   width="90" :formatter="sizeFmt" />
              <el-table-column prop="path" label="路径"   min-width="200" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="驱动 IRP 分发例程" icon-color="#f77f00"
            :count="(kd.driver_irps||[]).filter((x:any)=>x.hooked).length" count-label="已钩挂">
            <template #icon><el-icon><Operation /></el-icon></template>
            <el-table :data="kd.driver_irps||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle"
              :row-class-name="({row}:any) => row.hooked ? 'row-danger' : ''">
              <el-table-column prop="driver_name"    label="驱动"    width="160" show-overflow-tooltip />
              <el-table-column prop="irp_name"       label="IRP"     width="200" />
              <el-table-column prop="handler_addr"   label="处理函数" width="155" />
              <el-table-column prop="handler_module" label="所属模块" min-width="160" show-overflow-tooltip />
              <el-table-column label="状态" width="90" align="center">
                <template #default="{ row }">
                  <span class="status-badge" :class="row.hooked ? 'badge-danger' : 'badge-safe'">
                    {{ row.hooked ? 'HOOKED' : '正常' }}
                  </span>
                </template>
              </el-table-column>
            </el-table>
          </KernelSection>

          <KernelSection title="已卸载模块" icon-color="#ef233c" :count="(kd.unloaded_modules||[]).length">
            <template #icon><el-icon><DocumentDelete /></el-icon></template>
            <el-table :data="kd.unloaded_modules||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="name"        label="模块名"  min-width="160" />
              <el-table-column prop="start_addr"  label="起始地址" width="155" />
              <el-table-column prop="end_addr"    label="结束地址" width="155" />
              <el-table-column prop="unload_time" label="卸载时间" width="155" />
            </el-table>
          </KernelSection>

          <KernelSection title="内核回调例程" icon-color="#7c3aed" :count="(kd.callbacks||[]).length">
            <template #icon><el-icon><Bell /></el-icon></template>
            <el-table :data="kd.callbacks||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="callback_type" label="回调类型" width="240" />
              <el-table-column prop="callback_addr" label="地址"     width="155" />
              <el-table-column prop="module"        label="模块"     min-width="160" show-overflow-tooltip />
              <el-table-column prop="symbol"        label="符号"     min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="内核定时器" icon-color="#0078d4" :count="(kd.timers||[]).length">
            <template #icon><el-icon><Timer /></el-icon></template>
            <el-table :data="kd.timers||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="offset"          label="偏移量"   width="155" />
              <el-table-column prop="period"          label="周期(ms)" width="100" />
              <el-table-column prop="routine_addr"    label="例程地址" width="155" />
              <el-table-column prop="routine_module"  label="所属模块" min-width="160" show-overflow-tooltip />
              <el-table-column prop="routine_symbol"  label="符号"     min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="大页池分配" icon-color="#f77f00" :count="(kd.big_pools||[]).length">
            <template #icon><el-icon><DataLine /></el-icon></template>
            <el-table :data="kd.big_pools||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle"
              :row-class-name="({row}:any) => row.suspicious ? 'row-warn' : ''">
              <el-table-column prop="offset"    label="偏移量" width="155" />
              <el-table-column prop="pool_tag"  label="Tag"    width="80" />
              <el-table-column prop="pool_type" label="类型"   width="120" />
              <el-table-column prop="size"      label="大小"   width="90" :formatter="sizeFmt" />
              <el-table-column label="可疑" width="70" align="center">
                <template #default="{ row }">
                  <span v-if="row.suspicious" class="status-badge badge-warn">可疑</span>
                  <span v-else class="muted">—</span>
                </template>
              </el-table-column>
            </el-table>
          </KernelSection>

          <KernelSection title="虚拟内存映射" icon-color="#4361ee" :count="(kd.virtual_map||[]).length">
            <template #icon><el-icon><DataBoard /></el-icon></template>
            <el-table :data="kd.virtual_map||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="start"  label="起始地址" width="155" />
              <el-table-column prop="end"    label="结束地址" width="155" />
              <el-table-column prop="size"   label="大小"     width="90" :formatter="sizeFmt" />
              <el-table-column prop="region" label="区域描述" min-width="200" show-overflow-tooltip />
            </el-table>
          </KernelSection>

        </div>
        <div v-else class="no-data"><el-icon><InfoFilled /></el-icon>暂无内核数据</div>
      </el-tab-pane>

    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import {
  DataBoard, List, Connection, Cpu, Hide, Grid,
  Bell, Timer, Operation, DataAnalysis, DataLine,
  InfoFilled, DocumentDelete, Warning, Search
} from '@element-plus/icons-vue'
import DetectCard from './DetectCard.vue'
import KernelSection from './KernelSection.vue'
import KVTable from './KVTable.vue'

const props = defineProps<{ data: Record<string, any> }>()
const activeTab = ref('overview')
const kd = computed(() => props.data.windows_kernel_data || {})

const procSearch = ref('')
const netSearch  = ref('')

const filteredProcs = computed(() => {
  const q = procSearch.value.toLowerCase()
  if (!q) return props.data.processes || []
  return (props.data.processes || []).filter((p: any) =>
    String(p.pid).includes(q) || (p.name || '').toLowerCase().includes(q)
  )
})

const filteredNet = computed(() => {
  const q = netSearch.value.toLowerCase()
  if (!q) return props.data.network_connections || []
  return (props.data.network_connections || []).filter((c: any) =>
    (c.local_addr || '').includes(q) || (c.remote_addr || '').includes(q) ||
    (c.process || '').toLowerCase().includes(q)
  )
})

const headerStyle = () => ({
  background: '#f5f7fa',
  color: '#4b5563',
  fontWeight: '600',
  fontSize: '12px',
  padding: '8px 0',
})

const procRowClass = ({ row }: any) => {
  if (row.active === false) return 'row-inactive'
  return ''
}

const sizeFmt = (_: any, __: any, val: any) => {
  const n = Number(val)
  if (!val || isNaN(n)) return val || '-'
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1024 / 1024).toFixed(1) + ' MB'
}

const connStateClass = (s: string) => {
  if (!s) return 'state-default'
  const u = s.toUpperCase()
  if (u === 'ESTABLISHED') return 'state-established'
  if (u === 'LISTEN')      return 'state-listen'
  if (u.includes('WAIT') || u.includes('CLOSE')) return 'state-wait'
  return 'state-default'
}
</script>

<style scoped>
.win-result { height: 100%; display: flex; flex-direction: column; overflow: hidden; }

/* ── 标签页 ── */
.result-tabs { height: 100%; display: flex; flex-direction: column; }
.result-tabs :deep(.el-tabs__header) {
  margin: 0;
  padding: 0 16px;
  background: #ffffff;
  border-bottom: 2px solid #eef0f8;
  flex-shrink: 0;
}
.result-tabs :deep(.el-tabs__nav-wrap::after) { display: none; }
.result-tabs :deep(.el-tabs__item) {
  height: 42px;
  font-size: 12.5px;
  color: #6b7280;
  padding: 0 14px;
  transition: color 0.15s;
}
.result-tabs :deep(.el-tabs__item.is-active) { color: #4361ee; font-weight: 700; }
.result-tabs :deep(.el-tabs__item:hover) { color: #4361ee; }
.result-tabs :deep(.el-tabs__active-bar) { background: #4361ee; height: 2.5px; border-radius: 2px; }
.result-tabs :deep(.el-tabs__content) { flex: 1; overflow: hidden; }
.result-tabs :deep(.el-tab-pane) { height: 100%; overflow-y: auto; }
.result-tabs :deep(.el-tab-pane)::-webkit-scrollbar { width: 5px; }
.result-tabs :deep(.el-tab-pane)::-webkit-scrollbar-thumb { background: #dde1f0; border-radius: 4px; }

.tab-label { display: flex; align-items: center; gap: 5px; }
.tab-count {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 18px; height: 17px; padding: 0 5px;
  background: #eef2ff; color: #4361ee;
  border-radius: 9px; font-size: 10px; font-weight: 700;
}
.tab-count.warn { background: #fef3c7; color: #d97706; }

/* ── 检测摘要 ── */
.overview-wrap { padding: 14px 16px; }
.detect-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(270px, 1fr));
  gap: 12px;
}

/* ── 表格面板 ── */
.table-pane {
  display: flex;
  flex-direction: column;
  height: 100%;
  padding: 12px 16px;
  gap: 10px;
}
.table-toolbar { display: flex; gap: 10px; align-items: center; flex-shrink: 0; }
.search-input { width: 260px; }
.search-input :deep(.el-input__wrapper) {
  border-radius: 8px !important;
  background: #f5f7fa;
  box-shadow: none !important;
  border: 1.5px solid transparent;
  transition: all 0.2s;
}
.search-input :deep(.el-input__wrapper:hover),
.search-input :deep(.el-input__wrapper.is-focus) {
  border-color: #4361ee !important;
  background: #fff;
  box-shadow: 0 0 0 3px rgba(67,97,238,0.08) !important;
}

.pane-tip {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 14px; border-radius: 8px;
  font-size: 12px; flex-shrink: 0;
}
.warn-tip { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }

.data-table { border-radius: 9px; overflow: hidden; flex: 1; }
.data-table :deep(.el-table__header th) {
  background: #f5f7fa !important;
  color: #4b5563 !important;
  font-weight: 700 !important;
  font-size: 11.5px !important;
  padding: 9px 0 !important;
  border-bottom: 2px solid #eaecf4 !important;
}
.data-table :deep(.el-table__row > td) {
  font-size: 12px;
  color: #374151;
  padding: 7px 0;
}
.data-table :deep(.el-table__row:hover > td) { background: #f0f4ff !important; }
:deep(.row-danger > td) { background: #fff5f5 !important; }
:deep(.row-warn > td)   { background: #fffbf0 !important; }
:deep(.row-inactive > td) { opacity: 0.6; }

/* 状态点 */
.status-dot {
  display: inline-block; width: 7px; height: 7px;
  border-radius: 50%; margin-right: 5px;
  vertical-align: middle;
}
.dot-green { background: #22c55e; box-shadow: 0 0 0 2px #dcfce7; }
.dot-gray  { background: #9ca3af; }
.status-text { font-size: 11.5px; vertical-align: middle; }

/* 协议标签 */
.proto-tag {
  display: inline-block; padding: 1px 7px;
  background: #eef2ff; color: #4361ee;
  border-radius: 4px; font-size: 10.5px; font-weight: 700;
  letter-spacing: 0.3px;
}

/* 地址文本 */
.addr-text { font-family: monospace; font-size: 11.5px; color: #374151; }
.port-text { font-family: monospace; font-size: 11.5px; color: #6366f1; font-weight: 700; }

/* 连接状态 */
.conn-state {
  display: inline-block; padding: 2px 8px;
  border-radius: 4px; font-size: 10.5px; font-weight: 700;
}
.state-established { background: #dcfce7; color: #15803d; }
.state-listen      { background: #dbeafe; color: #1d4ed8; }
.state-wait        { background: #fef3c7; color: #b45309; }
.state-default     { background: #f3f4f6; color: #6b7280; }

/* 状态徽章 */
.status-badge {
  display: inline-block; padding: 2px 8px;
  border-radius: 4px; font-size: 10.5px; font-weight: 700;
}
.badge-danger { background: #fee2e2; color: #dc2626; }
.badge-safe   { background: #dcfce7; color: #16a34a; }
.badge-warn   { background: #fef3c7; color: #d97706; }

/* ── 内核数据 ── */
.kernel-pane {
  display: flex; flex-direction: column;
  gap: 10px; padding: 14px 16px;
}
.inner-table { border-radius: 8px; overflow: hidden; }
.inner-table :deep(.el-table__header th) {
  background: #f5f7fa !important;
  color: #4b5563 !important;
  font-weight: 700 !important;
  font-size: 11.5px !important;
  padding: 8px 0 !important;
}
.inner-table :deep(.el-table__row > td) {
  font-size: 11.5px;
  color: #374151;
  padding: 6px 0;
}
.inner-table :deep(.el-table__row:hover > td) { background: #f0f4ff !important; }

.no-data {
  display: flex; align-items: center; justify-content: center;
  gap: 8px; height: 200px; color: #b0b8d8; font-size: 14px;
}
.muted { color: #d1d5db; }
</style>
