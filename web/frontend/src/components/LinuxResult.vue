<template>
  <div class="linux-result">
    <el-tabs v-model="activeTab" class="result-tabs">

      <!-- ── 检测摘要 ── -->
      <el-tab-pane name="overview">
        <template #label>
          <span class="tab-label"><el-icon><DataBoard /></el-icon>检测摘要</span>
        </template>
        <div class="overview-wrap">
          <div class="detect-grid">
            <DetectCard title="隐藏进程" severity="critical" icon="hide"
              :count="(data.hidden_processes_linux||[]).length"
              :items="(data.hidden_processes_linux||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
              empty-text="未发现隐藏进程" />
            <DetectCard title="系统调用钩子" severity="critical" icon="hook"
              :count="(data.syscall_hooks||[]).length"
              :items="(data.syscall_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
              empty-text="未发现系统调用钩子" />
            <DetectCard title="IDT 钩子" severity="critical" icon="hook"
              :count="(data.idt_hooks||[]).length"
              :items="(data.idt_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
              empty-text="未发现 IDT 钩子" />
            <DetectCard title="afinfo 篡改" severity="critical" icon="warning"
              :count="(data.afinfo_hooks||[]).length"
              :items="(data.afinfo_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
              empty-text="未发现 afinfo 篡改" />
            <DetectCard title="隐藏内核模块" severity="critical" icon="module"
              :count="(data.hidden_modules_linux||[]).length"
              :items="(data.hidden_modules_linux||[]).map((m:any)=>m.name||m.base||'未知')"
              empty-text="未发现隐藏模块" />
            <DetectCard title="凭据异常" severity="high" icon="warning"
              :count="(data.cred_anomalies||[]).length"
              :items="(data.cred_anomalies||[]).map((c:any)=>`PID ${c.pid} ${c.name||''} UID=${c.uid}`)"
              empty-text="未发现凭据异常" />
            <DetectCard title="Netfilter 钩子" severity="medium" icon="connection"
              :count="(data.netfilter_hooks||[]).length"
              :items="(data.netfilter_hooks||[]).map((h:any)=>h.module||h.handler||'未知')"
              empty-text="未发现 Netfilter 钩子" />
            <DetectCard title="TTY 钩子" severity="medium" icon="hook"
              :count="(data.tty_hooks||[]).length"
              :items="(data.tty_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
              empty-text="未发现 TTY 钩子" />
            <DetectCard title="键盘通知链钩子" severity="high" icon="keyboard"
              :count="(data.keyboard_hooks||[]).length"
              :items="(data.keyboard_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
              empty-text="未发现键盘钩子" />
          </div>
        </div>
      </el-tab-pane>

      <!-- ── 进程列表 ── -->
      <el-tab-pane name="processes">
        <template #label>
          <span class="tab-label">
            <el-icon><List /></el-icon>进程列表
            <span class="tab-count">{{ (data.processes_linux||[]).length }}</span>
          </span>
        </template>
        <div class="table-pane">
          <div class="table-toolbar">
            <el-input v-model="procSearch" placeholder="搜索进程名 / PID…" clearable size="small" class="search-input">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
          </div>
          <el-table :data="filteredProcs" stripe size="small" class="data-table" border
            :header-cell-style="headerStyle">
            <el-table-column prop="pid"    label="PID"    width="72"  sortable />
            <el-table-column prop="ppid"   label="PPID"   width="72"  sortable />
            <el-table-column prop="name"   label="进程名" min-width="160" show-overflow-tooltip />
            <el-table-column prop="uid"    label="UID"    width="72" />
            <el-table-column prop="gid"    label="GID"    width="72" />
            <el-table-column prop="state"  label="状态"   width="80" align="center">
              <template #default="{ row }">
                <span class="proc-state" :class="procStateClass(row.state)">{{ row.state || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="start_time" label="启动时间" width="155" show-overflow-tooltip />
          </el-table>
        </div>
      </el-tab-pane>

      <!-- ── 网络连接 ── -->
      <el-tab-pane name="network">
        <template #label>
          <span class="tab-label">
            <el-icon><Connection /></el-icon>网络连接
            <span class="tab-count">{{ (data.network_connections_linux||[]).length }}</span>
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
        <div class="kernel-pane" v-if="data.linux_kernel_data">

          <KernelSection title="VMCore 元数据" icon-color="#4361ee" :default-open="true">
            <template #icon><el-icon><InfoFilled /></el-icon></template>
            <KVTable :rows="kd.vmcoreinfo||[]" />
          </KernelSection>

          <KernelSection title="系统启动时间" icon-color="#06d6a0">
            <template #icon><el-icon><Clock /></el-icon></template>
            <KVTable :rows="kd.boot_time ? [{key:'启动时间',value:kd.boot_time}] : []" />
          </KernelSection>

          <KernelSection title="已加载内核模块" icon-color="#4361ee" :count="(kd.loaded_modules||[]).length">
            <template #icon><el-icon><Grid /></el-icon></template>
            <el-table :data="kd.loaded_modules||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="name" label="模块名" min-width="180" show-overflow-tooltip />
              <el-table-column prop="base" label="基址"   width="155" />
              <el-table-column prop="size" label="大小"   width="90" :formatter="sizeFmt" />
            </el-table>
          </KernelSection>

          <KernelSection title="内核线程" icon-color="#0078d4" :count="(kd.kernel_threads||[]).length">
            <template #icon><el-icon><List /></el-icon></template>
            <el-table :data="kd.kernel_threads||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="pid"   label="PID"   width="80" />
              <el-table-column prop="name"  label="线程名" min-width="180" show-overflow-tooltip />
              <el-table-column prop="state" label="状态"   width="80" align="center">
                <template #default="{ row }">
                  <span class="proc-state" :class="procStateClass(row.state)">{{ row.state || '-' }}</span>
                </template>
              </el-table-column>
            </el-table>
          </KernelSection>

          <KernelSection title="eBPF 程序" icon-color="#7c3aed" :count="(kd.ebpf_programs||[]).length">
            <template #icon><el-icon><Operation /></el-icon></template>
            <el-table :data="kd.ebpf_programs||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="id"        label="ID"    width="70" />
              <el-table-column prop="type"      label="类型"  min-width="140" />
              <el-table-column prop="name"      label="名称"  min-width="160" show-overflow-tooltip />
              <el-table-column prop="tag"       label="Tag"   min-width="160" />
              <el-table-column prop="load_time" label="加载时间" min-width="155" />
            </el-table>
          </KernelSection>

          <KernelSection title="Netfilter 钩子链" icon-color="#f77f00" :count="(kd.netfilter_hooks||[]).length">
            <template #icon><el-icon><Connection /></el-icon></template>
            <el-table :data="kd.netfilter_hooks||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="proto"    label="协议"   width="80" />
              <el-table-column prop="table"    label="表"     width="100" />
              <el-table-column prop="chain"    label="链"     width="100" />
              <el-table-column prop="priority" label="优先级" width="80" />
              <el-table-column prop="handler"  label="处理函数" min-width="160" show-overflow-tooltip />
              <el-table-column prop="module"   label="模块"   min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="I/O 内存映射" icon-color="#06d6a0" :count="(kd.iomem||[]).length">
            <template #icon><el-icon><DataLine /></el-icon></template>
            <el-table :data="kd.iomem||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="start" label="起始地址" width="155" />
              <el-table-column prop="end"   label="结束地址" width="155" />
              <el-table-column prop="name"  label="名称"    min-width="200" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="文件系统挂载信息" icon-color="#4361ee" :count="(kd.mount_info||[]).length">
            <template #icon><el-icon><FolderOpened /></el-icon></template>
            <el-table :data="kd.mount_info||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="mount_id" label="ID"    width="60" />
              <el-table-column prop="source"   label="设备"  min-width="160" show-overflow-tooltip />
              <el-table-column prop="target"   label="挂载点" min-width="200" show-overflow-tooltip />
              <el-table-column prop="fstype"   label="文件系统" width="100" />
              <el-table-column prop="options"  label="选项"  min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="内核符号表" icon-color="#4361ee" :count="(kd.kallsyms||[]).length">
            <template #icon><el-icon><Document /></el-icon></template>
            <el-table :data="kd.kallsyms||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle" :max-height="300">
              <el-table-column prop="name"    label="符号名"  min-width="220" show-overflow-tooltip />
              <el-table-column prop="address" label="地址"   min-width="155" />
              <el-table-column prop="type"    label="类型"   width="60" align="center" />
            </el-table>
          </KernelSection>

          <KernelSection title="内核日志 (kmsg)" icon-color="#ef233c" :count="(kd.kernel_messages||[]).length">
            <template #icon><el-icon><ChatDotRound /></el-icon></template>
            <el-table :data="kd.kernel_messages||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle" :max-height="300">
              <el-table-column prop="timestamp" label="时间戳"   width="120" />
              <el-table-column prop="facility"  label="Facility" width="100" />
              <el-table-column prop="level"     label="级别"     width="80" align="center">
                <template #default="{ row }">
                  <span class="log-level" :class="logLevelClass(row.level)">{{ row.level || '-' }}</span>
                </template>
              </el-table-column>
              <el-table-column prop="message"   label="消息"     min-width="400" show-overflow-tooltip />
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
  DataBoard, List, Connection, Cpu, Grid, Operation,
  DataLine, InfoFilled, Clock, FolderOpened, Document, ChatDotRound, Search
} from '@element-plus/icons-vue'
import DetectCard from './DetectCard.vue'
import KernelSection from './KernelSection.vue'
import KVTable from './KVTable.vue'

const props = defineProps<{ data: Record<string, any> }>()
const activeTab = ref('overview')
const kd = computed(() => props.data.linux_kernel_data || {})

const procSearch = ref('')
const netSearch  = ref('')

const filteredProcs = computed(() => {
  const q = procSearch.value.toLowerCase()
  if (!q) return props.data.processes_linux || []
  return (props.data.processes_linux || []).filter((p: any) =>
    String(p.pid).includes(q) || (p.name || '').toLowerCase().includes(q)
  )
})

const filteredNet = computed(() => {
  const q = netSearch.value.toLowerCase()
  if (!q) return props.data.network_connections_linux || []
  return (props.data.network_connections_linux || []).filter((c: any) =>
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

const procStateClass = (s: string) => {
  if (!s) return ''
  const u = s.toUpperCase()
  if (u === 'R' || u === 'RUNNING') return 'pstate-run'
  if (u === 'S' || u === 'SLEEPING') return 'pstate-sleep'
  if (u === 'Z' || u === 'ZOMBIE') return 'pstate-zombie'
  return ''
}

const logLevelClass = (l: string) => {
  if (!l) return ''
  const u = l.toUpperCase()
  if (u.includes('ERR') || u.includes('CRIT') || u.includes('EMERG')) return 'level-err'
  if (u.includes('WARN')) return 'level-warn'
  if (u.includes('INFO') || u.includes('NOTICE')) return 'level-info'
  return ''
}
</script>

<style scoped>
.linux-result { height: 100%; display: flex; flex-direction: column; overflow: hidden; }

/* ── 标签页 ── */
.result-tabs { height: 100%; display: flex; flex-direction: column; }
.result-tabs :deep(.el-tabs__header) {
  margin: 0; padding: 0 16px;
  background: #ffffff;
  border-bottom: 2px solid #eef0f8;
  flex-shrink: 0;
}
.result-tabs :deep(.el-tabs__nav-wrap::after) { display: none; }
.result-tabs :deep(.el-tabs__item) {
  height: 42px; font-size: 12.5px; color: #6b7280; padding: 0 14px;
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

/* ── 检测摘要 ── */
.overview-wrap { padding: 14px 16px; }
.detect-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(270px, 1fr));
  gap: 12px;
}

/* ── 表格面板 ── */
.table-pane {
  display: flex; flex-direction: column;
  height: 100%; padding: 12px 16px; gap: 10px;
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
  font-size: 12px; color: #374151; padding: 7px 0;
}
.data-table :deep(.el-table__row:hover > td) { background: #f0f4ff !important; }

/* 进程状态 */
.proc-state {
  display: inline-block; padding: 1px 7px;
  border-radius: 4px; font-size: 10.5px; font-weight: 700;
  background: #f3f4f6; color: #6b7280;
}
.pstate-run    { background: #dcfce7; color: #15803d; }
.pstate-sleep  { background: #eef2ff; color: #4361ee; }
.pstate-zombie { background: #fee2e2; color: #dc2626; }

/* 协议标签 */
.proto-tag {
  display: inline-block; padding: 1px 7px;
  background: #f0fdf4; color: #15803d;
  border-radius: 4px; font-size: 10.5px; font-weight: 700;
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

/* 日志级别 */
.log-level {
  display: inline-block; padding: 1px 6px;
  border-radius: 4px; font-size: 10.5px; font-weight: 700;
  background: #f3f4f6; color: #6b7280;
}
.level-err  { background: #fee2e2; color: #dc2626; }
.level-warn { background: #fef3c7; color: #d97706; }
.level-info { background: #dbeafe; color: #1d4ed8; }

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
  font-size: 11.5px; color: #374151; padding: 6px 0;
}
.inner-table :deep(.el-table__row:hover > td) { background: #f0f4ff !important; }

.no-data {
  display: flex; align-items: center; justify-content: center;
  gap: 8px; height: 200px; color: #b0b8d8; font-size: 14px;
}
</style>
