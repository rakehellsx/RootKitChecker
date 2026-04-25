<template>
  <div class="linux-result">
    <el-tabs v-model="activeTab" class="result-tabs">

      <!-- ── 检测摘要 ── -->
      <el-tab-pane name="overview">
        <template #label>
          <span class="tab-label"><el-icon><DataBoard /></el-icon>检测摘要</span>
        </template>
        <div class="section-grid">
          <DetectCard title="隐藏进程" icon-type="danger"
            :count="(data.hidden_processes_linux||[]).length"
            :items="(data.hidden_processes_linux||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
            empty-text="未发现隐藏进程" />
          <DetectCard title="系统调用钩子" icon-type="danger"
            :count="(data.syscall_hooks||[]).length"
            :items="(data.syscall_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
            empty-text="未发现系统调用钩子" />
          <DetectCard title="IDT 钩子" icon-type="danger"
            :count="(data.idt_hooks||[]).length"
            :items="(data.idt_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
            empty-text="未发现 IDT 钩子" />
          <DetectCard title="afinfo 篡改" icon-type="danger"
            :count="(data.afinfo_hooks||[]).length"
            :items="(data.afinfo_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
            empty-text="未发现 afinfo 篡改" />
          <DetectCard title="隐藏内核模块" icon-type="danger"
            :count="(data.hidden_modules_linux||[]).length"
            :items="(data.hidden_modules_linux||[]).map((m:any)=>m.name||m.base||'未知')"
            empty-text="未发现隐藏模块" />
          <DetectCard title="凭据异常" icon-type="warning"
            :count="(data.cred_anomalies||[]).length"
            :items="(data.cred_anomalies||[]).map((c:any)=>`PID ${c.pid} ${c.name||''} UID=${c.uid}`)"
            empty-text="未发现凭据异常" />
          <DetectCard title="Netfilter 钩子" icon-type="warning"
            :count="(data.netfilter_hooks||[]).length"
            :items="(data.netfilter_hooks||[]).map((h:any)=>h.module||h.handler||'未知')"
            empty-text="未发现 Netfilter 钩子" />
          <DetectCard title="TTY 钩子" icon-type="warning"
            :count="(data.tty_hooks||[]).length"
            :items="(data.tty_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
            empty-text="未发现 TTY 钩子" />
          <DetectCard title="键盘通知链钩子" icon-type="warning"
            :count="(data.keyboard_hooks||[]).length"
            :items="(data.keyboard_hooks||[]).map((h:any)=>h.symbol||h.address||'未知')"
            empty-text="未发现键盘钩子" />
        </div>
      </el-tab-pane>

      <!-- ── 进程列表 ── -->
      <el-tab-pane name="processes">
        <template #label>
          <span class="tab-label">
            <el-icon><List /></el-icon>进程列表
            <el-badge :value="(data.processes_linux||[]).length" class="tab-badge" />
          </span>
        </template>
        <div class="table-wrap">
          <el-table :data="data.processes_linux||[]" stripe size="small" height="100%" border>
            <el-table-column prop="pid"    label="PID"    width="80"  sortable />
            <el-table-column prop="ppid"   label="PPID"   width="80"  sortable />
            <el-table-column prop="name"   label="进程名" min-width="160" />
            <el-table-column prop="uid"    label="UID"    width="80" />
            <el-table-column prop="gid"    label="GID"    width="80" />
            <el-table-column prop="state"  label="状态"   width="80" />
            <el-table-column prop="start_time" label="启动时间" width="160" />
          </el-table>
        </div>
      </el-tab-pane>

      <!-- ── 网络连接 ── -->
      <el-tab-pane name="network">
        <template #label>
          <span class="tab-label">
            <el-icon><Connection /></el-icon>网络连接
            <el-badge :value="(data.network_connections_linux||[]).length" class="tab-badge" />
          </span>
        </template>
        <div class="table-wrap">
          <el-table :data="data.network_connections_linux||[]" stripe size="small" height="100%" border>
            <el-table-column prop="pid"         label="PID"    width="70" />
            <el-table-column prop="process"     label="进程"   width="120" />
            <el-table-column prop="proto"       label="协议"   width="70" />
            <el-table-column prop="local_addr"  label="本地地址" width="140" />
            <el-table-column prop="local_port"  label="本地端口" width="90" />
            <el-table-column prop="remote_addr" label="远端地址" width="140" />
            <el-table-column prop="remote_port" label="远端端口" width="90" />
            <el-table-column prop="state" label="状态" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="connTagType(row.state)" effect="light">{{ row.state || '-' }}</el-tag>
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
        <div class="kernel-sections" v-if="data.linux_kernel_data">

          <KernelSection title="VMCore 元数据" icon-color="#4361ee">
            <template #icon><el-icon><InfoFilled /></el-icon></template>
            <KVTable :rows="kd.vmcoreinfo||[]" />
          </KernelSection>

          <KernelSection title="系统启动时间" icon-color="#06d6a0">
            <template #icon><el-icon><Clock /></el-icon></template>
            <KVTable :rows="kd.boot_time ? [{key:'启动时间',value:kd.boot_time}] : []" />
          </KernelSection>

          <KernelSection title="已加载内核模块" icon-color="#4361ee" :count="(kd.loaded_modules||[]).length">
            <template #icon><el-icon><Grid /></el-icon></template>
            <el-table :data="kd.loaded_modules||[]" stripe size="small" border>
              <el-table-column prop="name" label="模块名" min-width="180" />
              <el-table-column prop="base" label="基址"   width="160" />
              <el-table-column prop="size" label="大小"   width="100" :formatter="sizeFmt" />
            </el-table>
          </KernelSection>

          <KernelSection title="内核线程" icon-color="#0078d4" :count="(kd.kernel_threads||[]).length">
            <template #icon><el-icon><List /></el-icon></template>
            <el-table :data="kd.kernel_threads||[]" stripe size="small" border>
              <el-table-column prop="pid"   label="PID"   width="80" />
              <el-table-column prop="name"  label="线程名" min-width="180" />
              <el-table-column prop="state" label="状态"   width="80" />
            </el-table>
          </KernelSection>

          <KernelSection title="eBPF 程序" icon-color="#7c3aed" :count="(kd.ebpf_programs||[]).length">
            <template #icon><el-icon><Operation /></el-icon></template>
            <el-table :data="kd.ebpf_programs||[]" stripe size="small" border>
              <el-table-column prop="id"        label="ID"    width="70" />
              <el-table-column prop="type"      label="类型"  min-width="140" />
              <el-table-column prop="name"      label="名称"  min-width="160" />
              <el-table-column prop="tag"       label="Tag"   min-width="160" />
              <el-table-column prop="load_time" label="加载时间" min-width="160" />
            </el-table>
          </KernelSection>

          <KernelSection title="Netfilter 钩子链" icon-color="#f77f00" :count="(kd.netfilter_hooks||[]).length">
            <template #icon><el-icon><Connection /></el-icon></template>
            <el-table :data="kd.netfilter_hooks||[]" stripe size="small" border>
              <el-table-column prop="proto"    label="协议"   width="80" />
              <el-table-column prop="table"    label="表"     width="100" />
              <el-table-column prop="chain"    label="链"     width="100" />
              <el-table-column prop="priority" label="优先级" width="80" />
              <el-table-column prop="handler"  label="处理函数" min-width="160" />
              <el-table-column prop="module"   label="模块"   min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="I/O 内存映射" icon-color="#06d6a0" :count="(kd.iomem||[]).length">
            <template #icon><el-icon><DataLine /></el-icon></template>
            <el-table :data="kd.iomem||[]" stripe size="small" border>
              <el-table-column prop="start" label="起始地址" width="160" />
              <el-table-column prop="end"   label="结束地址" width="160" />
              <el-table-column prop="name"  label="名称"    min-width="200" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="文件系统挂载信息" icon-color="#4361ee" :count="(kd.mount_info||[]).length">
            <template #icon><el-icon><FolderOpened /></el-icon></template>
            <el-table :data="kd.mount_info||[]" stripe size="small" border>
              <el-table-column prop="mount_id" label="ID"    width="60" />
              <el-table-column prop="source"   label="设备"  min-width="160" />
              <el-table-column prop="target"   label="挂载点" min-width="200" />
              <el-table-column prop="fstype"   label="文件系统" width="100" />
              <el-table-column prop="options"  label="选项"  min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="内核符号表" icon-color="#4361ee" :count="(kd.kallsyms||[]).length">
            <template #icon><el-icon><Document /></el-icon></template>
            <el-table :data="kd.kallsyms||[]" stripe size="small" border :max-height="300">
              <el-table-column prop="name"    label="符号名"  min-width="220" />
              <el-table-column prop="address" label="地址"   min-width="160" />
              <el-table-column prop="type"    label="类型"   width="60" />
            </el-table>
          </KernelSection>

          <KernelSection title="内核日志 (kmsg)" icon-color="#ef233c" :count="(kd.kernel_messages||[]).length">
            <template #icon><el-icon><ChatDotRound /></el-icon></template>
            <el-table :data="kd.kernel_messages||[]" stripe size="small" border :max-height="300">
              <el-table-column prop="timestamp" label="时间戳"   width="120" />
              <el-table-column prop="facility"  label="Facility" width="100" />
              <el-table-column prop="level"     label="级别"     width="80" />
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
  DataLine, InfoFilled, Clock, FolderOpened, Document, ChatDotRound
} from '@element-plus/icons-vue'
import DetectCard from './DetectCard.vue'
import KernelSection from './KernelSection.vue'
import KVTable from './KVTable.vue'

const props = defineProps<{ data: Record<string, any> }>()
const activeTab = ref('overview')
const kd = computed(() => props.data.linux_kernel_data || {})

const sizeFmt = (_: any, __: any, val: any) => {
  const n = Number(val)
  if (!val || isNaN(n)) return val || '-'
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1024 / 1024).toFixed(1) + ' MB'
}

const connTagType = (s: string) => {
  if (!s) return 'info'
  const u = s.toUpperCase()
  if (u === 'ESTABLISHED') return 'success'
  if (u === 'LISTEN') return 'primary'
  if (u.includes('WAIT') || u.includes('CLOSE')) return 'warning'
  return 'info'
}
</script>

<style scoped>
.linux-result { height: 100%; display: flex; flex-direction: column; }

.result-tabs { height: 100%; display: flex; flex-direction: column; }
.result-tabs :deep(.el-tabs__content) { flex: 1; overflow: hidden; }
.result-tabs :deep(.el-tab-pane) { height: 100%; overflow-y: auto; }
.result-tabs :deep(.el-tabs__header) {
  margin-bottom: 0;
  padding: 0 8px;
  background: #ffffff;
  border-bottom: 1px solid #e8ecf4;
}

.tab-label {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 13px;
}

.tab-badge :deep(.el-badge__content) {
  font-size: 10px;
  height: 16px;
  line-height: 16px;
  padding: 0 5px;
  border: none;
  margin-left: 4px;
}

.section-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 14px;
  padding: 16px;
}

.table-wrap {
  height: calc(100vh - 300px);
  padding: 12px;
}

.table-wrap :deep(.el-table) {
  border-radius: 8px;
  overflow: hidden;
}

.kernel-sections {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 16px;
}

.no-data {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  height: 200px;
  color: #b0b8d8;
  font-size: 14px;
}
</style>
