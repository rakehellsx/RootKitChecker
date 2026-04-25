<template>
  <div class="win-result">
    <el-tabs v-model="activeTab" class="result-tabs">

      <!-- ── 检测摘要 ── -->
      <el-tab-pane name="overview">
        <template #label>
          <span class="tab-label"><el-icon><DataBoard /></el-icon>检测摘要</span>
        </template>
        <div class="section-grid">
          <DetectCard title="隐藏进程" icon-type="danger"
            :count="(data.hidden_processes||[]).length"
            :items="(data.hidden_processes||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
            empty-text="未发现隐藏进程" />
          <DetectCard title="进程空洞化" icon-type="warning"
            :count="(data.hollow_processes||[]).length"
            :items="(data.hollow_processes||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
            empty-text="未发现进程空洞化" />
          <DetectCard title="隐藏网络连接" icon-type="danger"
            :count="(data.hidden_connections||[]).length"
            :items="(data.hidden_connections||[]).map((c:any)=>`${c.local_addr||'?'}:${c.local_port||'?'} → ${c.remote_addr||'?'}:${c.remote_port||'?'}`)"
            empty-text="未发现隐藏连接" />
          <DetectCard title="SSDT 钩子" icon-type="danger"
            :count="(data.ssdt_hooks||[]).length"
            :items="(data.ssdt_hooks||[]).map((h:any)=>h.symbol||h.handler||'未知')"
            empty-text="未发现 SSDT 钩子" />
          <DetectCard title="隐藏内核模块" icon-type="danger"
            :count="(data.hidden_modules||[]).length"
            :items="(data.hidden_modules||[]).map((m:any)=>m.name||m.base||'未知')"
            empty-text="未发现隐藏模块" />
          <DetectCard title="驱动 IRP 钩子" icon-type="warning"
            :count="(kd.driver_irps||[]).filter((x:any)=>x.hooked).length"
            :items="(kd.driver_irps||[]).filter((x:any)=>x.hooked).map((x:any)=>`${x.driver_name} / ${x.irp_name}`)"
            empty-text="未发现 IRP 钩子" />
        </div>
      </el-tab-pane>

      <!-- ── 进程列表 ── -->
      <el-tab-pane name="processes">
        <template #label>
          <span class="tab-label">
            <el-icon><List /></el-icon>进程列表
            <el-badge :value="(data.processes||[]).length" class="tab-badge" />
          </span>
        </template>
        <div class="table-wrap">
          <el-table :data="data.processes||[]" stripe size="small" height="100%" border>
            <el-table-column prop="pid"    label="PID"    width="80"  sortable />
            <el-table-column prop="ppid"   label="PPID"   width="80"  sortable />
            <el-table-column prop="name"   label="进程名" min-width="160" />
            <el-table-column prop="offset" label="偏移量" width="160" />
            <el-table-column prop="threads" label="线程数" width="80" sortable />
            <el-table-column prop="create_time" label="创建时间" width="160" />
            <el-table-column label="状态" width="90">
              <template #default="{ row }">
                <el-tag size="small" :type="row.active ? 'success' : 'info'" effect="light">
                  {{ row.active ? '活跃' : '已退出' }}
                </el-tag>
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
            <el-badge v-if="(data.inactive_processes||[]).length" :value="(data.inactive_processes||[]).length" type="warning" class="tab-badge" />
          </span>
        </template>
        <div class="table-wrap">
          <el-table :data="data.inactive_processes||[]" stripe size="small" height="100%" border>
            <el-table-column prop="pid"       label="PID"    width="80" />
            <el-table-column prop="name"      label="进程名"  min-width="160" />
            <el-table-column prop="offset"    label="偏移量"  width="160" />
            <el-table-column prop="exit_time" label="退出时间" width="160" />
          </el-table>
        </div>
      </el-tab-pane>

      <!-- ── 网络连接 ── -->
      <el-tab-pane name="network">
        <template #label>
          <span class="tab-label">
            <el-icon><Connection /></el-icon>网络连接
            <el-badge :value="(data.network_connections||[]).length" class="tab-badge" />
          </span>
        </template>
        <div class="table-wrap">
          <el-table :data="data.network_connections||[]" stripe size="small" height="100%" border>
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
        <div class="kernel-sections" v-if="data.windows_kernel_data">

          <KernelSection title="系统信息" icon-color="#4361ee">
            <template #icon><el-icon><InfoFilled /></el-icon></template>
            <KVTable :rows="kd.os_info||[]" />
          </KernelSection>

          <KernelSection title="内存统计" icon-color="#06d6a0">
            <template #icon><el-icon><DataAnalysis /></el-icon></template>
            <KVTable :rows="kd.statistics||[]" />
          </KernelSection>

          <KernelSection title="已加载驱动" icon-color="#4361ee" :count="(kd.loaded_modules||[]).length">
            <template #icon><el-icon><Grid /></el-icon></template>
            <el-table :data="kd.loaded_modules||[]" stripe size="small" border>
              <el-table-column prop="name" label="模块名" min-width="160" />
              <el-table-column prop="base" label="基址"   width="160" />
              <el-table-column prop="size" label="大小"   width="100" :formatter="sizeFmt" />
              <el-table-column prop="path" label="路径"   min-width="200" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="驱动 IRP 分发例程" icon-color="#f77f00"
            :count="(kd.driver_irps||[]).filter((x:any)=>x.hooked).length" count-label="已钩挂">
            <template #icon><el-icon><Operation /></el-icon></template>
            <el-table :data="kd.driver_irps||[]" stripe size="small" border
              :row-class-name="({row}:any) => row.hooked ? 'row-danger' : ''">
              <el-table-column prop="driver_name"    label="驱动"    width="160" show-overflow-tooltip />
              <el-table-column prop="irp_name"       label="IRP"     width="200" />
              <el-table-column prop="handler_addr"   label="处理函数" width="160" />
              <el-table-column prop="handler_module" label="所属模块" min-width="160" show-overflow-tooltip />
              <el-table-column label="状态" width="90">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.hooked ? 'danger' : 'success'" effect="light">
                    {{ row.hooked ? 'HOOKED' : '正常' }}
                  </el-tag>
                </template>
              </el-table-column>
            </el-table>
          </KernelSection>

          <KernelSection title="未加载模块" icon-color="#ef233c" :count="(kd.unloaded_modules||[]).length">
            <template #icon><el-icon><DocumentDelete /></el-icon></template>
            <el-table :data="kd.unloaded_modules||[]" stripe size="small" border>
              <el-table-column prop="name"        label="模块名"  min-width="160" />
              <el-table-column prop="start_addr"  label="起始地址" width="160" />
              <el-table-column prop="end_addr"    label="结束地址" width="160" />
              <el-table-column prop="unload_time" label="卸载时间" width="160" />
            </el-table>
          </KernelSection>

          <KernelSection title="内核回调例程" icon-color="#7c3aed" :count="(kd.callbacks||[]).length">
            <template #icon><el-icon><Bell /></el-icon></template>
            <el-table :data="kd.callbacks||[]" stripe size="small" border>
              <el-table-column prop="callback_type" label="回调类型" width="240" />
              <el-table-column prop="callback_addr" label="地址"     width="160" />
              <el-table-column prop="module"        label="模块"     min-width="160" show-overflow-tooltip />
              <el-table-column prop="symbol"        label="符号"     min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="内核定时器" icon-color="#0078d4" :count="(kd.timers||[]).length">
            <template #icon><el-icon><Timer /></el-icon></template>
            <el-table :data="kd.timers||[]" stripe size="small" border>
              <el-table-column prop="offset"          label="偏移量"   width="160" />
              <el-table-column prop="period"          label="周期(ms)" width="100" />
              <el-table-column prop="routine_addr"    label="例程地址" width="160" />
              <el-table-column prop="routine_module"  label="所属模块" min-width="160" show-overflow-tooltip />
              <el-table-column prop="routine_symbol"  label="符号"     min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="大页池分配" icon-color="#f77f00" :count="(kd.big_pools||[]).length">
            <template #icon><el-icon><DataLine /></el-icon></template>
            <el-table :data="kd.big_pools||[]" stripe size="small" border
              :row-class-name="({row}:any) => row.suspicious ? 'row-warn' : ''">
              <el-table-column prop="offset"    label="偏移量" width="160" />
              <el-table-column prop="pool_tag"  label="Tag"    width="80" />
              <el-table-column prop="pool_type" label="类型"   width="120" />
              <el-table-column prop="size"      label="大小"   width="100" :formatter="sizeFmt" />
              <el-table-column label="可疑" width="70">
                <template #default="{ row }">
                  <el-tag v-if="row.suspicious" size="small" type="warning" effect="light">可疑</el-tag>
                  <span v-else class="safe-text">—</span>
                </template>
              </el-table-column>
            </el-table>
          </KernelSection>

          <KernelSection title="虚拟内存映射" icon-color="#4361ee" :count="(kd.virtual_map||[]).length">
            <template #icon><el-icon><DataBoard /></el-icon></template>
            <el-table :data="kd.virtual_map||[]" stripe size="small" border>
              <el-table-column prop="start"  label="起始地址" width="160" />
              <el-table-column prop="end"    label="结束地址" width="160" />
              <el-table-column prop="size"   label="大小"     width="100" :formatter="sizeFmt" />
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
  InfoFilled, DocumentDelete
} from '@element-plus/icons-vue'
import DetectCard from './DetectCard.vue'
import KernelSection from './KernelSection.vue'
import KVTable from './KVTable.vue'

const props = defineProps<{ data: Record<string, any> }>()
const activeTab = ref('overview')
const kd = computed(() => props.data.windows_kernel_data || {})

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
.win-result { height: 100%; display: flex; flex-direction: column; }

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
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
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

:deep(.row-danger td) { background: #fff5f5 !important; }
:deep(.row-warn td)   { background: #fffbf0 !important; }

.safe-text { color: #c0c4cc; }

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
