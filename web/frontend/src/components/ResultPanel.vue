<template>
  <div class="result-panel">
    <!-- 未选择状态 -->
    <div v-if="!image" class="empty-panel">
      <div class="empty-visual">
        <div class="ring ring1"></div>
        <div class="ring ring2"></div>
        <div class="ring ring3"></div>
        <div class="empty-center-icon"><el-icon><Aim /></el-icon></div>
      </div>
      <h2 class="empty-title">选择镜像开始分析</h2>
      <p class="empty-desc">从左侧列表选择一个内存镜像，查看 Rootkit 检测与内核数据分析结果</p>
      <div class="feature-chips">
        <div class="chip"><el-icon><Search /></el-icon>隐藏进程检测</div>
        <div class="chip"><el-icon><Connection /></el-icon>隐藏网络连接</div>
        <div class="chip"><el-icon><Warning /></el-icon>Rootkit 检测</div>
        <div class="chip"><el-icon><Cpu /></el-icon>内核数据采集</div>
      </div>
    </div>

    <!-- 分析中 -->
    <div v-else-if="image.status === 'pending' || image.status === 'running'" class="loading-panel">
      <div class="loading-visual">
        <div class="scan-ring sr1"></div>
        <div class="scan-ring sr2"></div>
        <div class="scan-ring sr3"></div>
        <div class="scan-icon"><el-icon><Search /></el-icon></div>
      </div>
      <h2 class="loading-title">正在分析内存镜像</h2>
      <p class="loading-file">{{ image.name }}</p>
      <div class="loading-steps">
        <div class="step active"><el-icon><Monitor /></el-icon><span>识别操作系统</span></div>
        <div class="step" :class="{ active: image.status === 'running' }"><el-icon><Search /></el-icon><span>扫描隐藏进程</span></div>
        <div class="step" :class="{ active: image.status === 'running' }"><el-icon><Connection /></el-icon><span>检测网络连接</span></div>
        <div class="step"><el-icon><Cpu /></el-icon><span>采集内核数据</span></div>
      </div>
      <el-progress
        :percentage="image.status === 'running' ? 65 : 15"
        :striped="true" :striped-flow="true" :duration="10"
        :stroke-width="8" class="scan-progress"
      />
    </div>

    <!-- 分析失败 -->
    <div v-else-if="image.status === 'error'" class="error-panel">
      <div class="error-icon-wrap"><el-icon class="error-icon"><CircleCloseFilled /></el-icon></div>
      <h2 class="error-title">分析失败</h2>
      <p class="error-file">{{ image.name }}</p>
      <div class="error-msg" v-if="image.error_msg">
        <el-icon><InfoFilled /></el-icon><span>{{ image.error_msg }}</span>
      </div>
      <div class="error-tips">
        <p class="tips-title"><el-icon><QuestionFilled /></el-icon>可能原因</p>
        <ul>
          <li>镜像文件损坏或格式不支持</li>
          <li>未找到对应的符号表文件</li>
          <li>Volatility3 不支持该内核版本</li>
          <li>内存不足或分析超时</li>
        </ul>
      </div>
      <el-button type="primary" :icon="RefreshRight" @click="$emit('reanalyze', image.id)">重新分析</el-button>
    </div>

    <!-- 分析完成 -->
    <template v-else-if="image.status === 'done'">
      <!-- 结果头部 -->
      <div class="result-header">
        <div class="result-info">
          <div class="result-os-badge" :class="`os-${image.os_type}`">
            <el-icon><Monitor v-if="image.os_type === 'windows'" /><Platform v-else /></el-icon>
          </div>
          <div>
            <div class="result-filename">{{ image.name }}</div>
            <div class="result-meta">
              <span v-if="image.arch && image.arch !== 'unknown'">
                <el-icon><Cpu /></el-icon>{{ image.arch }}
              </span>
              <span v-if="image.finished_at">
                <el-icon><Clock /></el-icon>{{ formatTime(image.finished_at) }}
              </span>
            </div>
          </div>
        </div>
        <div class="result-actions">
          <el-button size="small" :icon="RefreshRight" plain @click="$emit('reanalyze', image.id)" class="btn-plain">重新分析</el-button>
          <el-button size="small" :icon="Download" type="primary" @click="downloadResult" class="btn-export">导出 JSON</el-button>
        </div>
      </div>

      <!-- 摘要统计栏 -->
      <div class="summary-bar" v-if="resultData">
        <div class="summary-card threat-card" :class="{ 'has-threat': threatCount > 0 }">
          <div class="summary-icon-wrap" :class="threatCount > 0 ? 'icon-danger' : 'icon-safe'">
            <el-icon><Warning v-if="threatCount > 0" /><CircleCheck v-else /></el-icon>
          </div>
          <div class="summary-info">
            <div class="summary-num" :class="{ 'num-danger': threatCount > 0, 'num-safe': threatCount === 0 }">
              {{ threatCount }}
            </div>
            <div class="summary-label">威胁发现</div>
          </div>
        </div>
        <div class="summary-divider"></div>
        <div class="summary-card" :class="{ 'has-alert': hiddenProcessCount > 0 }">
          <div class="summary-icon-wrap" :class="hiddenProcessCount > 0 ? 'icon-warn' : 'icon-normal'">
            <el-icon><Hide /></el-icon>
          </div>
          <div class="summary-info">
            <div class="summary-num" :class="{ 'num-warn': hiddenProcessCount > 0 }">{{ hiddenProcessCount }}</div>
            <div class="summary-label">隐藏进程</div>
          </div>
        </div>
        <div class="summary-card">
          <div class="summary-icon-wrap icon-normal">
            <el-icon><List /></el-icon>
          </div>
          <div class="summary-info">
            <div class="summary-num">{{ processCount }}</div>
            <div class="summary-label">进程总数</div>
          </div>
        </div>
        <div class="summary-card" :class="{ 'has-alert': hiddenNetCount > 0 }">
          <div class="summary-icon-wrap" :class="hiddenNetCount > 0 ? 'icon-warn' : 'icon-normal'">
            <el-icon><Connection /></el-icon>
          </div>
          <div class="summary-info">
            <div class="summary-num" :class="{ 'num-warn': hiddenNetCount > 0 }">{{ networkCount }}</div>
            <div class="summary-label">网络连接</div>
          </div>
        </div>
        <div class="summary-card">
          <div class="summary-icon-wrap icon-normal">
            <el-icon><Grid /></el-icon>
          </div>
          <div class="summary-info">
            <div class="summary-num">{{ moduleCount }}</div>
            <div class="summary-label">内核模块</div>
          </div>
        </div>
      </div>

      <!-- 结果内容 -->
      <div class="result-body" v-loading="loading" element-loading-background="rgba(248,249,252,0.9)">
        <WindowsResult v-if="image.os_type === 'windows' && resultData" :data="resultData" />
        <LinuxResult   v-else-if="image.os_type === 'linux' && resultData"   :data="resultData" />
        <div v-else-if="!resultData && !loading" class="no-result">
          <el-icon><InfoFilled /></el-icon><span>暂无分析结果数据</span>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { ElMessage } from 'element-plus'
import {
  Aim, Search, Connection, Warning, Cpu, Monitor, Platform, List, Hide, Grid,
  CircleCloseFilled, InfoFilled, QuestionFilled, RefreshRight, Download, Clock,
  CircleCheck
} from '@element-plus/icons-vue'
import { getResult } from '../api'
import type { ImageRecord } from '../api'
import WindowsResult from './WindowsResult.vue'
import LinuxResult from './LinuxResult.vue'

const props = defineProps<{ image?: ImageRecord | null }>()
const emit = defineEmits<{ (e: 'reanalyze', id: number): void }>()

const loading    = ref(false)
const resultData = ref<Record<string, any> | null>(null)

const formatTime = (t: string | null) => {
  if (!t) return ''
  const d = new Date(t)
  if (isNaN(d.getTime())) return t.substring(0, 16).replace('T', ' ')
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  const mi = String(d.getMinutes()).padStart(2, '0')
  return `${mm}-${dd} ${hh}:${mi}`
}

watch(() => props.image, async (img) => {
  resultData.value = null
  if (!img || img.status !== 'done') return
  loading.value = true
  try { resultData.value = await getResult(img.id) }
  catch (e: any) { ElMessage.error('获取分析结果失败：' + (e?.message || '')) }
  finally { loading.value = false }
}, { immediate: true })

const threatCount = computed(() => {
  if (!resultData.value) return 0
  const d = resultData.value
  return [
    d.hidden_processes, d.hollow_processes, d.ssdt_hooks, d.hidden_modules, d.hidden_connections,
    d.hidden_processes_linux, d.syscall_hooks, d.idt_hooks, d.afinfo_hooks, d.hidden_modules_linux,
    d.cred_anomalies, d.netfilter_hooks, d.tty_hooks, d.keyboard_hooks,
    (d.windows_kernel_data?.driver_irps || []).filter((x: any) => x.hooked),
  ].reduce((s, a) => s + (Array.isArray(a) ? a.length : 0), 0)
})

const processCount      = computed(() => resultData.value?.processes?.length || resultData.value?.processes_linux?.length || 0)
const hiddenProcessCount = computed(() => (resultData.value?.hidden_processes?.length || 0) + (resultData.value?.hidden_processes_linux?.length || 0))
const networkCount      = computed(() => resultData.value?.network_connections?.length || resultData.value?.network_connections_linux?.length || 0)
const hiddenNetCount    = computed(() => (resultData.value?.hidden_connections?.length || 0) + (resultData.value?.hidden_connections_linux?.length || 0))
const moduleCount       = computed(() => resultData.value?.windows_kernel_data?.loaded_modules?.length || resultData.value?.linux_kernel_data?.loaded_modules?.length || 0)

const downloadResult = () => {
  if (!resultData.value) return
  const blob = new Blob([JSON.stringify(resultData.value, null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `${props.image?.name || 'result'}_analysis.json`
  a.click()
}
</script>

<style scoped>
.result-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #f8f9fc;
  overflow: hidden;
}

/* ── 空状态 ── */
.empty-panel {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  padding: 40px;
  gap: 16px;
}
.empty-visual {
  position: relative;
  width: 120px;
  height: 120px;
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.ring {
  position: absolute;
  border-radius: 50%;
  border: 2px solid #e0e6f8;
}
.ring1 { width: 120px; height: 120px; }
.ring2 { width: 86px;  height: 86px;  border-color: #c8d4f0; }
.ring3 { width: 54px;  height: 54px;  border-color: #b0c0e8; }
.empty-center-icon { position: absolute; font-size: 28px; color: #4361ee; }
.empty-title { font-size: 20px; font-weight: 700; color: #1a1a2e; margin: 0; }
.empty-desc {
  font-size: 13px; color: #8888aa;
  text-align: center; max-width: 380px; line-height: 1.7; margin: 0;
}
.feature-chips {
  display: flex; gap: 8px; flex-wrap: wrap;
  justify-content: center; margin-top: 8px;
}
.chip {
  display: flex; align-items: center; gap: 5px;
  padding: 7px 16px; background: #ffffff;
  border: 1px solid #e8ecf4; border-radius: 20px;
  font-size: 12px; color: #4a4a6a;
  box-shadow: 0 1px 4px rgba(0,0,0,0.04);
}
.chip .el-icon { color: #4361ee; }

/* ── 加载状态 ── */
.loading-panel {
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  height: 100%; padding: 40px; gap: 16px;
}
.loading-visual {
  position: relative; width: 120px; height: 120px;
  margin-bottom: 8px; display: flex;
  align-items: center; justify-content: center;
}
.scan-ring {
  position: absolute; border-radius: 50%;
  border: 2px solid transparent; border-top-color: #4361ee;
}
.sr1 { width: 120px; height: 120px; animation: spin 2s linear infinite; }
.sr2 { width: 86px; height: 86px; border-top-color: #7209b7; animation: spin 1.5s linear infinite reverse; }
.sr3 { width: 54px; height: 54px; border-top-color: #4cc9f0; animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.scan-icon { position: absolute; font-size: 28px; color: #4361ee; }
.loading-title { font-size: 18px; font-weight: 700; color: #1a1a2e; margin: 0; }
.loading-file  { font-size: 13px; color: #8888aa; margin: 0; }
.loading-steps { display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; }
.step {
  display: flex; align-items: center; gap: 5px;
  padding: 6px 14px; background: #ffffff;
  border: 1px solid #e8ecf4; border-radius: 20px;
  font-size: 12px; color: #b0b8d8;
}
.step.active { border-color: #4361ee; color: #4361ee; background: #f0f4ff; font-weight: 600; }
.scan-progress { width: 320px; }
.scan-progress :deep(.el-progress-bar__outer) { border-radius: 8px; background: #e8ecf4; }
.scan-progress :deep(.el-progress-bar__inner) { background: linear-gradient(90deg, #4361ee, #7209b7); border-radius: 8px; }

/* ── 错误状态 ── */
.error-panel {
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  height: 100%; padding: 40px; gap: 14px;
}
.error-icon-wrap {
  width: 72px; height: 72px; background: #fff0f3;
  border-radius: 50%; display: flex;
  align-items: center; justify-content: center;
}
.error-icon { font-size: 36px; color: #ef233c; }
.error-title { font-size: 18px; font-weight: 700; color: #1a1a2e; margin: 0; }
.error-file  { font-size: 13px; color: #8888aa; margin: 0; }
.error-msg {
  display: flex; align-items: flex-start; gap: 8px;
  padding: 12px 16px; background: #fff0f3;
  border: 1px solid #ffc0cb; border-radius: 8px;
  font-size: 13px; color: #ef233c; max-width: 480px;
}
.error-tips {
  background: #ffffff; border: 1px solid #e8ecf4;
  border-radius: 10px; padding: 14px 18px;
  max-width: 360px; width: 100%;
}
.tips-title {
  display: flex; align-items: center; gap: 6px;
  font-size: 13px; font-weight: 600; color: #4a4a6a; margin-bottom: 8px;
}
.error-tips ul { padding-left: 18px; display: flex; flex-direction: column; gap: 4px; }
.error-tips li { font-size: 12px; color: #8888aa; line-height: 1.6; }

/* ── 完成状态头部 ── */
.result-header {
  display: flex; align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  background: #ffffff;
  border-bottom: 1px solid #eef0f8;
  flex-shrink: 0;
  gap: 12px;
}
.result-info { display: flex; align-items: center; gap: 12px; min-width: 0; flex: 1; }
.result-os-badge {
  width: 44px; height: 44px; border-radius: 12px;
  display: flex; align-items: center; justify-content: center; font-size: 22px; flex-shrink: 0;
}
.os-windows { background: #eff6ff; color: #2563eb; }
.os-linux   { background: #f0fdf4; color: #16a34a; }
.result-filename {
  font-size: 15px; font-weight: 700; color: #1e1e3a;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  margin-bottom: 5px;
}
.result-meta { display: flex; gap: 12px; flex-wrap: wrap; }
.result-meta span {
  display: flex; align-items: center; gap: 4px;
  font-size: 12px; color: #6b7280;
  background: #f3f4f6; padding: 2px 8px; border-radius: 4px;
}
.result-meta .el-icon { font-size: 11px; }
.result-actions { display: flex; gap: 8px; flex-shrink: 0; }
.btn-plain { border-radius: 8px !important; }
.btn-export {
  border-radius: 8px !important;
  background: linear-gradient(135deg, #4361ee, #7c3aed) !important;
  border: none !important;
}

/* ── 摘要统计栏 ── */
.summary-bar {
  display: flex;
  align-items: stretch;
  gap: 0;
  padding: 0;
  background: #ffffff;
  border-bottom: 2px solid #eef0f8;
  flex-shrink: 0;
  overflow-x: auto;
}
.summary-bar::-webkit-scrollbar { height: 3px; }
.summary-bar::-webkit-scrollbar-thumb { background: #dde1f0; border-radius: 4px; }

.summary-divider {
  width: 1px;
  background: #eef0f8;
  flex-shrink: 0;
  margin: 10px 0;
}

.summary-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 20px;
  flex-shrink: 0;
  transition: background 0.15s;
  border-right: 1px solid #f0f2f8;
  position: relative;
}
.summary-card:last-child { border-right: none; }
.summary-card:hover { background: #f8f9ff; }

.summary-card.has-threat {
  background: #fff8f8;
}
.summary-card.has-threat::after {
  content: '';
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 2px;
  background: #ef4444;
}
.summary-card.has-alert {
  background: #fffdf5;
}
.summary-card.has-alert::after {
  content: '';
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 2px;
  background: #f59e0b;
}

.summary-icon-wrap {
  width: 40px; height: 40px;
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  font-size: 19px; flex-shrink: 0;
}
.icon-danger  { background: #fee2e2; color: #dc2626; }
.icon-safe    { background: #dcfce7; color: #16a34a; }
.icon-warn    { background: #fef3c7; color: #d97706; }
.icon-normal  { background: #eef2ff; color: #4361ee; }

.summary-info { display: flex; flex-direction: column; gap: 2px; }
.summary-num {
  font-size: 26px;
  font-weight: 900;
  color: #1e1e3a;
  line-height: 1;
  letter-spacing: -1px;
}
.num-danger { color: #dc2626; }
.num-safe   { color: #16a34a; }
.num-warn   { color: #d97706; }
.summary-label {
  font-size: 11px; font-weight: 500; color: #6b7280; white-space: nowrap;
}

/* ── 结果内容 ── */
.result-body {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.no-result {
  display: flex; align-items: center; justify-content: center;
  gap: 8px; height: 200px; color: #b0b8d8; font-size: 14px;
}
</style>
