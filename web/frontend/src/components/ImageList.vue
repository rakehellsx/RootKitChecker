<template>
  <div class="image-list">
    <!-- 顶部工具栏 -->
    <div class="list-header">
      <div class="header-title">
        <el-icon class="title-icon"><List /></el-icon>
        <span>镜像列表</span>
        <span class="count-pill" v-if="images.length > 0">{{ images.length }}</span>
      </div>
      <el-button type="primary" size="small" @click="showUpload = true" class="upload-btn">
        <el-icon><UploadFilled /></el-icon>上传
      </el-button>
    </div>

    <!-- 搜索栏 -->
    <div class="search-bar">
      <el-input
        v-model="searchText"
        placeholder="搜索镜像名称..."
        :prefix-icon="Search"
        size="small"
        clearable
      />
    </div>

    <!-- 镜像卡片列表 -->
    <div class="card-container" v-loading="loading" element-loading-background="rgba(255,255,255,0.85)">
      <transition-group name="card-list">
        <div
          v-for="img in filteredImages"
          :key="img.id"
          class="image-card"
          :class="{ active: selectedId === img.id, [`status-${img.status}`]: true }"
          @click="$emit('select', img)"
        >
          <!-- 顶部状态色条 -->
          <div class="card-topbar" :class="`bar-${img.status}`"></div>

          <div class="card-body">
            <!-- 行1：OS图标 + 文件名 + 状态 -->
            <div class="row-main">
              <div class="os-icon" :class="`os-${img.os_type}`">
                <el-icon>
                  <Monitor v-if="img.os_type === 'windows'" />
                  <Platform v-else-if="img.os_type === 'linux'" />
                  <QuestionFilled v-else />
                </el-icon>
              </div>
              <div class="name-wrap">
                <div class="img-name" :title="img.name">{{ img.name }}</div>
                <div class="img-tags">
                  <span class="tag-os" :class="`tag-${img.os_type}`">{{ osLabel(img.os_type) }}</span>
                  <span class="tag-arch" v-if="img.arch && img.arch !== 'unknown'">{{ img.arch }}</span>
                </div>
              </div>
              <div class="status-badge" :class="`badge-${img.status}`">
                <span class="badge-dot" :class="`dot-${img.status}`"></span>
                {{ statusLabel(img.status) }}
              </div>
            </div>

            <!-- 进度条（分析中） -->
            <div class="progress-bar" v-if="img.status === 'running'">
              <div class="progress-inner"></div>
            </div>

            <!-- 行2：时间信息 -->
            <div class="row-time">
              <div class="time-item">
                <el-icon><Clock /></el-icon>
                <span>{{ formatTime(img.created_at) }}</span>
              </div>
              <div class="time-item done-time" v-if="img.finished_at && img.status === 'done'">
                <el-icon><CircleCheckFilled /></el-icon>
                <span>{{ formatTime(img.finished_at) }}</span>
              </div>
              <div class="time-item error-time" v-if="img.status === 'error' && img.error_msg">
                <el-icon><CircleCloseFilled /></el-icon>
                <span class="error-text" :title="img.error_msg">{{ img.error_msg }}</span>
              </div>
            </div>

            <!-- 行3：操作按钮 -->
            <div class="row-actions" @click.stop>
              <el-button
                v-if="img.status === 'done' || img.status === 'error'"
                size="small" text class="btn-action btn-reanalyze"
                @click="handleReanalyze(img.id)"
              >
                <el-icon><RefreshRight /></el-icon>重新分析
              </el-button>
              <el-button
                v-if="img.status === 'running' || img.status === 'pending'"
                size="small" text disabled class="btn-action btn-running"
              >
                <el-icon class="spin"><Loading /></el-icon>
                {{ img.status === 'pending' ? '等待中...' : '分析中...' }}
              </el-button>
              <el-popconfirm
                title="确认删除该镜像记录？"
                confirm-button-text="删除"
                cancel-button-text="取消"
                :icon="WarningFilled"
                icon-color="#ef4444"
                @confirm="handleDelete(img.id)"
              >
                <template #reference>
                  <el-button size="small" text type="danger" class="btn-action btn-delete">
                    <el-icon><Delete /></el-icon>删除
                  </el-button>
                </template>
              </el-popconfirm>
            </div>
          </div>
        </div>
      </transition-group>

      <!-- 空状态 -->
      <div v-if="!loading && filteredImages.length === 0" class="empty-state">
        <div class="empty-icon-wrap">
          <el-icon><FolderOpened /></el-icon>
        </div>
        <p class="empty-title">{{ images.length === 0 ? '暂无镜像' : '无匹配结果' }}</p>
        <p class="empty-desc">{{ images.length === 0 ? '点击上方按钮上传内存镜像' : '尝试其他关键词' }}</p>
        <el-button v-if="images.length === 0" type="primary" size="small" @click="showUpload = true" style="margin-top:8px">
          <el-icon><UploadFilled /></el-icon>上传镜像
        </el-button>
      </div>
    </div>

    <!-- 上传对话框 -->
    <el-dialog
      v-model="showUpload"
      title="上传内存镜像"
      width="460px"
      :close-on-click-modal="false"
    >
      <div class="upload-form">
        <el-upload
          ref="uploadRef"
          :auto-upload="false"
          :limit="1"
          :on-change="onFileChange"
          :on-exceed="() => ElMessage.warning('每次只能上传一个文件')"
          drag
          accept=".vmem,.raw,.lime,.mem,.dmp,.img,.bin"
        >
          <div class="upload-area">
            <div class="upload-icon-wrap">
              <el-icon class="upload-icon"><UploadFilled /></el-icon>
            </div>
            <p class="upload-text">拖拽文件到此处，或 <em>点击选择</em></p>
            <p class="upload-hint">.vmem / .raw / .lime / .mem / .dmp</p>
          </div>
        </el-upload>

        <div class="os-select-wrap">
          <label class="os-label">操作系统类型</label>
          <div class="os-options">
            <div
              v-for="opt in osOptions"
              :key="opt.value"
              class="os-option"
              :class="{ selected: uploadForm.osType === opt.value }"
              @click="uploadForm.osType = opt.value"
            >
              <el-icon><component :is="opt.icon" /></el-icon>
              <span>{{ opt.label }}</span>
            </div>
          </div>
        </div>

        <div class="selected-file" v-if="uploadForm.file">
          <el-icon><Document /></el-icon>
          <span>{{ uploadForm.file.name }}</span>
          <span class="file-size">{{ formatFileSize(uploadForm.file.size) }}</span>
        </div>
      </div>

      <template #footer>
        <el-button @click="showUpload = false">取消</el-button>
        <el-button
          type="primary"
          :loading="uploading"
          :disabled="!uploadForm.file"
          @click="handleUpload"
        >
          <el-icon v-if="!uploading"><UploadFilled /></el-icon>
          {{ uploading ? '上传中...' : '上传并分析' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import {
  List, UploadFilled, Delete, RefreshRight, Search,
  Monitor, Platform, QuestionFilled, Loading,
  CircleCheckFilled, CircleCloseFilled, Clock,
  FolderOpened, Document, WarningFilled,
} from '@element-plus/icons-vue'
import type { UploadFile } from 'element-plus'
import { listImages, uploadImage, reanalyze, deleteImage } from '../api'
import type { ImageRecord } from '../api'

const emit = defineEmits<{
  (e: 'select', img: ImageRecord): void
  (e: 'uploaded', img: ImageRecord): void
}>()

defineProps<{ selectedId?: number }>()

const images     = ref<ImageRecord[]>([])
const loading    = ref(false)
const showUpload = ref(false)
const uploading  = ref(false)
const uploadRef  = ref()
const searchText = ref('')
const uploadForm = ref({ osType: 'auto', file: null as File | null })

const osOptions = [
  { value: 'auto',    label: '自动检测', icon: Search },
  { value: 'windows', label: 'Windows',  icon: Monitor },
  { value: 'linux',   label: 'Linux',    icon: Platform },
]

const filteredImages = computed(() =>
  searchText.value
    ? images.value.filter(i => i.name.toLowerCase().includes(searchText.value.toLowerCase()))
    : images.value
)

let pollTimer: ReturnType<typeof setInterval> | null = null

const fetchImages = async () => {
  loading.value = true
  try { images.value = await listImages() }
  finally { loading.value = false }
}

const startPolling = () => {
  pollTimer = setInterval(async () => {
    if (images.value.some(i => i.status === 'pending' || i.status === 'running')) {
      images.value = await listImages()
    }
  }, 3000)
}

onMounted(() => { fetchImages(); startPolling() })
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })

const onFileChange = (file: UploadFile) => { uploadForm.value.file = file.raw as File }

const handleUpload = async () => {
  if (!uploadForm.value.file) { ElMessage.warning('请先选择镜像文件'); return }
  uploading.value = true
  try {
    const rec = await uploadImage(uploadForm.value.file, uploadForm.value.osType)
    images.value.unshift(rec)
    showUpload.value = false
    uploadRef.value?.clearFiles()
    uploadForm.value.file = null
    ElMessage.success('上传成功，正在分析中...')
    emit('uploaded', rec)
  } catch (e: any) {
    ElMessage.error('上传失败：' + (e?.message || '未知错误'))
  } finally {
    uploading.value = false
  }
}

const handleReanalyze = async (id: number) => {
  try {
    await reanalyze(id)
    ElMessage.success('已重新提交分析')
    await fetchImages()
  } catch { ElMessage.error('操作失败') }
}

const handleDelete = async (id: number) => {
  try {
    await deleteImage(id)
    images.value = images.value.filter(i => i.id !== id)
    ElMessage.success('已删除')
  } catch { ElMessage.error('删除失败') }
}

const osLabel = (t: string) => ({ windows: 'Windows', linux: 'Linux', auto: '自动' }[t] || t)
const statusLabel = (s: string) => ({ pending: '等待中', running: '分析中', done: '已完成', error: '失败' }[s] || s)

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

const formatFileSize = (bytes: number) => {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB'
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}
</script>

<style scoped>
/* ===== 整体容器 ===== */
.image-list {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #ffffff;
}

/* ===== 顶部工具栏 ===== */
.list-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 14px 10px;
  border-bottom: 1px solid #f0f2f5;
  flex-shrink: 0;
}
.header-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13.5px;
  font-weight: 700;
  color: #1a1a2e;
}
.title-icon { color: #4361ee; font-size: 15px; }
.count-pill {
  background: #eef2ff;
  color: #4361ee;
  font-size: 10.5px;
  font-weight: 700;
  padding: 0 7px;
  height: 17px;
  line-height: 17px;
  border-radius: 9px;
}
.upload-btn {
  background: linear-gradient(135deg, #4361ee, #7c3aed) !important;
  border: none !important;
  font-size: 12px !important;
  padding: 0 12px !important;
  height: 28px !important;
  gap: 4px;
  transition: all 0.2s !important;
}
.upload-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(67, 97, 238, 0.35) !important;
}

/* ===== 搜索栏 ===== */
.search-bar {
  padding: 8px 12px 6px;
  border-bottom: 1px solid #f5f7fa;
  flex-shrink: 0;
}
.search-bar :deep(.el-input__wrapper) {
  border-radius: 7px !important;
  background: #f5f7fa;
  box-shadow: none !important;
  border: 1.5px solid transparent;
  transition: all 0.2s;
  font-size: 12.5px;
}
.search-bar :deep(.el-input__wrapper:hover),
.search-bar :deep(.el-input__wrapper.is-focus) {
  border-color: #4361ee !important;
  background: #fff;
  box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.08) !important;
}
.search-bar :deep(.el-input__inner) { font-size: 12.5px !important; }

/* ===== 卡片容器 ===== */
.card-container {
  flex: 1;
  overflow-y: auto;
  padding: 8px 8px 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.card-container::-webkit-scrollbar { width: 4px; }
.card-container::-webkit-scrollbar-track { background: transparent; }
.card-container::-webkit-scrollbar-thumb { background: #dde1f0; border-radius: 4px; }

/* ===== 镜像卡片 ===== */
.image-card {
  background: #fff;
  border: 1.5px solid #eaecf4;
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.18s ease;
  overflow: hidden;
  box-shadow: 0 1px 3px rgba(0,0,0,0.03);
}
.image-card:hover {
  border-color: #a5b4fc;
  box-shadow: 0 3px 12px rgba(67, 97, 238, 0.1);
  transform: translateY(-1px);
}
.image-card.active {
  border-color: #4361ee;
  background: #f8f9ff;
  box-shadow: 0 3px 16px rgba(67, 97, 238, 0.14);
}

/* ===== 顶部状态色条 ===== */
.card-topbar {
  height: 3px;
  width: 100%;
}
.bar-pending { background: #d1d5db; }
.bar-running {
  background: linear-gradient(90deg, #f59e0b, #fbbf24, #f59e0b);
  background-size: 200% 100%;
  animation: shimmer 1.8s ease-in-out infinite;
}
.bar-done    { background: linear-gradient(90deg, #10b981, #34d399); }
.bar-error   { background: linear-gradient(90deg, #ef4444, #f87171); }

@keyframes shimmer {
  0%   { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}

/* ===== 卡片主体 ===== */
.card-body {
  padding: 10px 11px 8px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

/* ===== 行1：主信息 ===== */
.row-main {
  display: flex;
  align-items: flex-start;
  gap: 8px;
}

.os-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  flex-shrink: 0;
  margin-top: 1px;
}
.os-windows { background: #eff6ff; color: #2563eb; }
.os-linux   { background: #f0fdf4; color: #16a34a; }
.os-auto    { background: #f5f3ff; color: #7c3aed; }

.name-wrap {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.img-name {
  font-size: 12.5px;
  font-weight: 700;
  color: #1e1e3a;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 1.3;
}
.img-tags {
  display: flex;
  gap: 4px;
  align-items: center;
}
.tag-os {
  font-size: 9.5px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 3px;
  letter-spacing: 0.2px;
  text-transform: uppercase;
}
.tag-windows { background: #dbeafe; color: #1d4ed8; }
.tag-linux   { background: #dcfce7; color: #15803d; }
.tag-auto    { background: #ede9fe; color: #6d28d9; }
.tag-arch {
  font-size: 9.5px;
  color: #6b7280;
  background: #f3f4f6;
  padding: 1px 6px;
  border-radius: 3px;
}

/* 状态徽章 */
.status-badge {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 20px;
  flex-shrink: 0;
  white-space: nowrap;
  margin-top: 2px;
}
.badge-pending { background: #f3f4f6; color: #6b7280; }
.badge-running { background: #fffbeb; color: #d97706; }
.badge-done    { background: #f0fdf4; color: #16a34a; }
.badge-error   { background: #fef2f2; color: #dc2626; }

.badge-dot {
  width: 5px; height: 5px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}
.dot-pending { background: #9ca3af; }
.dot-running { background: #f59e0b; animation: blink 1.2s ease-in-out infinite; }
.dot-done    { background: #22c55e; }
.dot-error   { background: #ef4444; }

@keyframes blink {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.25; }
}

/* ===== 进度条 ===== */
.progress-bar {
  height: 2px;
  background: #f0f2f5;
  border-radius: 2px;
  overflow: hidden;
  margin: 0 -1px;
}
.progress-inner {
  height: 100%;
  width: 40%;
  background: linear-gradient(90deg, #4361ee, #7c3aed);
  border-radius: 2px;
  animation: slide 1.8s ease-in-out infinite;
}
@keyframes slide {
  0%   { transform: translateX(-150%); }
  100% { transform: translateX(350%); }
}

/* ===== 行2：时间信息 ===== */
.row-time {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.time-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 10.5px;
  color: #9ca3af;
}
.time-item .el-icon { font-size: 10px; flex-shrink: 0; }
.time-item span { color: #6b7280; font-variant-numeric: tabular-nums; }
.done-time .el-icon { color: #22c55e; }
.done-time span { color: #4b5563; }
.error-time .el-icon { color: #ef4444; }
.error-text {
  color: #ef4444 !important;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 140px;
}

/* ===== 行3：操作按钮 ===== */
.row-actions {
  display: flex;
  gap: 0;
  justify-content: flex-end;
  border-top: 1px solid #f5f7fa;
  padding-top: 5px;
  margin-top: 1px;
}
.btn-action {
  font-size: 11px !important;
  height: 22px !important;
  padding: 0 7px !important;
  border-radius: 5px !important;
  gap: 3px;
  display: flex !important;
  align-items: center !important;
}
.btn-reanalyze { color: #4361ee !important; }
.btn-reanalyze:hover { background: #eef2ff !important; }
.btn-delete:hover { background: #fef2f2 !important; }
.btn-running { color: #9ca3af !important; }

.spin {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}

/* ===== 卡片列表动画 ===== */
.card-list-enter-active, .card-list-leave-active { transition: all 0.25s ease; }
.card-list-enter-from { opacity: 0; transform: translateY(-8px); }
.card-list-leave-to   { opacity: 0; transform: translateX(-16px); }

/* ===== 空状态 ===== */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 20px;
  flex: 1;
  gap: 6px;
}
.empty-icon-wrap {
  width: 52px; height: 52px;
  background: #f0f4ff;
  border-radius: 14px;
  display: flex; align-items: center; justify-content: center;
  font-size: 24px; color: #a5b4fc;
  margin-bottom: 4px;
}
.empty-title {
  font-size: 13px; font-weight: 700; color: #374151; margin: 0;
}
.empty-desc {
  font-size: 11.5px; color: #9ca3af; text-align: center; margin: 0; line-height: 1.5;
}

/* ===== 上传表单 ===== */
.upload-form { display: flex; flex-direction: column; gap: 16px; }
.upload-area {
  display: flex; flex-direction: column;
  align-items: center; gap: 8px; padding: 8px 0;
}
.upload-icon-wrap {
  width: 52px; height: 52px;
  background: linear-gradient(135deg, #eef2ff, #e0e8ff);
  border-radius: 14px;
  display: flex; align-items: center; justify-content: center;
}
.upload-icon { font-size: 26px; color: #4361ee; }
.upload-text { font-size: 13px; color: #374151; margin: 0; }
.upload-text em { color: #4361ee; font-style: normal; font-weight: 600; }
.upload-hint { font-size: 11.5px; color: #9ca3af; margin: 0; }

.os-select-wrap { display: flex; flex-direction: column; gap: 8px; }
.os-label {
  font-size: 12.5px; font-weight: 600; color: #374151;
}
.os-options { display: flex; gap: 8px; }
.os-option {
  flex: 1;
  display: flex; align-items: center; justify-content: center; gap: 6px;
  padding: 9px 10px;
  border: 1.5px solid #e8ecf4;
  border-radius: 9px;
  cursor: pointer;
  font-size: 12.5px; color: #6b7280;
  transition: all 0.15s;
}
.os-option:hover { border-color: #a5b4fc; color: #4361ee; background: #f8f9ff; }
.os-option.selected {
  border-color: #4361ee; color: #4361ee;
  background: #eef2ff; font-weight: 600;
}
.os-opt-icon { font-size: 15px; }

.selected-file {
  display: flex; align-items: center; gap: 8px;
  padding: 9px 12px;
  background: #f8f9ff; border: 1px solid #dde5ff;
  border-radius: 8px; font-size: 12.5px; color: #374151;
}
.selected-file .el-icon { color: #4361ee; font-size: 15px; flex-shrink: 0; }
.selected-file span:nth-child(2) {
  flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.file-size { color: #9ca3af; font-size: 11.5px; flex-shrink: 0; }
</style>
