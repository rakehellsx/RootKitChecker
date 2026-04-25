<template>
  <div class="image-list">
    <!-- 顶部操作栏 -->
    <div class="list-header">
      <div class="header-title">
        <el-icon class="title-icon"><List /></el-icon>
        <span>镜像列表</span>
        <el-badge :value="images.length" :max="99" class="count-badge" v-if="images.length > 0" />
      </div>
      <el-button type="primary" :icon="UploadFilled" size="small" @click="showUpload = true" round>
        上传镜像
      </el-button>
    </div>

    <!-- 搜索栏 -->
    <div class="search-bar" v-if="images.length > 0">
      <el-input
        v-model="searchText"
        placeholder="搜索镜像名称..."
        :prefix-icon="Search"
        size="small"
        clearable
      />
    </div>

    <!-- 镜像卡片列表 -->
    <div class="card-container" v-loading="loading" element-loading-background="rgba(255,255,255,0.8)">
      <transition-group name="card-list">
        <div
          v-for="img in filteredImages"
          :key="img.id"
          class="image-card"
          :class="{ active: selectedId === img.id, [`status-${img.status}`]: true }"
          @click="$emit('select', img)"
        >
          <!-- 状态指示条 -->
          <div class="status-bar" :class="`bar-${img.status}`"></div>

          <!-- 卡片内容 -->
          <div class="card-content">
            <!-- 头部 -->
            <div class="card-head">
              <div class="os-badge" :class="`os-${img.os_type}`">
                <el-icon>
                  <Monitor v-if="img.os_type === 'windows'" />
                  <Platform v-else-if="img.os_type === 'linux'" />
                  <QuestionFilled v-else />
                </el-icon>
              </div>
              <div class="card-title-wrap">
                <div class="img-name" :title="img.name">{{ img.name }}</div>
                <div class="img-os">{{ osLabel(img.os_type) }}</div>
              </div>
              <el-tag
                :type="statusTagType(img.status)"
                size="small"
                effect="light"
                class="status-tag"
                :class="`tag-${img.status}`"
              >
                <el-icon class="tag-icon" v-if="img.status === 'running'"><Loading /></el-icon>
                <el-icon class="tag-icon" v-else-if="img.status === 'done'"><CircleCheckFilled /></el-icon>
                <el-icon class="tag-icon" v-else-if="img.status === 'error'"><CircleCloseFilled /></el-icon>
                <el-icon class="tag-icon" v-else><Timer /></el-icon>
                {{ statusLabel(img.status) }}
              </el-tag>
            </div>

            <!-- 信息行 -->
            <div class="card-meta">
              <div class="meta-item" v-if="img.arch">
                <el-icon><Cpu /></el-icon>
                <span>{{ img.arch }}</span>
              </div>
              <div class="meta-item">
                <el-icon><Clock /></el-icon>
                <span>{{ formatTime(img.created_at) }}</span>
              </div>
              <div class="meta-item" v-if="img.finished_at">
                <el-icon><SuccessFilled /></el-icon>
                <span>完成 {{ formatTime(img.finished_at) }}</span>
              </div>
            </div>

            <!-- 操作按钮 -->
            <div class="card-actions" @click.stop>
              <el-button
                v-if="img.status === 'done' || img.status === 'error'"
                size="small"
                :icon="RefreshRight"
                @click="handleReanalyze(img.id)"
                plain
              >重新分析</el-button>
              <el-popconfirm
                title="确认删除该镜像记录？"
                confirm-button-text="删除"
                cancel-button-text="取消"
                :icon="WarningFilled"
                icon-color="#ef233c"
                @confirm="handleDelete(img.id)"
              >
                <template #reference>
                  <el-button size="small" type="danger" :icon="Delete" plain>删除</el-button>
                </template>
              </el-popconfirm>
            </div>
          </div>
        </div>
      </transition-group>

      <div v-if="!loading && filteredImages.length === 0" class="empty-state">
        <div class="empty-icon">
          <el-icon><FolderOpened /></el-icon>
        </div>
        <p class="empty-title">{{ images.length === 0 ? '暂无镜像' : '无匹配结果' }}</p>
        <p class="empty-desc">{{ images.length === 0 ? '点击上方按钮上传内存镜像' : '尝试其他关键词' }}</p>
      </div>
    </div>

    <!-- 上传对话框 -->
    <el-dialog
      v-model="showUpload"
      title="上传内存镜像"
      width="500px"
      :close-on-click-modal="false"
      class="upload-dialog"
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
          class="upload-dragger"
        >
          <div class="upload-area">
            <div class="upload-icon-wrap">
              <el-icon class="upload-icon"><UploadFilled /></el-icon>
            </div>
            <p class="upload-text">拖拽文件到此处，或 <em>点击选择</em></p>
            <p class="upload-hint">支持 .vmem / .raw / .lime / .mem / .dmp 格式</p>
          </div>
        </el-upload>

        <div class="os-select-wrap">
          <label class="os-label">
            <el-icon><Monitor /></el-icon>
            操作系统类型
          </label>
          <div class="os-options">
            <div
              v-for="opt in osOptions"
              :key="opt.value"
              class="os-option"
              :class="{ selected: uploadForm.osType === opt.value }"
              @click="uploadForm.osType = opt.value"
            >
              <el-icon class="os-opt-icon">
                <component :is="opt.icon" />
              </el-icon>
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
        <el-button @click="showUpload = false" size="default">取消</el-button>
        <el-button
          type="primary"
          :loading="uploading"
          :disabled="!uploadForm.file"
          size="default"
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
  Monitor, Platform, QuestionFilled, Loading, Timer,
  CircleCheckFilled, CircleCloseFilled, Cpu, Clock,
  SuccessFilled, FolderOpened, Document, WarningFilled,
} from '@element-plus/icons-vue'
import type { UploadFile } from 'element-plus'
import { listImages, uploadImage, reanalyze, deleteImage } from '../api'
import type { ImageRecord } from '../api'

const emit = defineEmits<{
  (e: 'select', img: ImageRecord): void
  (e: 'uploaded', img: ImageRecord): void
}>()

const props = defineProps<{ selectedId?: number }>()

const images      = ref<ImageRecord[]>([])
const loading     = ref(false)
const showUpload  = ref(false)
const uploading   = ref(false)
const uploadRef   = ref()
const searchText  = ref('')
const uploadForm  = ref({ osType: 'auto', file: null as File | null })

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

const onFileChange = (file: UploadFile) => {
  uploadForm.value.file = file.raw as File
}

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

const osLabel = (t: string) => ({ windows: 'Windows', linux: 'Linux', auto: '自动检测' }[t] || t)
const statusTagType = (s: string) => ({ pending: 'info', running: 'warning', done: 'success', error: 'danger' }[s] || 'info') as any
const statusLabel = (s: string) => ({ pending: '等待中', running: '分析中', done: '已完成', error: '失败' }[s] || s)

const formatTime = (t: string | null) => {
  if (!t) return ''
  return t.replace('T', ' ').substring(0, 16)
}

const formatFileSize = (bytes: number) => {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB'
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}
</script>

<style scoped>
.image-list {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #ffffff;
}

/* ── 顶部 ── */
.list-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 16px 12px;
  border-bottom: 1px solid #f0f2f5;
}

.header-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 700;
  color: #1a1a2e;
}

.title-icon {
  color: #4361ee;
  font-size: 16px;
}

.count-badge :deep(.el-badge__content) {
  background: #4361ee;
  border: none;
  font-size: 10px;
  height: 16px;
  line-height: 16px;
  padding: 0 5px;
}

/* ── 搜索栏 ── */
.search-bar {
  padding: 8px 12px;
  border-bottom: 1px solid #f0f2f5;
}

.search-bar :deep(.el-input__wrapper) {
  border-radius: 20px !important;
  background: #f5f7fa;
  box-shadow: none !important;
  border: 1px solid transparent;
}

.search-bar :deep(.el-input__wrapper:hover) {
  border-color: #4361ee !important;
}

/* ── 卡片容器 ── */
.card-container {
  flex: 1;
  overflow-y: auto;
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

/* ── 镜像卡片 ── */
.image-card {
  background: #ffffff;
  border: 1.5px solid #e8ecf4;
  border-radius: 12px;
  cursor: pointer;
  transition: all 0.2s ease;
  overflow: hidden;
  display: flex;
  box-shadow: 0 1px 4px rgba(0,0,0,0.04);
}

.image-card:hover {
  border-color: #4361ee;
  box-shadow: 0 4px 16px rgba(67, 97, 238, 0.12);
  transform: translateY(-1px);
}

.image-card.active {
  border-color: #4361ee;
  box-shadow: 0 4px 16px rgba(67, 97, 238, 0.15);
  background: #f8f9ff;
}

/* ── 状态指示条 ── */
.status-bar {
  width: 4px;
  flex-shrink: 0;
  border-radius: 0 2px 2px 0;
}

.bar-pending  { background: #c0c4cc; }
.bar-running  { background: linear-gradient(180deg, #f77f00, #ffc300); animation: pulse-bar 1.5s ease-in-out infinite; }
.bar-done     { background: linear-gradient(180deg, #06d6a0, #00b4d8); }
.bar-error    { background: linear-gradient(180deg, #ef233c, #ff6b6b); }

@keyframes pulse-bar {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

/* ── 卡片内容 ── */
.card-content {
  flex: 1;
  padding: 12px 12px 10px;
  min-width: 0;
}

.card-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.os-badge {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  flex-shrink: 0;
}

.os-windows { background: #e8f0fe; color: #0078d4; }
.os-linux   { background: #fff3e0; color: #e65100; }
.os-auto    { background: #f3e8ff; color: #7c3aed; }

.card-title-wrap {
  flex: 1;
  min-width: 0;
}

.img-name {
  font-size: 13px;
  font-weight: 600;
  color: #1a1a2e;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  line-height: 1.3;
}

.img-os {
  font-size: 11px;
  color: #8888aa;
  margin-top: 1px;
}

.status-tag {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 3px;
  font-size: 11px;
}

.tag-icon {
  font-size: 11px;
}

.tag-running .tag-icon {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}

/* ── 元数据 ── */
.card-meta {
  display: flex;
  flex-direction: column;
  gap: 3px;
  margin-bottom: 10px;
}

.meta-item {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  color: #8888aa;
}

.meta-item .el-icon {
  font-size: 11px;
  color: #b0b8d8;
}

/* ── 操作按钮 ── */
.card-actions {
  display: flex;
  gap: 6px;
  justify-content: flex-end;
}

.card-actions :deep(.el-button) {
  height: 26px;
  font-size: 12px;
  padding: 0 10px;
}

/* ── 空状态 ── */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  flex: 1;
}

.empty-icon {
  width: 64px;
  height: 64px;
  background: #f0f4ff;
  border-radius: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 12px;
  font-size: 28px;
  color: #b0b8d8;
}

.empty-title {
  font-size: 14px;
  font-weight: 600;
  color: #4a4a6a;
  margin-bottom: 4px;
}

.empty-desc {
  font-size: 12px;
  color: #b0b8d8;
}

/* ── 上传对话框 ── */
.upload-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.upload-area {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 24px;
  gap: 8px;
}

.upload-icon-wrap {
  width: 56px;
  height: 56px;
  background: linear-gradient(135deg, #e8eefe, #f0f4ff);
  border-radius: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 4px;
}

.upload-icon {
  font-size: 28px;
  color: #4361ee;
}

.upload-text {
  font-size: 14px;
  color: #4a4a6a;
}

.upload-text em {
  color: #4361ee;
  font-style: normal;
  font-weight: 600;
}

.upload-hint {
  font-size: 12px;
  color: #b0b8d8;
}

.os-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  font-weight: 600;
  color: #4a4a6a;
  margin-bottom: 10px;
}

.os-options {
  display: flex;
  gap: 8px;
}

.os-option {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 12px 8px;
  border: 1.5px solid #e8ecf4;
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 12px;
  color: #4a4a6a;
}

.os-option:hover {
  border-color: #4361ee;
  background: #f8f9ff;
}

.os-option.selected {
  border-color: #4361ee;
  background: #f0f4ff;
  color: #4361ee;
  font-weight: 600;
}

.os-opt-icon {
  font-size: 20px;
}

.selected-file {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  background: #f8f9ff;
  border: 1px solid #e8ecf4;
  border-radius: 8px;
  font-size: 13px;
  color: #4a4a6a;
}

.selected-file .el-icon {
  color: #4361ee;
}

.file-size {
  margin-left: auto;
  color: #b0b8d8;
  font-size: 12px;
}

/* ── 动画 ── */
.card-list-enter-active,
.card-list-leave-active {
  transition: all 0.3s ease;
}

.card-list-enter-from {
  opacity: 0;
  transform: translateY(-10px);
}

.card-list-leave-to {
  opacity: 0;
  transform: translateX(-20px);
}
</style>
