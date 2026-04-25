<template>
  <div class="app-root">
    <!-- 顶部导航栏 -->
    <header class="app-header">
      <div class="logo">
        <div class="logo-icon">
          <el-icon><Aim /></el-icon>
        </div>
        <div class="logo-text">
          <span class="logo-title">RootKit<span class="logo-accent">Checker</span></span>
          <span class="logo-sub">Memory Forensics Platform</span>
        </div>
      </div>
      <div class="header-right">
        <el-tag type="success" effect="light" size="small" class="status-badge">
          <el-icon><SuccessFilled /></el-icon> 服务运行中
        </el-tag>
      </div>
    </header>

    <!-- 主体：左右分栏 -->
    <div class="app-body">
      <!-- 左侧：镜像列表 -->
      <aside class="sidebar">
        <ImageList
          :selected-id="selectedImage?.id"
          @select="onSelect"
          @uploaded="onUploaded"
        />
      </aside>

      <!-- 右侧：分析结果 -->
      <main class="main-content">
        <ResultPanel
          :image="selectedImage"
          @reanalyze="onReanalyze"
        />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { Aim, SuccessFilled } from '@element-plus/icons-vue'
import { reanalyze } from './api'
import type { ImageRecord } from './api'
import ImageList from './components/ImageList.vue'
import ResultPanel from './components/ResultPanel.vue'
import { ElMessage } from 'element-plus'

const selectedImage = ref<ImageRecord | null>(null)

const onSelect = (img: ImageRecord) => {
  selectedImage.value = img
}

const onUploaded = (img: ImageRecord) => {
  selectedImage.value = img
}

const onReanalyze = async (id: number) => {
  try {
    await reanalyze(id)
    ElMessage.success('已重新提交分析')
  } catch {
    ElMessage.error('操作失败')
  }
}
</script>

<style>
/* ── 全局重置 ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body, #app { height: 100%; overflow: hidden; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC',
               'Microsoft YaHei', sans-serif;
  background: #f0f2f5;
  color: #1a1a2e;
  font-size: 14px;
  -webkit-font-smoothing: antialiased;
}

/* ── Element Plus 浅色主题覆盖 ── */
:root {
  --el-color-primary: #4361ee;
  --el-color-primary-light-3: #6b83f2;
  --el-color-primary-light-5: #8fa5f5;
  --el-color-primary-light-7: #b3c7f8;
  --el-color-primary-light-9: #e8eefe;
  --el-color-primary-dark-2: #3451d1;
  --el-color-danger: #ef233c;
  --el-color-warning: #f77f00;
  --el-color-success: #06d6a0;
  --el-bg-color: #ffffff;
  --el-bg-color-page: #f0f2f5;
  --el-bg-color-overlay: #ffffff;
  --el-text-color-primary: #1a1a2e;
  --el-text-color-regular: #4a4a6a;
  --el-text-color-secondary: #8888aa;
  --el-border-color: #e4e7ed;
  --el-border-color-light: #ebeef5;
  --el-fill-color: #f5f7fa;
  --el-fill-color-light: #fafafa;
  --el-fill-color-blank: #ffffff;
  --el-border-radius-base: 8px;
}

/* ── 应用根布局 ── */
.app-root {
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: #f0f2f5;
}

/* ── 顶部导航 ── */
.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  height: 60px;
  background: #ffffff;
  border-bottom: 1px solid #e8ecf4;
  box-shadow: 0 2px 8px rgba(67, 97, 238, 0.06);
  flex-shrink: 0;
  z-index: 100;
}

.logo {
  display: flex;
  align-items: center;
  gap: 12px;
}

.logo-icon {
  width: 38px;
  height: 38px;
  background: linear-gradient(135deg, #4361ee, #7209b7);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 18px;
  box-shadow: 0 4px 12px rgba(67, 97, 238, 0.3);
}

.logo-text {
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.logo-title {
  font-size: 17px;
  font-weight: 700;
  color: #1a1a2e;
  letter-spacing: -0.3px;
}

.logo-accent {
  color: #4361ee;
}

.logo-sub {
  font-size: 11px;
  color: #8888aa;
  letter-spacing: 0.3px;
  text-transform: uppercase;
}

.status-badge {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
}

/* ── 主体布局 ── */
.app-body {
  display: flex;
  flex: 1;
  overflow: hidden;
  gap: 0;
}

.sidebar {
  width: 300px;
  min-width: 260px;
  background: #ffffff;
  border-right: 1px solid #e8ecf4;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}

.main-content {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  background: #f0f2f5;
}

/* ── Element Plus 全局样式调整 ── */
.el-table {
  border-radius: 8px;
  overflow: hidden;
  font-size: 13px;
}

.el-table th.el-table__cell {
  background: #f8f9fc !important;
  color: #4a4a6a !important;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}

.el-table td.el-table__cell {
  color: #1a1a2e;
}

.el-table--striped .el-table__body tr.el-table__row--striped td.el-table__cell {
  background: #fafbff !important;
}

.el-table__row:hover > td.el-table__cell {
  background: #f0f4ff !important;
}

.el-tabs__nav-wrap::after {
  background-color: #e8ecf4 !important;
  height: 1px !important;
}

.el-tabs__item {
  color: #8888aa !important;
  font-size: 13px !important;
  font-weight: 500;
}

.el-tabs__item.is-active {
  color: #4361ee !important;
  font-weight: 600;
}

.el-tabs__active-bar {
  background-color: #4361ee !important;
  height: 2px !important;
  border-radius: 2px;
}

.el-card {
  border: 1px solid #e8ecf4 !important;
  border-radius: 12px !important;
  box-shadow: 0 2px 8px rgba(0,0,0,0.04) !important;
}

.el-tag {
  border-radius: 6px !important;
  font-weight: 500;
}

.el-button {
  border-radius: 8px !important;
  font-weight: 500;
}

.el-button--primary {
  background: #4361ee !important;
  border-color: #4361ee !important;
}

.el-button--primary:hover {
  background: #3451d1 !important;
  border-color: #3451d1 !important;
}

.el-dialog {
  border-radius: 16px !important;
  box-shadow: 0 20px 60px rgba(0,0,0,0.12) !important;
}

.el-dialog__header {
  padding: 20px 24px 16px !important;
  border-bottom: 1px solid #f0f2f5;
}

.el-dialog__title {
  font-size: 16px !important;
  font-weight: 700 !important;
  color: #1a1a2e !important;
}

.el-dialog__body {
  padding: 20px 24px !important;
}

.el-dialog__footer {
  padding: 16px 24px 20px !important;
  border-top: 1px solid #f0f2f5;
}

.el-upload-dragger {
  border: 2px dashed #d0d7f0 !important;
  border-radius: 12px !important;
  background: #f8f9ff !important;
  transition: all 0.2s;
}

.el-upload-dragger:hover {
  border-color: #4361ee !important;
  background: #f0f4ff !important;
}

.el-select .el-input__wrapper {
  border-radius: 8px !important;
}

.el-popconfirm__main {
  font-size: 13px;
}

/* ── 滚动条美化 ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #d0d7f0; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #b0b8e0; }
</style>
