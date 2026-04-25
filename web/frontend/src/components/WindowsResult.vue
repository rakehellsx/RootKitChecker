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
              title="隐藏进程" severity="critical" icon="hide"
              :count="(data.hidden_processes||[]).length"
              :items="(data.hidden_processes||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
              empty-text="未发现隐藏进程"
              :clickable="true"
              @click="activeTab='hidden_procs'" />
            <DetectCard
              title="进程空洞化" severity="high" icon="warning"
              :count="(data.hollow_processes||[]).length"
              :items="(data.hollow_processes||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
              empty-text="未发现进程空洞化" />
            <DetectCard
              title="隐藏网络连接" severity="critical" icon="connection"
              :count="(data.hidden_connections||[]).length"
              :items="(data.hidden_connections||[]).map((c:any)=>`${c.local_addr||'?'}:${c.local_port||'?'} → ${c.remote_addr||'?'}:${c.remote_port||'?'}`)"
              empty-text="未发现隐藏连接"
              :clickable="true"
              @click="activeTab='hidden_net'" />
            <DetectCard
              title="SSDT 钩子" severity="critical" icon="hook"
              :count="(data.ssdt_hooks||[]).length"
              :items="(data.ssdt_hooks||[]).map((h:any)=>h.name||h.symbol||'未知')"
              empty-text="未发现 SSDT 钩子" />
            <DetectCard
              title="隐藏内核模块" severity="critical" icon="module"
              :count="(data.hidden_modules||[]).length"
              :items="(data.hidden_modules||[]).map((m:any)=>m.name||m.base||'未知')"
              empty-text="未发现隐藏模块" />
            <DetectCard
              title="驱动 IRP 钩子" severity="high" icon="irp"
              :count="(data.driver_irps||kd.driver_irps||[]).filter((x:any)=>x.hooked).length"
              :items="(data.driver_irps||kd.driver_irps||[]).filter((x:any)=>x.hooked).map((x:any)=>`${x.driver_name} / ${x.irp_name}`)"
              empty-text="未发现 IRP 钩子" />
          </div>
        </div>
      </el-tab-pane>

      <!-- ══════════════════════════════════════════
           隐藏进程详情
      ══════════════════════════════════════════ -->
      <el-tab-pane name="hidden_procs">
        <template #label>
          <span class="tab-label">
            <el-icon><Hide /></el-icon>隐藏进程
            <span v-if="(data.hidden_processes||[]).length" class="tab-count danger">
              {{ (data.hidden_processes||[]).length }}
            </span>
          </span>
        </template>
        <div class="table-pane">

          <!-- 威胁横幅 -->
          <div v-if="(data.hidden_processes||[]).length" class="threat-banner">
            <div class="threat-banner-icon"><el-icon><WarningFilled /></el-icon></div>
            <div class="threat-banner-body">
              <div class="threat-banner-title">
                发现 {{ (data.hidden_processes||[]).length }} 个隐藏进程
              </div>
              <div class="threat-banner-desc">
                以下进程未出现在正常进程链表（PsList）中，但通过物理内存扫描（PsScan）或多源交叉比对（PsXView）发现，极可能由 Rootkit 从 EPROCESS 双向链表中摘除以隐藏自身。
              </div>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ (data.hidden_processes||[]).filter((p:any)=>p.in_psscan).length }}</span>
              <span class="stat-label">PsScan 发现</span>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ (data.hidden_processes||[]).filter((p:any)=>p.in_psxview).length }}</span>
              <span class="stat-label">PsXView 发现</span>
            </div>
          </div>

          <!-- 检测方法说明 -->
          <div v-if="(data.hidden_processes||[]).length" class="method-bar">
            <span class="method-label">检测来源说明：</span>
            <span class="method-item"><span class="method-dot dot-green"></span>PsList — 内核链表（正常可见）</span>
            <span class="method-item"><span class="method-dot dot-red"></span>PsScan — 物理内存扫描（绕过链表）</span>
            <span class="method-item"><span class="method-dot dot-orange"></span>PsXView — 多源交叉比对</span>
          </div>

          <!-- 搜索工具栏 -->
          <div v-if="(data.hidden_processes||[]).length" class="table-toolbar">
            <el-input v-model="hiddenProcSearch" placeholder="搜索进程名 / PID / 路径…" clearable size="small" class="search-input">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <span class="toolbar-hint">共 {{ filteredHiddenProcs.length }} 条</span>
          </div>

          <!-- 主表格 -->
          <el-table
            v-if="(data.hidden_processes||[]).length"
            :data="filteredHiddenProcs"
            stripe size="small" class="data-table threat-table" border
            :header-cell-style="headerStyle"
            row-key="pid">
            <el-table-column type="index" label="#" width="42" align="center" />

            <!-- PID -->
            <el-table-column prop="pid" label="PID" width="80" sortable>
              <template #default="{ row }">
                <span class="pid-badge danger-pid">{{ row.pid ?? '-' }}</span>
              </template>
            </el-table-column>

            <!-- PPID -->
            <el-table-column prop="ppid" label="父PID" width="72" align="center">
              <template #default="{ row }">
                <span class="muted-val">{{ row.ppid ?? '-' }}</span>
              </template>
            </el-table-column>

            <!-- 进程名 -->
            <el-table-column prop="name" label="进程名称" min-width="140" show-overflow-tooltip>
              <template #default="{ row }">
                <div class="proc-name-cell">
                  <el-icon class="proc-icon-danger"><Warning /></el-icon>
                  <span class="proc-name-danger">{{ row.name || '(未知)' }}</span>
                </div>
              </template>
            </el-table-column>

            <!-- 可见性矩阵 -->
            <el-table-column label="可见性矩阵" width="190" align="center">
              <template #header>
                <div class="matrix-header">
                  <span>PsList</span><span>PsScan</span><span>PsXView</span>
                </div>
              </template>
              <template #default="{ row }">
                <div class="visibility-matrix">
                  <span class="vis-cell" :class="row.in_pslist ? 'vis-yes' : 'vis-no'">
                    <el-icon v-if="row.in_pslist"><CircleCheckFilled /></el-icon>
                    <el-icon v-else><CircleCloseFilled /></el-icon>
                  </span>
                  <span class="vis-cell" :class="row.in_psscan ? 'vis-yes' : 'vis-no'">
                    <el-icon v-if="row.in_psscan"><CircleCheckFilled /></el-icon>
                    <el-icon v-else><CircleCloseFilled /></el-icon>
                  </span>
                  <span class="vis-cell" :class="row.in_psxview ? 'vis-yes' : 'vis-no'">
                    <el-icon v-if="row.in_psxview"><CircleCheckFilled /></el-icon>
                    <el-icon v-else><CircleCloseFilled /></el-icon>
                  </span>
                </div>
              </template>
            </el-table-column>

            <!-- EPROCESS -->
            <el-table-column prop="offset" label="EPROCESS" width="170">
              <template #default="{ row }">
                <span class="mono-addr">{{ row.offset || '-' }}</span>
              </template>
            </el-table-column>

            <!-- 线程/句柄 -->
            <el-table-column label="线程/句柄" width="90" align="center">
              <template #default="{ row }">
                <span class="num-pair">
                  <span class="num-val">{{ row.threads ?? '-' }}</span>
                  <span class="num-sep">/</span>
                  <span class="num-val">{{ row.handles ?? '-' }}</span>
                </span>
              </template>
            </el-table-column>

            <!-- 会话ID -->
            <el-table-column prop="session_id" label="会话" width="60" align="center">
              <template #default="{ row }">
                <span class="muted-val">{{ row.session_id ?? '-' }}</span>
              </template>
            </el-table-column>

            <!-- 完整性 -->
            <el-table-column prop="integrity" label="完整性" width="90" align="center">
              <template #default="{ row }">
                <span v-if="row.integrity" class="integrity-badge" :class="integrityClass(row.integrity)">
                  {{ row.integrity }}
                </span>
                <span v-else class="muted-val">-</span>
              </template>
            </el-table-column>

            <!-- 创建时间 -->
            <el-table-column prop="create_time" label="创建时间" width="150" show-overflow-tooltip>
              <template #default="{ row }">
                <span class="time-val">{{ row.create_time || '-' }}</span>
              </template>
            </el-table-column>

            <!-- 展开行：路径 + 命令行 -->
            <el-table-column type="expand" width="30">
              <template #default="{ row }">
                <div class="expand-detail">
                  <div class="detail-row">
                    <span class="detail-label">镜像路径</span>
                    <span class="detail-value mono-addr">{{ row.image_path || '(未知)' }}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">命令行</span>
                    <span class="detail-value cmdline-val">{{ row.cmdline || '(未知)' }}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">检测来源</span>
                    <span class="source-badge" :class="sourceBadgeClass(row.source)">
                      <el-icon><CircleCloseFilled /></el-icon>{{ row.source || '未知' }}
                    </span>
                  </div>
                </div>
              </template>
            </el-table-column>

            <!-- 风险 -->
            <el-table-column label="风险" width="72" align="center">
              <template #default>
                <span class="risk-badge risk-critical">高危</span>
              </template>
            </el-table-column>
          </el-table>

          <!-- 空状态 -->
          <div v-if="!(data.hidden_processes||[]).length" class="empty-state safe-state">
            <el-icon><CircleCheckFilled /></el-icon>
            <span>未发现隐藏进程，系统进程链表完整</span>
          </div>
        </div>
      </el-tab-pane>

      <!-- ══════════════════════════════════════════
           隐藏网络连接详情
      ══════════════════════════════════════════ -->
      <el-tab-pane name="hidden_net">
        <template #label>
          <span class="tab-label">
            <el-icon><Connection /></el-icon>隐藏连接
            <span v-if="(data.hidden_connections||[]).length" class="tab-count danger">
              {{ (data.hidden_connections||[]).length }}
            </span>
          </span>
        </template>
        <div class="table-pane">

          <!-- 威胁横幅 -->
          <div v-if="(data.hidden_connections||[]).length" class="threat-banner">
            <div class="threat-banner-icon"><el-icon><WarningFilled /></el-icon></div>
            <div class="threat-banner-body">
              <div class="threat-banner-title">
                发现 {{ (data.hidden_connections||[]).length }} 个隐藏网络连接
              </div>
              <div class="threat-banner-desc">
                以下连接仅在 NetScan（物理内存扫描）中发现，未出现在 NetStat（内核连接表）中，可能被 Rootkit 从网络连接表中摘除，用于隐藏 C2 通信或数据外泄通道。
              </div>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ (data.hidden_connections||[]).filter((c:any)=>c.state==='ESTABLISHED').length }}</span>
              <span class="stat-label">已建立连接</span>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ (data.hidden_connections||[]).filter((c:any)=>c.state==='LISTEN').length }}</span>
              <span class="stat-label">监听端口</span>
            </div>
          </div>

          <!-- 检测方法说明 -->
          <div v-if="(data.hidden_connections||[]).length" class="method-bar">
            <span class="method-label">检测来源说明：</span>
            <span class="method-item"><span class="method-dot dot-red"></span>NetScan — 物理内存扫描（可发现隐藏连接）</span>
            <span class="method-item"><span class="method-dot dot-green"></span>NetStat — 内核连接表（正常可见）</span>
          </div>

          <!-- 搜索工具栏 -->
          <div v-if="(data.hidden_connections||[]).length" class="table-toolbar">
            <el-input v-model="hiddenNetSearch" placeholder="搜索 IP / 端口 / 进程…" clearable size="small" class="search-input">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <span class="toolbar-hint">共 {{ filteredHiddenNet.length }} 条</span>
          </div>

          <!-- 主表格 -->
          <el-table
            v-if="(data.hidden_connections||[]).length"
            :data="filteredHiddenNet"
            stripe size="small" class="data-table threat-table" border
            :header-cell-style="headerStyle">
            <el-table-column type="index" label="#" width="42" align="center" />

            <!-- PID + 进程名 -->
            <el-table-column label="进程" width="175">
              <template #default="{ row }">
                <div class="proc-cell">
                  <span class="pid-badge danger-pid">{{ row.pid ?? '-' }}</span>
                  <span class="proc-name-danger">{{ row.process || '(未知)' }}</span>
                </div>
              </template>
            </el-table-column>

            <!-- 协议 -->
            <el-table-column prop="proto" label="协议" width="80" align="center">
              <template #default="{ row }">
                <span class="proto-tag">{{ row.proto || '-' }}</span>
              </template>
            </el-table-column>

            <!-- 本地地址 -->
            <el-table-column label="本地地址" min-width="175">
              <template #default="{ row }">
                <div class="addr-cell">
                  <span class="mono-addr">{{ row.local_addr || '-' }}</span>
                  <span class="port-sep">:</span>
                  <span class="port-num">{{ row.local_port ?? '-' }}</span>
                </div>
              </template>
            </el-table-column>

            <!-- 远端地址（可疑） -->
            <el-table-column label="远端地址（可疑）" min-width="185">
              <template #default="{ row }">
                <div class="addr-cell danger-addr-cell">
                  <el-icon class="addr-warn-icon"><WarningFilled /></el-icon>
                  <span class="mono-addr danger-addr">{{ row.remote_addr || '-' }}</span>
                  <span class="port-sep">:</span>
                  <span class="port-num danger-port">{{ row.remote_port ?? '-' }}</span>
                </div>
              </template>
            </el-table-column>

            <!-- 连接状态 -->
            <el-table-column prop="state" label="状态" width="120" align="center">
              <template #default="{ row }">
                <span class="conn-state" :class="connStateClass(row.state)">{{ row.state || '-' }}</span>
              </template>
            </el-table-column>

            <!-- 可见性矩阵 -->
            <el-table-column label="可见性" width="130" align="center">
              <template #header>
                <div class="matrix-header"><span>NetScan</span><span>NetStat</span></div>
              </template>
              <template #default="{ row }">
                <div class="visibility-matrix">
                  <span class="vis-cell" :class="row.in_netscan !== false ? 'vis-yes' : 'vis-no'">
                    <el-icon v-if="row.in_netscan !== false"><CircleCheckFilled /></el-icon>
                    <el-icon v-else><CircleCloseFilled /></el-icon>
                  </span>
                  <span class="vis-cell" :class="row.in_netstat ? 'vis-yes' : 'vis-no'">
                    <el-icon v-if="row.in_netstat"><CircleCheckFilled /></el-icon>
                    <el-icon v-else><CircleCloseFilled /></el-icon>
                  </span>
                </div>
              </template>
            </el-table-column>

            <!-- 建立时间 -->
            <el-table-column prop="create_time" label="建立时间" width="150" show-overflow-tooltip>
              <template #default="{ row }">
                <span class="time-val">{{ row.create_time || '-' }}</span>
              </template>
            </el-table-column>

            <!-- 展开行：SOCKET偏移 + 检测来源 -->
            <el-table-column type="expand" width="30">
              <template #default="{ row }">
                <div class="expand-detail">
                  <div class="detail-row">
                    <span class="detail-label">SOCKET 偏移</span>
                    <span class="detail-value mono-addr">{{ row.offset || '(未知)' }}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">检测来源</span>
                    <span class="source-badge source-scan">
                      <el-icon><CircleCloseFilled /></el-icon>{{ row.source || '未知' }}
                    </span>
                  </div>
                </div>
              </template>
            </el-table-column>

            <!-- 风险 -->
            <el-table-column label="风险" width="72" align="center">
              <template #default>
                <span class="risk-badge risk-critical">高危</span>
              </template>
            </el-table-column>
          </el-table>

          <!-- 空状态 -->
          <div v-if="!(data.hidden_connections||[]).length" class="empty-state safe-state">
            <el-icon><CircleCheckFilled /></el-icon>
            <span>未发现隐藏网络连接</span>
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
            <span class="toolbar-hint">共 {{ filteredProcs.length }} 条</span>
          </div>
          <el-table :data="filteredProcs" stripe size="small" class="data-table" border
            :header-cell-style="headerStyle" :row-class-name="procRowClass">
            <el-table-column prop="pid"    label="PID"    width="72"  sortable />
            <el-table-column prop="ppid"   label="PPID"   width="72"  sortable />
            <el-table-column prop="name"   label="进程名" min-width="160" show-overflow-tooltip />
            <el-table-column prop="offset" label="EPROCESS" width="175">
              <template #default="{ row }">
                <span class="mono-addr">{{ row.offset || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="threads" label="线程" width="68" sortable />
            <el-table-column prop="handles" label="句柄" width="68" />
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
            <el-icon><Clock /></el-icon>不活跃进程
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
            <el-table-column prop="ppid"      label="PPID"   width="80" />
            <el-table-column prop="name"      label="进程名"  min-width="160" show-overflow-tooltip />
            <el-table-column prop="offset"    label="EPROCESS" width="175">
              <template #default="{ row }">
                <span class="mono-addr">{{ row.offset || '-' }}</span>
              </template>
            </el-table-column>
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
            <span class="toolbar-hint">共 {{ filteredNet.length }} 条</span>
          </div>
          <el-table :data="filteredNet" stripe size="small" class="data-table" border
            :header-cell-style="headerStyle">
            <el-table-column prop="pid"         label="PID"    width="70" />
            <el-table-column prop="process"     label="进程"   width="130" show-overflow-tooltip />
            <el-table-column prop="proto"       label="协议"   width="80" align="center">
              <template #default="{ row }">
                <span class="proto-tag">{{ row.proto || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="本地" min-width="170">
              <template #default="{ row }">
                <span class="mono-addr">{{ row.local_addr || '-' }}</span>
                <span class="port-sep">:</span>
                <span class="port-num">{{ row.local_port ?? '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="远端" min-width="170">
              <template #default="{ row }">
                <span class="mono-addr">{{ row.remote_addr || '-' }}</span>
                <span class="port-sep">:</span>
                <span class="port-num">{{ row.remote_port ?? '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="state" label="状态" width="130" align="center">
              <template #default="{ row }">
                <span class="conn-state" :class="connStateClass(row.state)">{{ row.state || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="create_time" label="创建时间" width="155" show-overflow-tooltip />
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
              <el-table-column prop="base" label="基址"   width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.base }}</span></template>
              </el-table-column>
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
              <el-table-column prop="handler_addr"   label="处理函数" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.handler_addr }}</span></template>
              </el-table-column>
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
              <el-table-column prop="start_addr"  label="起始地址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.start_addr }}</span></template>
              </el-table-column>
              <el-table-column prop="end_addr"    label="结束地址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.end_addr }}</span></template>
              </el-table-column>
              <el-table-column prop="unload_time" label="卸载时间" width="155" />
            </el-table>
          </KernelSection>

          <KernelSection title="内核回调例程" icon-color="#7c3aed" :count="(kd.callbacks||[]).length">
            <template #icon><el-icon><Bell /></el-icon></template>
            <el-table :data="kd.callbacks||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="callback_type" label="回调类型" width="240" />
              <el-table-column prop="callback_addr" label="地址"     width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.callback_addr }}</span></template>
              </el-table-column>
              <el-table-column prop="module"        label="模块"     min-width="160" show-overflow-tooltip />
              <el-table-column prop="symbol"        label="符号"     min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="内核定时器" icon-color="#0078d4" :count="(kd.timers||[]).length">
            <template #icon><el-icon><Timer /></el-icon></template>
            <el-table :data="kd.timers||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle">
              <el-table-column prop="offset"          label="偏移量"   width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.offset }}</span></template>
              </el-table-column>
              <el-table-column prop="period"          label="周期(ms)" width="100" />
              <el-table-column prop="routine_addr"    label="例程地址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.routine_addr }}</span></template>
              </el-table-column>
              <el-table-column prop="routine_module"  label="所属模块" min-width="160" show-overflow-tooltip />
              <el-table-column prop="routine_symbol"  label="符号"     min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>

          <KernelSection title="大页池分配" icon-color="#f77f00" :count="(kd.big_pools||[]).length">
            <template #icon><el-icon><DataLine /></el-icon></template>
            <el-table :data="kd.big_pools||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle"
              :row-class-name="({row}:any) => row.suspicious ? 'row-warn' : ''">
              <el-table-column prop="tag"       label="Tag"    width="80" />
              <el-table-column prop="va"        label="虚拟地址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.va }}</span></template>
              </el-table-column>
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
              <el-table-column prop="start"  label="起始地址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.start }}</span></template>
              </el-table-column>
              <el-table-column prop="end"    label="结束地址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.end }}</span></template>
              </el-table-column>
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
  DataBoard, List, Connection, Cpu, Hide, Grid, Clock,
  Bell, Timer, Operation, DataAnalysis, DataLine,
  InfoFilled, DocumentDelete, Warning, WarningFilled,
  Search, CircleCheckFilled, CircleCloseFilled
} from '@element-plus/icons-vue'
import DetectCard from './DetectCard.vue'
import KernelSection from './KernelSection.vue'
import KVTable from './KVTable.vue'

const props = defineProps<{ data: Record<string, any> }>()
const activeTab = ref('overview')
const kd = computed(() => props.data.windows_kernel_data || {})

const procSearch       = ref('')
const netSearch        = ref('')
const hiddenProcSearch = ref('')
const hiddenNetSearch  = ref('')

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

const filteredHiddenProcs = computed(() => {
  const q = hiddenProcSearch.value.toLowerCase()
  if (!q) return props.data.hidden_processes || []
  return (props.data.hidden_processes || []).filter((p: any) =>
    String(p.pid).includes(q) ||
    (p.name || '').toLowerCase().includes(q) ||
    (p.image_path || '').toLowerCase().includes(q) ||
    (p.cmdline || '').toLowerCase().includes(q)
  )
})

const filteredHiddenNet = computed(() => {
  const q = hiddenNetSearch.value.toLowerCase()
  if (!q) return props.data.hidden_connections || []
  return (props.data.hidden_connections || []).filter((c: any) =>
    (c.local_addr || '').includes(q) ||
    (c.remote_addr || '').includes(q) ||
    String(c.pid || '').includes(q) ||
    (c.process || '').toLowerCase().includes(q)
  )
})

const headerStyle = () => ({
  background: '#f5f7fa',
  color: '#4b5563',
  fontWeight: '700',
  fontSize: '11.5px',
  padding: '9px 0',
  borderBottom: '2px solid #eaecf4',
})

const procRowClass = ({ row }: any) => row.active === false ? 'row-inactive' : ''

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

const sourceBadgeClass = (src: string) => {
  if (!src) return 'source-unknown'
  const s = src.toLowerCase()
  if (s.includes('psscan'))  return 'source-scan'
  if (s.includes('psxview')) return 'source-xview'
  return 'source-unknown'
}

const integrityClass = (level: string) => {
  if (!level) return ''
  const l = level.toLowerCase()
  if (l === 'system') return 'integrity-system'
  if (l === 'high')   return 'integrity-high'
  if (l === 'medium') return 'integrity-medium'
  if (l === 'low')    return 'integrity-low'
  return ''
}
</script>

<style scoped>
.win-result { height: 100%; display: flex; flex-direction: column; overflow: hidden; }

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
  height: 42px; font-size: 12.5px; color: #6b7280;
  padding: 0 14px; transition: color 0.15s;
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
.tab-count.warn   { background: #fef3c7; color: #d97706; }
.tab-count.danger { background: #fee2e2; color: #dc2626; }

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
.toolbar-hint { font-size: 12px; color: #9ca3af; }
.search-input { width: 280px; }
.search-input :deep(.el-input__wrapper) {
  border-radius: 8px !important; background: #f5f7fa;
  box-shadow: none !important; border: 1.5px solid transparent; transition: all 0.2s;
}
.search-input :deep(.el-input__wrapper:hover),
.search-input :deep(.el-input__wrapper.is-focus) {
  border-color: #4361ee !important; background: #fff;
  box-shadow: 0 0 0 3px rgba(67,97,238,0.08) !important;
}

/* ── 威胁横幅 ── */
.threat-banner {
  display: flex; align-items: center; gap: 14px;
  padding: 14px 18px; border-radius: 10px; flex-shrink: 0;
  background: linear-gradient(135deg, #fff5f5 0%, #fef2f2 100%);
  border: 1.5px solid #fca5a5;
}
.threat-banner-icon { font-size: 24px; color: #dc2626; flex-shrink: 0; }
.threat-banner-body { flex: 1; display: flex; flex-direction: column; gap: 3px; }
.threat-banner-title { font-size: 13.5px; font-weight: 700; color: #dc2626; }
.threat-banner-desc  { font-size: 11.5px; color: #7f1d1d; line-height: 1.5; }
.threat-banner-stat {
  display: flex; flex-direction: column; align-items: center;
  padding: 6px 14px; background: rgba(220,38,38,0.08);
  border-radius: 8px; flex-shrink: 0; min-width: 72px;
}
.stat-num   { font-size: 22px; font-weight: 900; color: #dc2626; line-height: 1; }
.stat-label { font-size: 10.5px; color: #9ca3af; margin-top: 2px; white-space: nowrap; }

/* ── 检测方法说明栏 ── */
.method-bar {
  display: flex; gap: 16px; align-items: center;
  padding: 7px 14px; background: #f8faff;
  border: 1px solid #e8ecf8; border-radius: 8px;
  flex-shrink: 0; flex-wrap: wrap;
}
.method-label { font-size: 11.5px; font-weight: 600; color: #4b5563; }
.method-item  { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: #6b7280; }
.method-dot   { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.dot-green  { background: #22c55e; }
.dot-red    { background: #ef4444; }
.dot-orange { background: #f59e0b; }

/* ── 可见性矩阵 ── */
.matrix-header {
  display: flex; justify-content: space-around;
  font-size: 10.5px; font-weight: 700; color: #4b5563;
}
.visibility-matrix {
  display: flex; justify-content: space-around; align-items: center;
}
.vis-cell { font-size: 15px; }
.vis-yes  { color: #22c55e; }
.vis-no   { color: #ef4444; }

/* ── 数据表格 ── */
.data-table { border-radius: 9px; overflow: hidden; flex: 1; }
.threat-table :deep(.el-table__body-wrapper) { background: #fffbfb; }
.data-table :deep(.el-table__header th) {
  background: #f5f7fa !important; color: #4b5563 !important;
  font-weight: 700 !important; font-size: 11.5px !important;
  padding: 9px 0 !important; border-bottom: 2px solid #eaecf4 !important;
}
.data-table :deep(.el-table__row > td) {
  font-size: 12px; color: #374151; padding: 8px 0;
}
.data-table :deep(.el-table__row:hover > td) { background: #f0f4ff !important; }
:deep(.row-danger > td)   { background: #fff5f5 !important; }
:deep(.row-warn > td)     { background: #fffbf0 !important; }
:deep(.row-inactive > td) { opacity: 0.6; }

/* ── 展开行详情 ── */
.expand-detail {
  padding: 10px 20px 10px 50px;
  background: #fafbff;
  display: flex; flex-direction: column; gap: 8px;
}
.detail-row { display: flex; align-items: flex-start; gap: 12px; }
.detail-label {
  flex-shrink: 0; width: 80px;
  font-size: 11px; font-weight: 700; color: #9ca3af;
  padding-top: 1px;
}
.detail-value { font-size: 12px; color: #374151; word-break: break-all; }
.cmdline-val  { font-family: 'Courier New', monospace; font-size: 11.5px; color: #374151; }

/* ── 特殊单元格 ── */
.pid-badge {
  display: inline-block; padding: 1px 8px;
  background: #eef2ff; color: #4361ee;
  border-radius: 5px; font-size: 11.5px; font-weight: 700;
  font-family: monospace;
}
.danger-pid { background: #fee2e2; color: #dc2626; }

.proc-cell { display: flex; align-items: center; gap: 6px; }
.proc-name-cell { display: flex; align-items: center; gap: 5px; }
.proc-icon-danger { color: #dc2626; font-size: 13px; flex-shrink: 0; }
.proc-name-danger { font-weight: 700; color: #dc2626; font-size: 12.5px; }

.addr-cell { display: flex; align-items: center; gap: 2px; }
.danger-addr-cell { gap: 3px; }
.addr-warn-icon { color: #f59e0b; font-size: 12px; flex-shrink: 0; }

.mono-addr    { font-family: 'Courier New', monospace; font-size: 11.5px; color: #374151; }
.danger-addr  { color: #dc2626; font-weight: 600; }
.muted-val    { color: #9ca3af; font-size: 11.5px; }
.time-val     { font-size: 11.5px; color: #6b7280; }
.num-val      { font-family: monospace; font-size: 12px; color: #374151; }
.num-pair     { display: flex; align-items: center; gap: 2px; }
.num-sep      { color: #d1d5db; font-size: 11px; }
.port-sep     { color: #9ca3af; font-size: 11px; margin: 0 1px; }
.port-num     { font-family: monospace; font-size: 11.5px; color: #6366f1; font-weight: 700; }
.danger-port  { color: #dc2626; }

/* 完整性级别 */
.integrity-badge {
  display: inline-block; padding: 1px 7px;
  border-radius: 4px; font-size: 10.5px; font-weight: 700;
}
.integrity-system { background: #fee2e2; color: #dc2626; }
.integrity-high   { background: #fef3c7; color: #d97706; }
.integrity-medium { background: #dbeafe; color: #1d4ed8; }
.integrity-low    { background: #f3f4f6; color: #6b7280; }

/* 检测来源徽章 */
.source-badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 8px; border-radius: 5px;
  font-size: 10.5px; font-weight: 700;
}
.source-scan    { background: #fee2e2; color: #dc2626; }
.source-xview   { background: #fef3c7; color: #d97706; }
.source-unknown { background: #f3f4f6; color: #6b7280; }

/* 风险等级 */
.risk-badge {
  display: inline-block; padding: 2px 9px;
  border-radius: 5px; font-size: 10.5px; font-weight: 700;
}
.risk-critical { background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; }
.risk-high     { background: #fef3c7; color: #d97706; border: 1px solid #fde68a; }

/* 空状态 */
.empty-state {
  display: flex; align-items: center; justify-content: center;
  gap: 10px; padding: 40px; border-radius: 10px;
  font-size: 14px; font-weight: 500;
}
.safe-state { background: #f0fdf4; color: #15803d; border: 1.5px solid #bbf7d0; }
.safe-state .el-icon { font-size: 22px; }

/* 提示条 */
.pane-tip {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 14px; border-radius: 8px;
  font-size: 12px; flex-shrink: 0;
}
.warn-tip { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }

/* 状态点 */
.status-dot {
  display: inline-block; width: 7px; height: 7px;
  border-radius: 50%; margin-right: 5px; vertical-align: middle;
}
.dot-green { background: #22c55e; box-shadow: 0 0 0 2px #dcfce7; }
.dot-gray  { background: #9ca3af; }
.status-text { font-size: 11.5px; vertical-align: middle; }

/* 协议标签 */
.proto-tag {
  display: inline-block; padding: 1px 7px;
  background: #eef2ff; color: #4361ee;
  border-radius: 4px; font-size: 10.5px; font-weight: 700;
}

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
.kernel-pane { display: flex; flex-direction: column; gap: 10px; padding: 14px 16px; }
.inner-table { border-radius: 8px; overflow: hidden; }
.inner-table :deep(.el-table__header th) {
  background: #f5f7fa !important; color: #4b5563 !important;
  font-weight: 700 !important; font-size: 11.5px !important; padding: 8px 0 !important;
}
.inner-table :deep(.el-table__row > td) {
  font-size: 11.5px; color: #374151; padding: 6px 0;
}
.inner-table :deep(.el-table__row:hover > td) { background: #f0f4ff !important; }

.no-data {
  display: flex; align-items: center; justify-content: center;
  gap: 8px; padding: 60px; color: #9ca3af; font-size: 14px;
}
.muted { color: #d1d5db; }
.uid-root { color: #dc2626; font-weight: 700; }
</style>
