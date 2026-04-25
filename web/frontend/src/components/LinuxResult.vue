<template>
  <div class="linux-result">
    <el-tabs v-model="activeTab" class="result-tabs">

      <!-- 检测摘要 -->
      <el-tab-pane name="overview">
        <template #label>
          <span class="tab-label"><el-icon><DataBoard /></el-icon>检测摘要</span>
        </template>
        <div class="overview-wrap">
          <div class="detect-grid">
            <DetectCard title="隐藏进程" severity="critical" icon="hide"
              :count="(data.hidden_processes_linux||[]).length"
              :items="(data.hidden_processes_linux||[]).map((p:any)=>`PID ${p.pid} — ${p.name||'?'}`)"
              empty-text="未发现隐藏进程" :clickable="true" @click="activeTab='hidden_procs'" />
            <DetectCard title="系统调用钩子" severity="critical" icon="hook"
              :count="(data.syscall_hooks||[]).length"
              :items="(data.syscall_hooks||[]).map((h:any)=>`#${h.index} → ${h.module||h.symbol||'?'}`)"
              empty-text="未发现系统调用钩子" />
            <DetectCard title="IDT 钩子" severity="critical" icon="irp"
              :count="(data.idt_hooks||[]).length"
              :items="(data.idt_hooks||[]).map((h:any)=>`#${h.index} → ${h.module||'?'}`)"
              empty-text="未发现 IDT 钩子" />
            <DetectCard title="隐藏网络连接" severity="critical" icon="connection"
              :count="(data.hidden_connections||[]).length"
              :items="(data.hidden_connections||[]).map((c:any)=>`${c.local_addr||'?'}:${c.local_port||'?'} → ${c.foreign_addr||c.remote_addr||'?'}:${c.foreign_port||c.remote_port||'?'}`)"
              empty-text="未发现隐藏连接" :clickable="true" @click="activeTab='hidden_net'" />
            <DetectCard title="隐藏内核模块" severity="critical" icon="module"
              :count="(data.hidden_modules_linux||[]).length"
              :items="(data.hidden_modules_linux||[]).map((m:any)=>m.name||m.base||'?')"
              empty-text="未发现隐藏模块" />
            <DetectCard title="凭据异常" severity="high" icon="warning"
              :count="(data.cred_anomalies||[]).length"
              :items="(data.cred_anomalies||[]).map((c:any)=>`PID ${c.pid} — ${c.name||'?'}`)"
              empty-text="未发现凭据异常" />
            <DetectCard title="afinfo 篡改" severity="critical" icon="hook"
              :count="(data.afinfo_hooks||[]).length"
              :items="(data.afinfo_hooks||[]).map((h:any)=>h.symbol||h.module||'?')"
              empty-text="未发现 afinfo 篡改" />
            <DetectCard title="Netfilter 钩子" severity="medium" icon="connection"
              :count="(data.netfilter_hooks||[]).length"
              :items="(data.netfilter_hooks||[]).map((h:any)=>`${h.chain||'?'} → ${h.module||'?'}`)"
              empty-text="未发现 Netfilter 钩子" />
            <DetectCard title="TTY 钩子" severity="high" icon="hook"
              :count="(data.tty_hooks||[]).length"
              :items="(data.tty_hooks||[]).map((h:any)=>h.module||h.symbol||'?')"
              empty-text="未发现 TTY 钩子" />
            <DetectCard title="键盘钩子" severity="critical" icon="keyboard"
              :count="(data.keyboard_notifiers||[]).length"
              :items="(data.keyboard_notifiers||[]).map((h:any)=>h.module||h.symbol||'?')"
              empty-text="未发现键盘钩子（键盘记录器）" />
          </div>
        </div>
      </el-tab-pane>

      <!-- 隐藏进程详情 -->
      <el-tab-pane name="hidden_procs">
        <template #label>
          <span class="tab-label">
            <el-icon><Hide /></el-icon>隐藏进程
            <span v-if="hiddenProcs.length" class="tab-count danger">{{ hiddenProcs.length }}</span>
          </span>
        </template>
        <div class="table-pane">

          <!-- 威胁横幅 -->
          <div v-if="hiddenProcs.length" class="threat-banner">
            <div class="threat-banner-icon"><el-icon><WarningFilled /></el-icon></div>
            <div class="threat-banner-body">
              <div class="threat-banner-title">发现 {{ hiddenProcs.length }} 个隐藏进程</div>
              <div class="threat-banner-desc">
                以下进程未出现在内核 task_struct 链表（pslist）中，但通过物理内存扫描（psscan）或 PID 哈希表（pidhashtable）发现，极可能被 Rootkit 从进程链表中摘除以隐藏自身。
              </div>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ hiddenProcs.filter((p:any)=>p.in_psscan).length }}</span>
              <span class="stat-label">PsScan 发现</span>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ hiddenProcs.filter((p:any)=>p.in_pidhashtable).length }}</span>
              <span class="stat-label">PidHash 发现</span>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ hiddenProcs.filter((p:any)=>p.uid===0).length }}</span>
              <span class="stat-label">root 权限</span>
            </div>
          </div>

          <!-- 检测方法说明 -->
          <div v-if="hiddenProcs.length" class="method-bar">
            <span class="method-label">检测来源：</span>
            <span class="method-item"><span class="method-dot dot-pslist"></span>pslist — task_struct 链表（正常可见）</span>
            <span class="method-item"><span class="method-dot dot-psscan"></span>psscan — 物理内存扫描（绕过链表）</span>
            <span class="method-item"><span class="method-dot dot-pidhash"></span>pidhashtable — PID 哈希表扫描</span>
          </div>

          <!-- 搜索工具栏 -->
          <div v-if="hiddenProcs.length" class="table-toolbar">
            <el-input v-model="hiddenProcSearch" placeholder="搜索进程名 / PID / 路径…" clearable size="small" class="search-input">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <span class="toolbar-hint">共 {{ filteredHiddenProcs.length }} 条</span>
          </div>

          <!-- 主表格 -->
          <el-table v-if="hiddenProcs.length"
            :data="filteredHiddenProcs" stripe size="small"
            class="data-table threat-table" border :header-cell-style="headerStyle" row-key="pid">
            <el-table-column type="index" label="#" width="42" align="center" />
            <el-table-column prop="pid" label="PID" width="80" sortable>
              <template #default="{ row }"><span class="pid-badge danger-pid">{{ row.pid }}</span></template>
            </el-table-column>
            <el-table-column prop="ppid" label="父PID" width="72" align="center">
              <template #default="{ row }"><span class="muted-val">{{ row.ppid ?? '-' }}</span></template>
            </el-table-column>
            <el-table-column label="进程名称" min-width="145" show-overflow-tooltip>
              <template #default="{ row }">
                <div class="proc-name-cell">
                  <el-icon class="proc-icon-danger"><Warning /></el-icon>
                  <span class="proc-name-danger">{{ row.name || row.comm || '(未知)' }}</span>
                </div>
              </template>
            </el-table-column>
            <!-- 可见性矩阵 -->
            <el-table-column label="可见性矩阵" width="195" align="center">
              <template #header>
                <div class="matrix-header"><span>pslist</span><span>psscan</span><span>pidhash</span></div>
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
                  <span class="vis-cell" :class="row.in_pidhashtable ? 'vis-yes' : 'vis-no'">
                    <el-icon v-if="row.in_pidhashtable"><CircleCheckFilled /></el-icon>
                    <el-icon v-else><CircleCloseFilled /></el-icon>
                  </span>
                </div>
              </template>
            </el-table-column>
            <el-table-column prop="task_offset" label="task_struct" width="175">
              <template #default="{ row }"><span class="mono-addr">{{ row.task_offset || '-' }}</span></template>
            </el-table-column>
            <el-table-column label="UID / GID" width="100" align="center">
              <template #default="{ row }">
                <span :class="row.uid === 0 ? 'uid-root' : 'muted-val'">{{ row.uid ?? '-' }}</span>
                <span class="muted-val"> / </span>
                <span class="muted-val">{{ row.gid ?? '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="state" label="状态" width="65" align="center">
              <template #default="{ row }">
                <span class="proc-state-badge" :class="procStateClass(row.state)">{{ row.state || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="start_time" label="启动时间" width="150" show-overflow-tooltip>
              <template #default="{ row }"><span class="time-val">{{ row.start_time || '-' }}</span></template>
            </el-table-column>
            <!-- 展开行：路径 + 命令行 + 来源 -->
            <el-table-column type="expand" width="30">
              <template #default="{ row }">
                <div class="expand-detail">
                  <div class="detail-row">
                    <span class="detail-label">可执行路径</span>
                    <span class="detail-value mono-addr">{{ row.exe || '(未知)' }}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">命令行</span>
                    <span class="detail-value cmdline-val">{{ row.cmdline || '(未知)' }}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">EUID / EGID</span>
                    <span class="detail-value">
                      <span :class="row.euid === 0 ? 'uid-root' : ''">{{ row.euid ?? '-' }}</span>
                      <span class="muted-val"> / {{ row.egid ?? '-' }}</span>
                    </span>
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
            <el-table-column label="风险" width="72" align="center">
              <template #default><span class="risk-badge risk-critical">高危</span></template>
            </el-table-column>
          </el-table>

          <div v-if="!hiddenProcs.length" class="empty-state safe-state">
            <el-icon><CircleCheckFilled /></el-icon><span>未发现隐藏进程，内核进程链表完整</span>
          </div>
        </div>
      </el-tab-pane>

      <!-- 隐藏网络连接详情 -->
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
              <div class="threat-banner-title">发现 {{ (data.hidden_connections||[]).length }} 个隐藏网络连接</div>
              <div class="threat-banner-desc">
                以下连接通过 afinfo 结构扫描（check_afinfo）发现，未出现在正常网络连接表中，可能被 Rootkit 篡改 tcp_seq_ops/udp_seq_ops 的 show 函数指针以隐藏 C2 通信或数据外泄通道。
              </div>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ (data.hidden_connections||[]).filter((c:any)=>c.state==='ESTABLISHED').length }}</span>
              <span class="stat-label">已建立连接</span>
            </div>
            <div class="threat-banner-stat">
              <span class="stat-num">{{ (data.hidden_connections||[]).filter((c:any)=>c.uid===0).length }}</span>
              <span class="stat-label">root 权限</span>
            </div>
          </div>

          <!-- 检测方法说明 -->
          <div v-if="(data.hidden_connections||[]).length" class="method-bar">
            <span class="method-label">检测来源：</span>
            <span class="method-item"><span class="method-dot dot-psscan"></span>check_afinfo — afinfo 结构扫描（可发现隐藏连接）</span>
            <span class="method-item"><span class="method-dot dot-pslist"></span>netstat — 内核连接表（正常可见）</span>
          </div>

          <!-- 搜索工具栏 -->
          <div v-if="(data.hidden_connections||[]).length" class="table-toolbar">
            <el-input v-model="hiddenNetSearch" placeholder="搜索 IP / 端口 / 进程…" clearable size="small" class="search-input">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <span class="toolbar-hint">共 {{ filteredHiddenNet.length }} 条</span>
          </div>

          <!-- 主表格 -->
          <el-table v-if="(data.hidden_connections||[]).length"
            :data="filteredHiddenNet" stripe size="small"
            class="data-table threat-table" border :header-cell-style="headerStyle">
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
            <el-table-column prop="proto" label="协议" width="72" align="center">
              <template #default="{ row }"><span class="proto-tag">{{ row.proto || '-' }}</span></template>
            </el-table-column>
            <el-table-column label="本地地址" min-width="165">
              <template #default="{ row }">
                <div class="addr-cell">
                  <span class="mono-addr">{{ row.local_addr || '-' }}</span>
                  <span class="port-sep">:</span>
                  <span class="port-num">{{ row.local_port ?? '-' }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="远端地址（可疑）" min-width="185">
              <template #default="{ row }">
                <div class="addr-cell danger-addr-cell">
                  <el-icon class="addr-warn-icon"><WarningFilled /></el-icon>
                  <span class="mono-addr danger-addr">{{ row.foreign_addr || row.remote_addr || '-' }}</span>
                  <span class="port-sep">:</span>
                  <span class="port-num danger-port">{{ row.foreign_port ?? row.remote_port ?? '-' }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column prop="state" label="状态" width="120" align="center">
              <template #default="{ row }">
                <span class="conn-state" :class="connStateClass(row.state)">{{ row.state || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="uid" label="UID" width="65" align="center">
              <template #default="{ row }">
                <span :class="row.uid === 0 ? 'uid-root' : 'muted-val'">{{ row.uid ?? '-' }}</span>
              </template>
            </el-table-column>
            <!-- 可见性矩阵 -->
            <el-table-column label="可见性" width="140" align="center">
              <template #header>
                <div class="matrix-header"><span>afinfo</span><span>netstat</span></div>
              </template>
              <template #default="{ row }">
                <div class="visibility-matrix">
                  <span class="vis-cell" :class="row.in_afinfo !== false ? 'vis-yes' : 'vis-no'">
                    <el-icon v-if="row.in_afinfo !== false"><CircleCheckFilled /></el-icon>
                    <el-icon v-else><CircleCloseFilled /></el-icon>
                  </span>
                  <span class="vis-cell" :class="row.in_netstat ? 'vis-yes' : 'vis-no'">
                    <el-icon v-if="row.in_netstat"><CircleCheckFilled /></el-icon>
                    <el-icon v-else><CircleCloseFilled /></el-icon>
                  </span>
                </div>
              </template>
            </el-table-column>
            <!-- 展开行：Inode + 网络命名空间 + 来源 -->
            <el-table-column type="expand" width="30">
              <template #default="{ row }">
                <div class="expand-detail">
                  <div class="detail-row">
                    <span class="detail-label">Inode</span>
                    <span class="detail-value mono-addr">{{ row.inode ?? '(未知)' }}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">网络命名空间</span>
                    <span class="detail-value mono-addr">{{ row.net_ns || '(未知)' }}</span>
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
            <el-table-column label="风险" width="72" align="center">
              <template #default><span class="risk-badge risk-critical">高危</span></template>
            </el-table-column>
          </el-table>

          <div v-if="!(data.hidden_connections||[]).length" class="empty-state safe-state">
            <el-icon><CircleCheckFilled /></el-icon><span>未发现隐藏网络连接</span>
          </div>
        </div>
      </el-tab-pane>

      <!-- 进程列表 -->
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
            <span class="toolbar-hint">共 {{ filteredProcs.length }} 条</span>
          </div>
          <el-table :data="filteredProcs" stripe size="small" class="data-table" border :header-cell-style="headerStyle">
            <el-table-column type="expand" width="30">
              <template #default="{ row }">
                <div class="expand-detail">
                  <div class="detail-row"><span class="detail-label">可执行路径</span><span class="detail-value mono-addr">{{ row.exe || '(未知)' }}</span></div>
                  <div class="detail-row"><span class="detail-label">命令行</span><span class="detail-value cmdline-val">{{ row.cmdline || '(未知)' }}</span></div>
                  <div class="detail-row"><span class="detail-label">task_struct 偏移</span><span class="detail-value mono-addr">{{ row.task_offset || '(未知)' }}</span></div>
                  <div class="detail-row"><span class="detail-label">EUID / EGID</span><span class="detail-value"><span :class="row.euid===0?'uid-root':''" >{{ row.euid ?? '-' }}</span><span class="muted-val"> / {{ row.egid ?? '-' }}</span></span></div>
                </div>
              </template>
            </el-table-column>
            <el-table-column prop="pid"        label="PID"   width="72" sortable>
              <template #default="{ row }"><span class="pid-badge">{{ row.pid }}</span></template>
            </el-table-column>
            <el-table-column prop="ppid"       label="PPID"  width="72" sortable />
            <el-table-column prop="name"       label="进程名" min-width="160" show-overflow-tooltip />
            <el-table-column prop="uid"        label="UID"   width="65">
              <template #default="{ row }">
                <span :class="row.uid === 0 ? 'uid-root' : ''">{{ row.uid ?? '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="gid"        label="GID"   width="65" />
            <el-table-column prop="state"      label="状态"  width="65" align="center">
              <template #default="{ row }">
                <span class="proc-state-badge" :class="procStateClass(row.state)">{{ row.state || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="start_time" label="启动时间" width="155" show-overflow-tooltip />
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 网络连接 -->
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
            <span class="toolbar-hint">共 {{ filteredNet.length }} 条</span>
          </div>
          <el-table :data="filteredNet" stripe size="small" class="data-table" border :header-cell-style="headerStyle">
            <el-table-column type="expand" width="30">
              <template #default="{ row }">
                <div class="expand-detail">
                  <div class="detail-row"><span class="detail-label">Inode</span><span class="detail-value mono-addr">{{ row.inode ?? '(未知)' }}</span></div>
                  <div class="detail-row"><span class="detail-label">网络命名空间</span><span class="detail-value mono-addr">{{ row.net_ns || '(未知)' }}</span></div>
                  <div class="detail-row"><span class="detail-label">UID</span><span class="detail-value"><span :class="row.uid===0?'uid-root':''" >{{ row.uid ?? '-' }}</span></span></div>
                </div>
              </template>
            </el-table-column>
            <el-table-column prop="pid"     label="PID"  width="70">
              <template #default="{ row }"><span class="pid-badge">{{ row.pid ?? '-' }}</span></template>
            </el-table-column>
            <el-table-column prop="process" label="进程" width="130" show-overflow-tooltip />
            <el-table-column prop="proto"   label="协议" width="80" align="center">
              <template #default="{ row }"><span class="proto-tag">{{ row.proto || '-' }}</span></template>
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
                <span class="mono-addr">{{ row.remote_addr || row.foreign_addr || '-' }}</span>
                <span class="port-sep">:</span>
                <span class="port-num">{{ row.remote_port ?? row.foreign_port ?? '-' }}</span>
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

      <!-- 内核数据 -->
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
            <div class="boot-time-box">
              <el-icon><Timer /></el-icon><span>{{ kd.boot_time || '未知' }}</span>
            </div>
          </KernelSection>
          <KernelSection title="已加载内核模块" icon-color="#4361ee" :count="(kd.loaded_modules||[]).length">
            <template #icon><el-icon><Grid /></el-icon></template>
            <el-table :data="kd.loaded_modules||[]" stripe size="small" border class="inner-table" :header-cell-style="headerStyle">
              <el-table-column prop="name" label="模块名" min-width="160" />
              <el-table-column prop="base" label="基址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.base }}</span></template>
              </el-table-column>
              <el-table-column prop="size" label="大小" width="90" :formatter="sizeFmt" />
            </el-table>
          </KernelSection>
          <KernelSection title="内核线程" icon-color="#7c3aed" :count="(kd.kernel_threads||[]).length">
            <template #icon><el-icon><List /></el-icon></template>
            <el-table :data="kd.kernel_threads||[]" stripe size="small" border class="inner-table" :header-cell-style="headerStyle">
              <el-table-column prop="pid"   label="PID"  width="80" />
              <el-table-column prop="name"  label="名称" min-width="160" />
              <el-table-column prop="state" label="状态" width="80" align="center">
                <template #default="{ row }"><span class="proc-state-badge">{{ row.state || '-' }}</span></template>
              </el-table-column>
            </el-table>
          </KernelSection>
          <KernelSection title="eBPF 程序" icon-color="#ef233c" :count="(kd.ebpf_programs||[]).length">
            <template #icon><el-icon><Operation /></el-icon></template>
            <el-table :data="kd.ebpf_programs||[]" stripe size="small" border class="inner-table" :header-cell-style="headerStyle">
              <el-table-column prop="id"        label="ID"   width="70" />
              <el-table-column prop="type"      label="类型" width="120" />
              <el-table-column prop="name"      label="名称" min-width="160" />
              <el-table-column prop="tag"       label="Tag"  width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.tag }}</span></template>
              </el-table-column>
              <el-table-column prop="load_time" label="加载时间" width="155" />
            </el-table>
          </KernelSection>
          <KernelSection title="Netfilter 钩子" icon-color="#f77f00" :count="(kd.netfilter_hooks||[]).length">
            <template #icon><el-icon><Connection /></el-icon></template>
            <el-table :data="kd.netfilter_hooks||[]" stripe size="small" border class="inner-table" :header-cell-style="headerStyle">
              <el-table-column prop="proto"    label="协议"   width="80" />
              <el-table-column prop="table"    label="表"     width="90" />
              <el-table-column prop="chain"    label="链"     width="100" />
              <el-table-column prop="priority" label="优先级" width="80" />
              <el-table-column prop="handler"  label="处理函数" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.handler }}</span></template>
              </el-table-column>
              <el-table-column prop="module"   label="模块"   min-width="160" show-overflow-tooltip />
            </el-table>
          </KernelSection>
          <KernelSection title="I/O 内存映射" icon-color="#0078d4" :count="(kd.iomem||[]).length">
            <template #icon><el-icon><DataLine /></el-icon></template>
            <el-table :data="kd.iomem||[]" stripe size="small" border class="inner-table" :header-cell-style="headerStyle">
              <el-table-column prop="start" label="起始地址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.start }}</span></template>
              </el-table-column>
              <el-table-column prop="end"   label="结束地址" width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.end }}</span></template>
              </el-table-column>
              <el-table-column prop="name"  label="区域名称" min-width="200" />
            </el-table>
          </KernelSection>
          <KernelSection title="挂载点信息" icon-color="#06d6a0" :count="(kd.mount_info||[]).length">
            <template #icon><el-icon><FolderOpened /></el-icon></template>
            <el-table :data="kd.mount_info||[]" stripe size="small" border class="inner-table" :header-cell-style="headerStyle">
              <el-table-column prop="mount_id" label="ID"     width="60" />
              <el-table-column prop="source"   label="设备"   width="160" show-overflow-tooltip />
              <el-table-column prop="target"   label="挂载点" width="160" show-overflow-tooltip />
              <el-table-column prop="fstype"   label="文件系统" width="100" />
              <el-table-column prop="options"  label="选项"   min-width="200" show-overflow-tooltip />
            </el-table>
          </KernelSection>
          <KernelSection title="内核符号表" icon-color="#7c3aed" :count="(kd.kallsyms||[]).length">
            <template #icon><el-icon><Tickets /></el-icon></template>
            <el-table :data="kd.kallsyms||[]" stripe size="small" border class="inner-table" :header-cell-style="headerStyle">
              <el-table-column prop="name"    label="符号名"  min-width="200" />
              <el-table-column prop="address" label="地址"   width="175">
                <template #default="{ row }"><span class="mono-addr">{{ row.address }}</span></template>
              </el-table-column>
              <el-table-column prop="type"    label="类型"   width="70" align="center" />
            </el-table>
          </KernelSection>
          <KernelSection title="内核日志 (kmsg)" icon-color="#ef233c" :count="(kd.kernel_messages||[]).length">
            <template #icon><el-icon><Document /></el-icon></template>
            <el-table :data="kd.kernel_messages||[]" stripe size="small" border class="inner-table"
              :header-cell-style="headerStyle"
              :row-class-name="({row}:any) => row.level === 'warning' || row.level === 'err' ? 'row-warn' : ''">
              <el-table-column prop="timestamp" label="时间戳"  width="120" />
              <el-table-column prop="facility"  label="来源"    width="80" />
              <el-table-column prop="level"     label="级别"    width="80" align="center">
                <template #default="{ row }">
                  <span class="log-level" :class="logLevelClass(row.level)">{{ row.level || '-' }}</span>
                </template>
              </el-table-column>
              <el-table-column prop="message"   label="消息"    min-width="300" show-overflow-tooltip />
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
  DataBoard, List, Connection, Cpu, Hide, Grid, Clock, Timer,
  Operation, DataLine, InfoFilled, Warning, WarningFilled, Search,
  CircleCheckFilled, CircleCloseFilled, FolderOpened, Tickets, Document
} from '@element-plus/icons-vue'
import DetectCard from './DetectCard.vue'
import KernelSection from './KernelSection.vue'
import KVTable from './KVTable.vue'

const props = defineProps<{ data: Record<string, any> }>()
const activeTab = ref('overview')
const kd = computed(() => props.data.linux_kernel_data || {})
const procSearch       = ref('')
const netSearch        = ref('')
const hiddenProcSearch = ref('')
const hiddenNetSearch  = ref('')

const hiddenProcs = computed(() =>
  props.data.hidden_processes_linux || props.data.hidden_processes || []
)

const filteredProcs = computed(() => {
  const q = procSearch.value.toLowerCase()
  if (!q) return props.data.processes_linux || []
  return (props.data.processes_linux || []).filter((p: any) =>
    String(p.pid).includes(q) || (p.name || '').toLowerCase().includes(q))
})

const filteredNet = computed(() => {
  const q = netSearch.value.toLowerCase()
  if (!q) return props.data.network_connections_linux || []
  return (props.data.network_connections_linux || []).filter((c: any) =>
    (c.local_addr || '').includes(q) || (c.remote_addr || '').includes(q) ||
    (c.process || '').toLowerCase().includes(q))
})

const filteredHiddenProcs = computed(() => {
  const q = hiddenProcSearch.value.toLowerCase()
  if (!q) return hiddenProcs.value
  return hiddenProcs.value.filter((p: any) =>
    String(p.pid).includes(q) ||
    (p.name || p.comm || '').toLowerCase().includes(q) ||
    (p.exe || '').toLowerCase().includes(q) ||
    (p.cmdline || '').toLowerCase().includes(q)
  )
})

const filteredHiddenNet = computed(() => {
  const q = hiddenNetSearch.value.toLowerCase()
  if (!q) return props.data.hidden_connections || []
  return (props.data.hidden_connections || []).filter((c: any) =>
    (c.local_addr || '').includes(q) ||
    (c.foreign_addr || c.remote_addr || '').includes(q) ||
    String(c.pid || '').includes(q) ||
    (c.process || '').toLowerCase().includes(q)
  )
})

const headerStyle = () => ({
  background: '#f5f7fa', color: '#4b5563', fontWeight: '700',
  fontSize: '11.5px', padding: '9px 0', borderBottom: '2px solid #eaecf4',
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

const sourceBadgeClass = (src: string) => {
  if (!src) return 'source-unknown'
  const s = src.toLowerCase()
  if (s.includes('psscan'))       return 'source-scan'
  if (s.includes('pidhashtable')) return 'source-pidhash'
  return 'source-unknown'
}

const procStateClass = (s: string) => {
  if (!s) return 'state-default-p'
  const u = s.toUpperCase()
  if (u === 'R') return 'state-running'
  if (u === 'S') return 'state-sleep'
  if (u === 'D') return 'state-disk'
  if (u === 'Z') return 'state-zombie'
  return 'state-default-p'
}

const logLevelClass = (level: string) => {
  if (!level) return 'level-info'
  const l = level.toLowerCase()
  if (l === 'err' || l === 'crit' || l === 'emerg') return 'level-err'
  if (l === 'warning' || l === 'warn')               return 'level-warn'
  return 'level-info'
}
</script>

<style scoped>
.linux-result { height: 100%; display: flex; flex-direction: column; overflow: hidden; }
.result-tabs { height: 100%; display: flex; flex-direction: column; }
.result-tabs :deep(.el-tabs__header) { margin: 0; padding: 0 16px; background: #fff; border-bottom: 2px solid #eef0f8; flex-shrink: 0; }
.result-tabs :deep(.el-tabs__nav-wrap::after) { display: none; }
.result-tabs :deep(.el-tabs__item) { height: 42px; font-size: 12.5px; color: #6b7280; padding: 0 14px; }
.result-tabs :deep(.el-tabs__item.is-active) { color: #0ea5e9; font-weight: 700; }
.result-tabs :deep(.el-tabs__item:hover)      { color: #0ea5e9; }
.result-tabs :deep(.el-tabs__active-bar)      { background: #0ea5e9; height: 2.5px; border-radius: 2px; }
.result-tabs :deep(.el-tabs__content)         { flex: 1; overflow: hidden; }
.result-tabs :deep(.el-tab-pane)              { height: 100%; overflow-y: auto; }
.result-tabs :deep(.el-tab-pane)::-webkit-scrollbar { width: 5px; }
.result-tabs :deep(.el-tab-pane)::-webkit-scrollbar-thumb { background: #dde1f0; border-radius: 4px; }
.tab-label { display: flex; align-items: center; gap: 5px; }
.tab-count { display: inline-flex; align-items: center; justify-content: center; min-width: 18px; height: 17px; padding: 0 5px; background: #e0f2fe; color: #0369a1; border-radius: 9px; font-size: 10px; font-weight: 700; }
.tab-count.danger { background: #fee2e2; color: #dc2626; }
.overview-wrap { padding: 14px 16px; }
.detect-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(270px, 1fr)); gap: 12px; }
.table-pane { display: flex; flex-direction: column; height: 100%; padding: 12px 16px; gap: 10px; }
.table-toolbar { display: flex; gap: 10px; align-items: center; flex-shrink: 0; }
.toolbar-hint { font-size: 12px; color: #9ca3af; }
.search-input { width: 260px; }
.search-input :deep(.el-input__wrapper) { border-radius: 8px !important; background: #f5f7fa; box-shadow: none !important; border: 1.5px solid transparent; transition: all 0.2s; }
.search-input :deep(.el-input__wrapper:hover), .search-input :deep(.el-input__wrapper.is-focus) { border-color: #0ea5e9 !important; background: #fff; box-shadow: 0 0 0 3px rgba(14,165,233,0.08) !important; }
/* 告警横幅 */
.alert-banner { display: flex; align-items: flex-start; gap: 12px; padding: 12px 16px; border-radius: 10px; flex-shrink: 0; }
.danger-banner { background: linear-gradient(135deg, #fff5f5 0%, #fef2f2 100%); border: 1.5px solid #fca5a5; }
.danger-banner .el-icon { font-size: 20px; color: #dc2626; margin-top: 1px; flex-shrink: 0; }
.banner-body { display: flex; flex-direction: column; gap: 3px; }
.banner-title { font-size: 13px; font-weight: 700; color: #dc2626; }
.banner-desc  { font-size: 11.5px; color: #7f1d1d; line-height: 1.5; }
/* 检测方法说明栏 */
.method-bar { display: flex; gap: 20px; align-items: center; padding: 7px 14px; background: #f8faff; border: 1px solid #e8ecf8; border-radius: 8px; flex-shrink: 0; flex-wrap: wrap; }
.method-item { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: #6b7280; }
.method-dot  { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.dot-pslist  { background: #22c55e; }
.dot-psscan  { background: #ef4444; }
.dot-pidhash { background: #f59e0b; }
.dot-afinfo  { background: #ef4444; }
.dot-netstat { background: #22c55e; }
/* 表格 */
.data-table { border-radius: 9px; overflow: hidden; flex: 1; }
.threat-table :deep(.el-table__body-wrapper) { background: #fffbfb; }
.data-table :deep(.el-table__header th) { background: #f5f7fa !important; color: #4b5563 !important; font-weight: 700 !important; font-size: 11.5px !important; padding: 9px 0 !important; border-bottom: 2px solid #eaecf4 !important; }
.data-table :deep(.el-table__row > td) { font-size: 12px; color: #374151; padding: 8px 0; }
.data-table :deep(.el-table__row:hover > td) { background: #f0f9ff !important; }
:deep(.row-warn > td) { background: #fffbf0 !important; }
/* 单元格样式 */
.pid-badge { display: inline-block; padding: 1px 8px; background: #e0f2fe; color: #0369a1; border-radius: 5px; font-size: 11.5px; font-weight: 700; font-family: monospace; }
.danger-pid { background: #fee2e2 !important; color: #dc2626 !important; }
.proc-cell { display: flex; align-items: center; gap: 6px; }
.proc-name-cell { display: flex; align-items: center; gap: 5px; }
.proc-icon-danger { color: #dc2626; font-size: 13px; flex-shrink: 0; }
.proc-name-danger { font-weight: 700; color: #dc2626; font-size: 12.5px; }
.addr-cell { display: flex; align-items: center; gap: 2px; }
.danger-addr-cell { gap: 3px; }
.addr-warn-icon { color: #f59e0b; font-size: 12px; flex-shrink: 0; }
.mono-addr { font-family: 'Courier New', monospace; font-size: 11.5px; color: #374151; }
.danger-addr { color: #dc2626; font-weight: 600; }
.muted-val { color: #9ca3af; font-size: 11.5px; }
.time-val { font-size: 11.5px; color: #6b7280; }
.port-sep { color: #9ca3af; font-size: 11px; margin: 0 1px; }
.port-num { font-family: monospace; font-size: 11.5px; color: #0369a1; font-weight: 700; }
.danger-port { color: #dc2626; }
.uid-root { font-weight: 700; color: #dc2626; }
.proc-state-badge { display: inline-block; padding: 1px 6px; background: #f3f4f6; color: #6b7280; border-radius: 4px; font-size: 10.5px; font-weight: 700; font-family: monospace; }
.state-running  { background: #dcfce7 !important; color: #16a34a !important; }
.state-sleep    { background: #dbeafe !important; color: #1d4ed8 !important; }
.state-disk     { background: #fef3c7 !important; color: #d97706 !important; }
.state-zombie   { background: #fee2e2 !important; color: #dc2626 !important; }
.state-default-p { background: #f3f4f6; color: #6b7280; }
.source-badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 5px; font-size: 10.5px; font-weight: 700; }
.source-scan    { background: #fee2e2; color: #dc2626; }
.source-pidhash { background: #fef3c7; color: #d97706; }
.source-unknown { background: #f3f4f6; color: #6b7280; }
.risk-badge { display: inline-block; padding: 2px 9px; border-radius: 5px; font-size: 10.5px; font-weight: 700; }
.risk-critical { background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; }
/* 威胁横幅 */
.threat-banner { display: flex; align-items: center; gap: 14px; padding: 14px 18px; border-radius: 10px; flex-shrink: 0; background: linear-gradient(135deg, #fff5f5 0%, #fef2f2 100%); border: 1.5px solid #fca5a5; }
.threat-banner-icon { font-size: 24px; color: #dc2626; flex-shrink: 0; }
.threat-banner-body { flex: 1; display: flex; flex-direction: column; gap: 3px; }
.threat-banner-title { font-size: 13.5px; font-weight: 700; color: #dc2626; }
.threat-banner-desc  { font-size: 11.5px; color: #7f1d1d; line-height: 1.5; }
.threat-banner-stat  { display: flex; flex-direction: column; align-items: center; padding: 6px 14px; background: rgba(220,38,38,0.08); border-radius: 8px; flex-shrink: 0; min-width: 72px; }
.stat-num   { font-size: 22px; font-weight: 900; color: #dc2626; line-height: 1; }
.stat-label { font-size: 10.5px; color: #9ca3af; margin-top: 2px; white-space: nowrap; }
/* 检测方法说明栏 */
.method-label { font-size: 11.5px; font-weight: 600; color: #4b5563; }
/* 可见性矩阵 */
.matrix-header { display: flex; justify-content: space-around; font-size: 10.5px; font-weight: 700; color: #4b5563; }
.visibility-matrix { display: flex; justify-content: space-around; align-items: center; }
.vis-cell { font-size: 15px; }
.vis-yes  { color: #22c55e; }
.vis-no   { color: #ef4444; }
/* 展开行 */
.expand-detail { padding: 10px 20px 10px 50px; background: #fafbff; display: flex; flex-direction: column; gap: 8px; }
.detail-row { display: flex; align-items: flex-start; gap: 12px; }
.detail-label { flex-shrink: 0; width: 90px; font-size: 11px; font-weight: 700; color: #9ca3af; padding-top: 1px; }
.detail-value { font-size: 12px; color: #374151; word-break: break-all; }
.cmdline-val  { font-family: 'Courier New', monospace; font-size: 11.5px; color: #374151; }
/* 空状态 */
.empty-state { display: flex; align-items: center; justify-content: center; gap: 10px; padding: 40px; border-radius: 10px; font-size: 14px; font-weight: 500; }
.safe-state { background: #f0fdf4; color: #15803d; border: 1.5px solid #bbf7d0; }
.safe-state .el-icon { font-size: 22px; }
/* 网络 */
.proto-tag { display: inline-block; padding: 1px 7px; background: #e0f2fe; color: #0369a1; border-radius: 4px; font-size: 10.5px; font-weight: 700; }
.conn-state { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10.5px; font-weight: 700; }
.state-established { background: #dcfce7; color: #15803d; }
.state-listen      { background: #dbeafe; color: #1d4ed8; }
.state-wait        { background: #fef3c7; color: #b45309; }
.state-default     { background: #f3f4f6; color: #6b7280; }
/* 内核数据 */
.kernel-pane { display: flex; flex-direction: column; gap: 10px; padding: 14px 16px; }
.inner-table { border-radius: 8px; overflow: hidden; }
.inner-table :deep(.el-table__header th) { background: #f5f7fa !important; color: #4b5563 !important; font-weight: 700 !important; font-size: 11.5px !important; padding: 8px 0 !important; }
.inner-table :deep(.el-table__row > td) { font-size: 11.5px; color: #374151; padding: 6px 0; }
.inner-table :deep(.el-table__row:hover > td) { background: #f0f9ff !important; }
.boot-time-box { display: flex; align-items: center; gap: 10px; padding: 12px 16px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; font-size: 14px; font-weight: 600; color: #15803d; }
.boot-time-box .el-icon { font-size: 18px; }
.log-level { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 10.5px; font-weight: 700; }
.level-err  { background: #fee2e2; color: #dc2626; }
.level-warn { background: #fef3c7; color: #d97706; }
.level-info { background: #f3f4f6; color: #6b7280; }
.no-data { display: flex; align-items: center; justify-content: center; gap: 8px; height: 200px; color: #b0b8d8; font-size: 14px; }
</style>
