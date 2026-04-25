# RootKitChecker

> 基于 [Volatility3](https://github.com/volatilityfoundation/volatility3) 的 Linux C/C++ 内存取证工具，支持 Windows 和 Linux 内存镜像分析，检测隐藏进程、Rootkit、隐藏网络连接，并采集完整内核数据，所有结果以 **cJSON** 格式输出。

---

## 功能特性

### 检测能力

| 类别 | 功能 | 使用插件 |
|---|---|---|
| **进程检测** | 隐藏进程（链表外进程） | PsList vs PsScan vs PsXView / PIDHashTable 三源交叉比对 |
| **进程检测** | 不活跃/已终止进程 | PsScan（含 exit_time 进程） |
| **进程检测** | 进程空洞化（Hollowing） | `windows.hollowprocesses.HollowProcesses` |
| **进程检测** | 凭据异常（权限提升） | `linux.check_creds.Check_creds` |
| **网络检测** | 隐藏网络连接 | NetScan vs NetStat / Sockstat vs Lsof 交叉比对 |
| **模块检测** | 隐藏内核模块/驱动 | Modules vs ModScan / Lsmod vs Hidden_modules 交叉比对 |
| **钩子检测** | SSDT 钩子 | `windows.ssdt.SSDT` |
| **钩子检测** | IDT 钩子 | `linux.check_idt.Check_idt` |
| **钩子检测** | 系统调用表钩子 | `linux.check_syscall.Check_syscall` |
| **钩子检测** | afinfo 结构篡改 | `linux.check_afinfo.Check_afinfo` |
| **钩子检测** | Netfilter 钩子 | `linux.netfilter.Netfilter` |
| **钩子检测** | TTY 处理函数钩子 | `linux.tty_check.tty_check` |
| **钩子检测** | 键盘通知链钩子 | `linux.keyboard_notifiers.keyboard_notifiers` |
| **eBPF 检测** | eBPF 程序挂载点 | `linux.ebpf.EBPF` |

### Windows 内核数据采集

| JSON 字段 | Volatility3 插件 | 说明 |
|---|---|---|
| `os_info` | `windows.info.Info` | 系统版本、内核基址、KDBG 结构 |
| `loaded_modules` | `windows.modules.Modules` | 已加载驱动完整列表（名称、基址、大小、路径） |
| `big_pools` | `windows.bigpools.BigPools` | 内核大页池分配，可疑 Tag 自动标记（Rootkit 常分配大页隐藏代码） |
| `memory_map` | `windows.memmap.Memmap` | 内核虚拟地址映射（System PID=0） |
| `statistics` | `windows.statistics.Statistics` | 内存统计摘要（页面计数、大小） |
| `virtual_map` | `windows.virtmap.VirtMap` | 虚拟内存区域划分（起止地址、名称） |

### Linux 内核数据采集

| JSON 字段 | Volatility3 插件 | 说明 |
|---|---|---|
| `kallsyms` | `linux.kallsyms.Kallsyms` | 内核符号表（符号名、地址、类型），可用于定位未导出函数 |
| `iomem` | `linux.iomem.IOMem` | 物理内存 / I/O 资源映射 |
| `vmcoreinfo` | `linux.vmcoreinfo.VMCoreInfo` | VMCore 元数据（内核版本、页大小、符号偏移） |
| `kernel_messages` | `linux.kmsg.Kmsg` | 内核 ring buffer 日志（可能含 Rootkit 加载记录） |
| `boot_time` | `linux.boottime.Boottime` | 系统启动时间戳 |
| `loaded_modules` | `linux.lsmod.Lsmod` | 内核模块完整列表（名称、基址、大小） |
| `kernel_threads` | `linux.kthreads.Kthreads` | 内核线程枚举（可发现隐藏 Rootkit 工作线程） |
| `ebpf_programs` | `linux.ebpf.EBPF` | eBPF 程序挂载点（新型 Rootkit 载体） |
| `netfilter_hooks` | `linux.netfilter.Netfilter` | Netfilter 钩子链（所有钩子点） |
| `mount_info` | `linux.mountinfo.MountInfo` | 文件系统挂载信息（Rootkit 常 bind-mount 隐藏文件） |

---

## 架构设计

```
┌─────────────────────────────────────────────────────┐
│                  RootKitChecker (C)                  │
│                                                      │
│  main.c ──► windows_scan.c / linux_scan.c           │
│                    │                                 │
│              py_bridge.c                             │
│            (subprocess 调用)                         │
│                    │                                 │
│           scripts/vol_runner.py                      │
│                    │                                 │
│              volatility3 (Python)                    │
│                    │                                 │
│           内存镜像文件 (.vmem/.raw/.lime)             │
│                    │                                 │
│  json_output.c ──► cJSON ──► stdout / 文件           │
└─────────────────────────────────────────────────────┘
```

**设计亮点**：采用 subprocess 桥接模式而非嵌入 CPython，C 二进制与 Python 环境完全解耦，可独立升级 volatility3 版本，无需重新编译 C 代码。

---

## 环境依赖

| 组件 | 版本要求 | 说明 |
|---|---|---|
| GCC / Clang | >= 9 | C99 标准 |
| Python | >= 3.8 | 用于运行 volatility3 |
| volatility3 | >= 2.0 | 内存分析框架 |
| cJSON | 内置 | 已包含在 `third_party/cjson/`，无需额外安装 |

---

## 编译与安装

### 方式一：Make（推荐）

```bash
git clone https://github.com/rakehellsx/RootKitChecker.git
cd RootKitChecker
git checkout dev
make
# 编译产物：./build/memscope
```

### 方式二：CMake

```bash
mkdir build_cmake && cd build_cmake
cmake ..
make
```

---

## Python 虚拟环境配置

```bash
# 方式一：使用内置脚本（推荐）
./scripts/setup_venv.sh .venv

# 方式二：手动配置
python3 -m venv .venv
source .venv/bin/activate
pip install volatility3
```

---

## 使用方法

### 基本用法

```bash
export MEMSCOPE_VENV=$(pwd)/.venv

# 自动检测 OS 并扫描（输出到 stdout）
./build/memscope -i /path/to/image.vmem

# 指定 OS 类型
./build/memscope -i /path/to/image.vmem --os windows
./build/memscope -i /path/to/image.lime --os linux

# 指定符号表路径（目录）
./build/memscope -i /path/to/image.vmem --symbols /opt/vol3-symbols/ --pretty

# 指定符号表路径（单个 ISF 文件）
./build/memscope -i /path/to/linux.lime --os linux --symbols /opt/symbols/linux-5.15.json

# 通过环境变量指定符号表路径
export VOLATILITY_SYMBOLS=/opt/vol3-symbols/
./build/memscope -i /path/to/image.vmem --pretty

# 格式化 JSON 输出
./build/memscope -i /path/to/image.vmem --pretty

# 输出到文件
./build/memscope -i /path/to/image.vmem -o report.json --pretty
```

### 命令行参数

| 参数 | 说明 |
|---|---|
| `-i <path>` | 内存镜像路径（必填） |
| `--os <windows\|linux>` | 指定操作系统类型（可选，默认自动检测） |
| `-o <file>` | 输出 JSON 文件路径（可选，默认 stdout） |
| `--symbols <path>` | Volatility3 符号表目录或单个 ISF 文件路径（也可通过 `VOLATILITY_SYMBOLS` 环境变量设置） |
| `--pretty` | 格式化 JSON 输出（缩进 2 空格） |
| `--venv <path>` | Python 虚拟环境路径（也可通过 `MEMSCOPE_VENV` 环境变量设置） |
| `--no-net` | 跳过网络连接分析 |
| `--no-modules` | 跳过内核模块分析 |
| `--no-hooks` | 跳过 Rootkit 钩子检测 |
| `--version` | 显示版本信息 |
| `--help` | 显示帮助信息 |

---

## JSON 输出结构

### 顶层结构

```json
{
  "tool": "RootKitChecker",
  "version": "1.1.0",
  "scan_time": "2026-04-25T12:00:00Z",
  "image_path": "/path/to/image.vmem",
  "kernel_info": { ... },
  "summary": { ... },
  "processes": [ ... ],
  "hidden_processes": [ ... ],
  "inactive_processes": [ ... ],
  "connections": [ ... ],
  "hidden_connections": [ ... ],
  "modules": [ ... ],
  "hidden_modules": [ ... ],
  "hooks": [ ... ],
  "windows_kernel_data": { ... },
  "linux_kernel_data": { ... },
  "errors": [ ... ]
}
```

### Windows 内核数据字段

```json
"windows_kernel_data": {
  "os_info": [
    { "key": "Kernel Base", "value": "0xf80002600000" },
    { "key": "DTB", "value": "0x187000" },
    { "key": "NtBuildLab", "value": "19041.1.amd64fre.vb_release" }
  ],
  "loaded_modules": [
    { "name": "ntoskrnl.exe", "base": "0xf80002600000", "size": 5898240, "path": "\\SystemRoot\\system32\\ntoskrnl.exe" }
  ],
  "big_pools": [
    { "virtual_addr": "0xffff800012340000", "size": 65536, "tag": "Driv", "type": "NonPagedPool", "suspicious": false },
    { "virtual_addr": "0xffff800098760000", "size": 131072, "tag": "XxXx", "type": "NonPagedPool", "suspicious": true }
  ],
  "memory_map": [
    { "start": "0xfffff80000000000", "end": "0xfffff80010000000", "size": 268435456, "name": "ntoskrnl.exe" }
  ],
  "statistics": [
    { "key": "Pages", "value": "1048576", "extra": "4294967296" }
  ],
  "virtual_map": [
    { "start": "0x0", "end": "0x7fffffffffff", "name": "User Space" },
    { "start": "0xffff800000000000", "end": "0xffffffffffffffff", "name": "Kernel Space" }
  ]
}
```

### Linux 内核数据字段

```json
"linux_kernel_data": {
  "kallsyms": [
    { "key": "sys_call_table", "value": "0xffffffff81e001a0", "extra": "D" },
    { "key": "commit_creds", "value": "0xffffffff810a8b40", "extra": "T" }
  ],
  "iomem": [
    { "start": "0x0", "end": "0x9fbff", "size": 654336, "name": "System RAM" },
    { "start": "0x100000", "end": "0x7fffffff", "size": 2146435072, "name": "System RAM" }
  ],
  "vmcoreinfo": [
    { "key": "OSRELEASE", "value": "5.15.0-91-generic" },
    { "key": "PAGESIZE", "value": "4096" },
    { "key": "SYMBOL(init_uts_ns)", "value": "ffffffff82a4b5c0" }
  ],
  "kernel_messages": [
    { "key": "1234567.890123", "value": "rootkit: module loaded successfully", "extra": "kern" },
    { "key": "1234568.001234", "value": "rootkit: hiding process 1337", "extra": "kern" }
  ],
  "boot_time": "2026-01-01T00:00:00",
  "loaded_modules": [
    { "name": "rootkit", "base": "0xffffffffc0a00000", "size": 4096 },
    { "name": "nf_conntrack", "base": "0xffffffffc0b00000", "size": 163840 }
  ],
  "kernel_threads": [
    { "pid": 2, "ppid": 0, "name": "kthreadd", "state": "S" },
    { "pid": 3, "ppid": 2, "name": "rcu_gp", "state": "I" }
  ],
  "ebpf_programs": [
    { "symbol": "xdp_redirect_prog", "module": "abcd1234efgh5678", "hook_type": "eBPF", "hooked": true }
  ],
  "netfilter_hooks": [
    { "symbol": "NF_INET_PRE_ROUTING", "handler": "0xffffffffc0a01234", "module": "rootkit", "hook_type": "netfilter", "hooked": true }
  ],
  "mount_info": [
    { "pid": 1, "device": "/dev/sda1", "path": "/", "fstype": "ext4", "options": "rw,relatime" },
    { "pid": 1, "device": "overlay", "path": "/proc/1337", "fstype": "overlay", "options": "rw" }
  ]
}
```

---

## 符号表配置

Volatility3 需要符号表（ISF 格式）才能正确解析内存结构。RootKitChecker 支持通过 `--symbols` 参数或 `VOLATILITY_SYMBOLS` 环境变量指定符号表路径，两种方式等效，命令行参数优先级更高。

### 指定方式

```bash
# 方式一：命令行参数（推荐）
./build/memscope -i image.vmem --symbols /opt/vol3-symbols/

# 方式二：环境变量
export VOLATILITY_SYMBOLS=/opt/vol3-symbols/
./build/memscope -i image.vmem

# 支持目录（含多个符号文件）
./build/memscope -i win10.vmem --symbols /opt/symbols/windows/

# 支持单个 ISF 文件
./build/memscope -i linux.lime --os linux --symbols /opt/symbols/linux-5.15.0-91-generic.json
```

### Windows 符号表

Windows 镜像分析时，volatility3 默认会自动从 Microsoft Symbol Server 下载 PDB 符号文件并转换为 ISF 格式，**无需手动操作**。如需离线环境或加速分析，可预先下载后通过 `--symbols` 指定：

```bash
# 离线使用：将已下载的符号目录传入
./build/memscope -i win10.vmem --symbols /opt/windows-symbols/ --pretty
```

### Linux 符号表

Linux 内核符号表需要手动生成，使用 [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) 工具从带调试信息的内核文件生成 ISF 文件：

```bash
# 步骤一：安装 dwarf2json
pip install dwarf2json

# 步骤二：生成符号文件（在目标系统或版本完全一致的系统上执行）
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > linux-$(uname -r).json

# 步骤三：分析时通过 --symbols 指定
./build/memscope -i linux.lime --os linux --symbols ./linux-$(uname -r).json --pretty

# 或者将符号文件放入统一目录，批量管理
mkdir -p /opt/vol3-symbols/linux/
cp linux-*.json /opt/vol3-symbols/linux/
./build/memscope -i linux.lime --os linux --symbols /opt/vol3-symbols/
```

### 符号路径优先级

| 优先级 | 来源 | 示例 |
|---|---|---|
| 1（最高） | `--symbols` 命令行参数 | `--symbols /opt/symbols/` |
| 2 | `VOLATILITY_SYMBOLS` 环境变量 | `export VOLATILITY_SYMBOLS=/opt/symbols/` |
| 3（最低） | volatility3 内置路径 | 自动搜索 site-packages 内的 symbols/ 目录 |

---

## 项目结构

```
RootKitChecker/
├── README.md
├── CMakeLists.txt
├── Makefile
├── src/
│   ├── main.c              # CLI 主程序，参数解析，扫描编排
│   ├── py_bridge.c         # subprocess 桥接层
│   ├── windows_scan.c      # Windows 检测 + 内核数据采集（6项）
│   ├── linux_scan.c        # Linux 检测 + 内核数据采集（10项）
│   └── json_output.c       # cJSON 序列化层（覆盖全部数据结构）
├── include/
│   ├── memscope.h          # 公共 API 与数据结构定义
│   ├── py_bridge.h         # 桥接层接口
│   ├── windows_scan.h      # Windows 模块接口（含6项内核数据函数）
│   └── linux_scan.h        # Linux 模块接口（含10项内核数据函数）
├── scripts/
│   ├── vol_runner.py       # Volatility3 Python 运行脚本（支持全部插件）
│   └── setup_venv.sh       # 一键环境配置脚本
├── third_party/
│   └── cjson/
│       ├── cJSON.c         # cJSON 库源码（内置）
│       └── cJSON.h
└── docs/
    ├── example_output_windows.json
    └── example_output_linux.json
```

---

## 许可证

本项目基于 MIT License 开源。volatility3 遵循其自身的 [Volatility Software License](https://www.volatilityfoundation.org/license/vsl-v1.0)。cJSON 遵循 MIT License。
