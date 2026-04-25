# RootKitChecker (memscope)

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
| `loaded_modules` | `windows.modules.Modules` | 遍历 `PsLoadedModuleList`，列出 ntoskrnl.exe、驱动、HAL 等完整列表 |
| `module_dumps` | `windows.modules.Modules --dump` | 提取内核驱动 `.sys` 文件到本地，用于后续静态分析（含 dump_ok 标志） |
| `driver_irps` | `windows.driverirp.DriverIrp` | 解析 `DRIVER_OBJECT->MajorFunction` 数组，检测 IRP Hook（28 个 IRP 名称自动映射） |
| `unloaded_modules` | `windows.unloadedmodules.UnloadedModules` | 提取 `PsUnloadedDriversList`，发现曾加载后卸载的恶意驱动（含卸载时间戳） |
| `callbacks` | `windows.callbacks.Callbacks` | 枚举 CreateProcessNotifyRoutine、CreateThreadNotifyRoutine、LoadImageNotifyRoutine、RegistryCallback 等内核回调 |
| `timers` | `windows.timers.Timers` | 解析 `KTIMER` 对象，检测 Rootkit 使用的内核定时器（含 DPC 例程地址和所属模块） |
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

- **操作系统**：Linux (Ubuntu/Debian/CentOS 等)
- **编译器**：GCC 或 Clang (支持 C11 标准)
- **构建工具**：Make 或 CMake
- **Python**：Python 3.8+ (用于运行 volatility3)

---

## 编译与安装

### 1. 编译 C 主程序

提供两种编译方式：

**方式一：使用 Make（推荐）**
```bash
make clean
make
# 编译产物位于 build/memscope
```

**方式二：使用 CMake**
```bash
mkdir build && cd build
cmake ..
make
```

### 2. 配置 Python 虚拟环境

工具内置了一键配置脚本，自动创建虚拟环境并安装 volatility3 及其依赖：

```bash
# 在项目根目录下执行
./scripts/setup_venv.sh .venv
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

# 指定内核驱动模块导出目录（Windows 镜像）
./build/memscope -i /path/to/win10.vmem --dump-dir /tmp/drivers --pretty

# 通过环境变量指定模块导出目录
export MEMSCOPE_DUMP_DIR=/opt/driver-dumps/
./build/memscope -i /path/to/win10.vmem --pretty

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
| `--dump-dir <path>` | 内核驱动模块（`.sys`）导出目录（也可通过 `MEMSCOPE_DUMP_DIR` 环境变量设置，默认 `./module_dumps`） |
| `--pretty` | 格式化 JSON 输出（缩进 2 空格） |
| `-v <path>` | Python 虚拟环境路径（也可通过 `MEMSCOPE_VENV` 环境变量设置） |
| `--no-net` | 跳过网络连接分析 |
| `--no-modules` | 跳过内核模块分析 |
| `--no-hooks` | 跳过 Rootkit 钩子检测 |
| `--version` | 显示版本信息 |
| `--help` | 显示帮助信息 |

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

## 模块导出路径配置

分析 Windows 内存镜像时，`windows.modules.Modules --dump` 插件会将内核驱动（`.sys` 文件）提取到本地磁盘，供后续静态分析使用（如 IDA Pro、Ghidra 逆向分析）。导出目录通过以下方式指定，优先级由高到低：

### 指定方式

```bash
# 方式一：命令行参数 --dump-dir（最高优先级，推荐）
./build/memscope -i win10.vmem --dump-dir /opt/driver-dumps/ --pretty

# 方式二：环境变量 MEMSCOPE_DUMP_DIR
export MEMSCOPE_DUMP_DIR=/opt/driver-dumps/
./build/memscope -i win10.vmem --pretty

# 方式三：默认路径（最低优先级）
# 若两者均未设置，导出到当前工作目录下的 ./module_dumps/ 子目录
./build/memscope -i win10.vmem --pretty
# 驱动文件将写入 ./module_dumps/ntfs.sys.0xfffff80012345000.dmp 等
```

### 导出路径优先级

| 优先级 | 来源 | 示例 |
|---|---|---|
| 1（最高） | `--dump-dir` 命令行参数 | `--dump-dir /opt/driver-dumps/` |
| 2 | `MEMSCOPE_DUMP_DIR` 环境变量 | `export MEMSCOPE_DUMP_DIR=/opt/driver-dumps/` |
| 3（最低） | 默认路径 | `./module_dumps/`（相对于当前工作目录） |

> **注意**：目录不存在时工具会自动创建（等效于 `mkdir -p`）。导出结果记录在 JSON 输出的 `windows_kernel_data.module_dumps` 数组中，每条记录含 `dump_path`（本地文件路径）和 `dump_ok`（是否成功）字段。

---

## 项目结构

```
RootKitChecker/
├── README.md                          # 完整中文说明文档
├── CMakeLists.txt                     # CMake 构建配置
├── Makefile                           # Make 构建配置
├── src/
│   ├── main.c                         # CLI 主程序，参数解析，扫描编排
│   ├── py_bridge.c                    # Python 子进程桥接层
│   ├── windows_scan.c                 # Windows 检测模块
│   ├── linux_scan.c                   # Linux 检测模块
│   └── json_output.c                  # cJSON 序列化层
├── include/
│   ├── memscope.h                     # 公共 API 与数据结构
│   ├── py_bridge.h                    # 桥接层接口
│   ├── windows_scan.h                 # Windows 模块接口
│   └── linux_scan.h                   # Linux 模块接口
├── scripts/
│   ├── vol_runner.py                  # Volatility3 Python 运行脚本
│   └── setup_venv.sh                  # 一键环境配置脚本
├── third_party/cjson/
│   ├── cJSON.c                        # cJSON 库源码
│   └── cJSON.h                        # cJSON 库头文件
└── docs/
    ├── example_output_windows.json    # Windows 扫描 JSON 示例
    └── example_output_linux.json      # Linux 扫描 JSON 示例
```

---

## 许可证

本项目采用 MIT 许可证。内置的 cJSON 库采用 MIT 许可证。
