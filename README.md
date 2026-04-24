# RootKitChecker (memscope)

**RootKitChecker** (内部代号 memscope) 是一个基于 [Volatility 3](https://github.com/volatilityfoundation/volatility3) 的 Linux C/C++ 内存取证与 Rootkit 检测工具。它能够对 Windows 和 Linux 系统的内存镜像进行深度分析，检测隐藏进程、内核级 Rootkit 钩子、隐藏网络连接等高级威胁，并将所有检测结果以结构化的 **JSON** 格式输出，便于与 SIEM、SOAR 或其他自动化分析平台集成。

---

## 核心功能特性

| 类别 | 检测能力说明 |
|---|---|
| **隐藏进程检测** | 交叉比对 `PsList`（链表遍历）、`PsScan`（内存池/堆扫描）与 `PsXView`（多源交叉视图），精准发现被断链隐藏的恶意进程。 |
| **不活跃进程检测** | 识别已终止但其进程控制块（EPROCESS/task_struct）仍驻留在内存中的进程（如非零 `ExitTime` 的进程）。 |
| **Linux Rootkit 检测** | 深度检测 Linux 内核威胁，包括：系统调用表钩子（`check_syscall`）、IDT 钩子（`check_idt`）、`afinfo` 结构篡改（用于隐藏网络连接）、隐藏内核模块（`hidden_modules`/`modxview`）、恶意 eBPF 程序、Netfilter 钩子、TTY 处理函数钩子、键盘通知链钩子（键盘记录器）以及凭据异常（`check_creds`）。 |
| **Windows Rootkit 检测** | 检测 SSDT 钩子、进程空洞化（`HollowProcesses`）、驱动模块异常（`DriverModule`）以及隐藏的内核模块。 |
| **隐藏网络连接检测** | Windows 环境下交叉比对 `NetScan` 与 `NetStat`；Linux 环境下交叉比对 `sockstat` 与 `lsof`，发现未关联合法进程的隐蔽网络套接字。 |
| **内核数据提取** | 自动提取目标系统的内核关键信息。Windows：KDBG、DTB、构建字符串、架构信息；Linux：`vmcoreinfo`、`kallsyms`。 |
| **标准化 JSON 输出** | 采用 [cJSON](https://github.com/DaveGamble/cJSON) 库，将所有扫描结果序列化为标准 JSON 格式，包含全局摘要、分类数组及错误日志。 |

---

## 架构设计

本项目采用 **C/C++ 主程序 + Python 子进程桥接（Subprocess Bridge）** 的混合架构设计：

1. **C/C++ 核心层**：负责命令行解析、任务编排、结果聚合与 JSON 序列化。
2. **Python 桥接层**：通过 `vol_runner.py` 脚本作为独立子进程调用 Volatility 3 框架执行具体的内存分析插件。

**设计优势**：
- **环境隔离**：避免了将 CPython 直接嵌入 C 程序时常见的 ABI 版本冲突问题。
- **高兼容性**：C 二进制文件保持独立，Python 虚拟环境（包含 Volatility 3 及其依赖）可独立更新和维护。
- **易于集成**：对外提供纯粹的 C 接口和 JSON 输出，屏蔽了底层 Python 调用的复杂性。

---

## 环境依赖

| 组件 | 最低版本要求 | 说明 |
|---|---|---|
| **操作系统** | Ubuntu 22.04+ | 推荐的构建与运行环境 |
| **编译器** | GCC 11+ / Clang | 支持 C11 标准 |
| **Python** | 3.8+ | 用于运行 Volatility 3 |
| **Volatility 3** | 2.x | 必须安装在 Python 虚拟环境中 |
| **cJSON** | 1.7+ | 已内置于 `third_party/cjson/`，无需额外安装 |

---

## 编译与安装

### 1. 获取源码

```bash
git clone https://github.com/rakehellsx/RootKitChecker.git
cd RootKitChecker
```

### 2. 编译 C/C++ 主程序

推荐使用 `make` 进行编译：

```bash
# 编译 Release 版本（默认）
make

# 编译 Debug 版本
make debug

# 安装到系统目录（可选，默认 /usr/local）
sudo make install PREFIX=/usr/local
```

编译完成后，可执行文件将生成在 `build/memscope`。

### 3. 配置 Python 虚拟环境

本项目依赖 Volatility 3，建议使用内置脚本自动创建并配置虚拟环境：

```bash
# 自动创建 .venv 目录并安装 volatility3
./scripts/setup_venv.sh .venv
```

---

## 使用指南

### 基本用法

```bash
# 导出虚拟环境路径（必须）
export MEMSCOPE_VENV=$(pwd)/.venv

# 自动检测系统类型并扫描，格式化输出 JSON
./build/memscope -i /path/to/memory_image.raw --pretty

# 强制指定为 Windows 镜像，并将结果保存到文件
./build/memscope -i /path/to/win10.vmem --os windows -o report.json

# 强制指定为 Linux 镜像，跳过网络和模块检测以加快速度
./build/memscope -i /path/to/linux.lime --os linux --no-net --no-modules --pretty
```

### 命令行参数说明

```text
Usage: memscope -i <image_path> [options]

Options:
  -i <path>        内存镜像文件路径 (必填)
  -o <path>        输出 JSON 文件路径 (默认: 标准输出)
  -v <path>        Python 虚拟环境目录 (覆盖 MEMSCOPE_VENV 环境变量)
  --os <type>      强制指定操作系统类型: windows | linux | auto (默认: auto)
  --pretty         格式化 JSON 输出 (Pretty-print)
  --no-net         跳过网络连接分析
  --no-modules     跳过内核模块分析
  --no-hooks       跳过 Rootkit 钩子检测
  --version        打印版本信息并退出
  -h, --help       显示帮助信息
```

---

## 符号表配置 (Symbol Tables)

Volatility 3 需要符号表来解析内存结构。

- **Windows 镜像**：在首次分析时，Volatility 3 会自动从微软符号服务器下载所需的 PDB 符号文件，需保持网络畅通。
- **Linux 镜像**：Linux 内核符号表需要手动生成。请在目标系统（或内核版本完全一致的系统）上使用 [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) 工具生成 JSON 格式的符号表，并将其放置在虚拟环境的对应目录中：
  ```bash
  # 存放路径示例
  .venv/lib/python3.*/site-packages/volatility3/symbols/linux/
  ```

---

## JSON 输出结构示例

工具输出的 JSON 数据结构清晰，包含元数据、内核信息、全局摘要以及各类检测结果的详细数组。

```json
{
  "tool": "memscope",
  "version": "1.0.0",
  "scan_time": "2026-04-24T12:00:00Z",
  "image_path": "/path/to/image.vmem",
  "kernel_info": {
    "os_type": "Windows",
    "architecture": "x86_64",
    "kdbg_offset": "0xf80002a3e120"
  },
  "summary": {
    "total_processes": 85,
    "hidden_processes": 1,
    "hook_count": 2
  },
  "hidden_processes": [
    {
      "pid": 1234,
      "ppid": 4,
      "name": "malware.exe",
      "in_pslist": false,
      "in_psscan": true,
      "hidden": true,
      "source": "psscan(hidden)"
    }
  ],
  "hooks": [
    {
      "index": 0,
      "symbol": "NtCreateFile",
      "handler": "0xfffff88003...",
      "module": "rootkit.sys",
      "hook_type": "SSDT",
      "hooked": true
    }
  ]
}
```

---

## 许可证

本项目基于 [MIT License](LICENSE) 开源。

- 核心依赖 [Volatility 3](https://github.com/volatilityfoundation/volatility3) 遵循 Volatility Software License (VSL)。
- JSON 解析库 [cJSON](https://github.com/DaveGamble/cJSON) 遵循 MIT License。
