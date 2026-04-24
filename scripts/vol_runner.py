#!/usr/bin/env python3
"""
vol_runner.py  –  Volatility3 plugin runner used by RootKitChecker C tool.

Usage:
    python vol_runner.py --image <path> --plugin <name> [--args key=val ...]
                         [--detect-os] [--list-plugins]

Output: JSON to stdout.
Errors: JSON {"error": "..."} to stdout with exit code 1.

Supported plugins (Windows):
    windows.info.Info               os_info
    windows.pslist.PsList           process list
    windows.psscan.PsScan           process scan
    windows.cmdline.CmdLine         command lines
    windows.psxview.PsXView         cross-view process detection
    windows.netscan.NetScan         network scan
    windows.netstat.NetStat         network stat
    windows.modules.Modules         loaded modules
    windows.modscan.ModScan         module scan
    windows.driverscan.DriverScan   driver scan
    windows.drivermodule.DriverModule driver anomalies
    windows.ssdt.SSDT               SSDT hooks
    windows.hollowprocesses.HollowProcesses process hollowing
    windows.bigpools.BigPools       large kernel pool allocations
    windows.memmap.Memmap           kernel virtual address map
    windows.statistics.Statistics   memory statistics
    windows.virtmap.VirtMap         virtual memory regions

Supported plugins (Linux):
    linux.pslist.PsList             process list
    linux.psscan.PsScan             process scan
    linux.pidhashtable.PIDHashTable PID hash table
    linux.sockstat.Sockstat         socket statistics
    linux.lsof.Lsof                 open file descriptors
    linux.lsmod.Lsmod               loaded kernel modules
    linux.check_syscall.Check_syscall syscall hooks
    linux.check_idt.Check_idt       IDT hooks
    linux.check_afinfo.Check_afinfo afinfo tampering
    linux.check_creds.Check_creds   credential anomalies
    linux.hidden_modules.Hidden_modules hidden modules
    linux.modxview.Modxview         module cross-view
    linux.ebpf.EBPF                 eBPF programs
    linux.netfilter.Netfilter       netfilter hooks
    linux.tty_check.tty_check       TTY handler hooks
    linux.keyboard_notifiers.keyboard_notifiers keyboard hooks
    linux.kallsyms.Kallsyms         kernel symbol table
    linux.iomem.IOMem               I/O memory map
    linux.vmcoreinfo.VMCoreInfo     vmcore metadata
    linux.kmsg.Kmsg                 kernel ring buffer
    linux.boottime.Boottime         system boot time
    linux.kthreads.Kthreads         kernel threads
    linux.mountinfo.MountInfo       mount points
"""

import sys
import os
import json
import argparse
import traceback
import logging

# Suppress volatility3 progress and warning output
logging.disable(logging.CRITICAL)

# ---------------------------------------------------------------------------
# Column name normalization map
# Maps plugin-specific column names to canonical names expected by C code.
# ---------------------------------------------------------------------------
COLUMN_ALIASES = {
    # windows.info.Info
    "Variable":          "Variable",
    "Value":             "Value",

    # windows.modules / modscan / driverscan
    "Offset":            "Base",
    "Base DLL":          "Base",
    "DLL Base":          "Base",
    "ImageSize":         "Size",
    "FullDllName":       "Path",
    "BaseDllName":       "Name",
    "DriverName":        "Name",
    "ServiceKey":        "Path",

    # windows.bigpools
    "PoolBigPageTable":  "PoolBigPageTable",
    "AllocSize":         "AllocSize",
    "Tag":               "Tag",
    "PoolType":          "PoolType",

    # windows.memmap
    "Virtual":           "Virtual",
    "Mapped File":       "Mapped File",

    # windows.statistics
    "Stat":              "Stat",
    "Count":             "Count",

    # windows.virtmap
    "Start":             "Start",
    "End":               "End",

    # linux.kallsyms
    "Symbol":            "Symbol",
    "Address":           "Address",
    "Type":              "Type",

    # linux.iomem
    "Name":              "Name",

    # linux.vmcoreinfo
    "Key":               "Key",

    # linux.kmsg
    "Timestamp":         "Timestamp",
    "Message":           "Message",
    "Facility":          "Facility",

    # linux.boottime
    "BootTime":          "BootTime",
    "Boot Time":         "Boot Time",

    # linux.lsmod / kthreads
    "COMM":              "COMM",
    "OFFSET (V)":        "OFFSET (V)",
    "State":             "State",

    # linux.kthreads
    "PID":               "PID",
    "PPID":              "PPID",

    # linux.ebpf
    "LoadTime":          "LoadTime",

    # linux.netfilter
    "Hook":              "Hook",
    "Handler":           "Handler",
    "Module":            "Module",
    "Priority":          "Priority",

    # linux.mountinfo
    "Device":            "Device",
    "Path":              "Path",
    "FSType":            "FSType",
    "Options":           "Options",

    # linux.sockstat
    "NetNS":             "NetNS",
    "Process":           "Process",
    "Source Addr":       "Source Addr",
    "Source Port":       "Source Port",
    "Dest Addr":         "Dest Addr",
    "Dest Port":         "Dest Port",
    "Sock Offset":       "Sock Offset",
}


def setup_volatility():
    """Import and configure volatility3 framework."""
    import volatility3.framework as framework
    import volatility3.plugins
    import volatility3.framework.constants as constants
    from volatility3.framework import contexts, automagic

    # Load all plugins
    volatility3.plugins.__path__ = list(constants.PLUGINS_PATH)
    framework.import_files(volatility3.plugins, True)
    return framework, contexts, automagic, constants


def render_treegrid(treegrid):
    """Convert a TreeGrid to a list of row dicts."""
    from volatility3.framework.interfaces.renderers import BaseAbsentValue

    columns = [col.name for col in treegrid.columns]
    rows = []

    def visitor(node, accumulator):
        row = {}
        for i, col in enumerate(treegrid.columns):
            try:
                val = node.values[i]
                if isinstance(val, BaseAbsentValue):
                    row[col.name] = None
                elif isinstance(val, bool):
                    row[col.name] = val
                elif hasattr(val, '__int__'):
                    row[col.name] = int(val)
                else:
                    row[col.name] = str(val)
            except Exception:
                row[col.name] = None
        row["__depth__"] = node.path_depth
        accumulator.append(row)
        return accumulator

    treegrid.populate(visitor, rows)
    return columns, rows


def run_plugin(image_path, plugin_name, extra_args=None):
    """Run a single volatility3 plugin and return JSON-serialisable dict."""
    framework, contexts, automagic_mod, constants = setup_volatility()
    from volatility3.framework.interfaces import configuration as iconfig

    ctx = contexts.Context()
    base_config_path = "plugins"

    ctx.config["automagic.LayerStacker.single_location"] = (
        "file://" + os.path.abspath(image_path)
    )

    plugin_list = framework.list_plugins()

    # Case-insensitive plugin lookup
    resolved_name = plugin_name
    if plugin_name not in plugin_list:
        for name in plugin_list:
            if name.lower() == plugin_name.lower():
                resolved_name = name
                break
        else:
            return {
                "error": f"Plugin '{plugin_name}' not found. "
                         f"Available: {sorted(plugin_list.keys())}",
                "columns": [], "rows": []
            }

    plugin_cls = plugin_list[resolved_name]

    # Apply extra args
    if extra_args:
        for kv in extra_args:
            if "=" in kv:
                k, v = kv.split("=", 1)
                ctx.config[k] = v

    # Run automagic
    available = automagic_mod.available(ctx)
    automagics = automagic_mod.choose_automagic(available, plugin_cls)

    automagic_mod.run(
        automagics, ctx, plugin_cls, base_config_path,
        progress_callback=None
    )

    plugin_config_path = iconfig.path_join(
        base_config_path, plugin_cls.__name__
    )
    unsatisfied = plugin_cls.unsatisfied(ctx, plugin_config_path)
    if unsatisfied:
        return {
            "error": f"Unsatisfied requirements: {list(unsatisfied.keys())}",
            "columns": [], "rows": []
        }

    plugin = plugin_cls(ctx, plugin_config_path)
    treegrid = plugin.run()

    columns, rows = render_treegrid(treegrid)
    return {"error": None, "columns": columns, "rows": rows}


def detect_os(image_path):
    """Detect OS type from a memory image."""
    framework, contexts, automagic_mod, constants = setup_volatility()
    from volatility3.framework.interfaces import configuration as iconfig

    ctx = contexts.Context()
    base_config_path = "plugins"
    ctx.config["automagic.LayerStacker.single_location"] = (
        "file://" + os.path.abspath(image_path)
    )

    plugin_list = framework.list_plugins()

    # Try Windows first
    for probe in ["windows.info.Info", "windows.pslist.PsList"]:
        if probe not in plugin_list:
            continue
        plugin_cls = plugin_list[probe]
        available = automagic_mod.available(ctx)
        automagics = automagic_mod.choose_automagic(available, plugin_cls)
        try:
            automagic_mod.run(automagics, ctx, plugin_cls,
                              base_config_path, progress_callback=None)
            plugin_config_path = iconfig.path_join(
                base_config_path, plugin_cls.__name__
            )
            unsatisfied = plugin_cls.unsatisfied(ctx, plugin_config_path)
            if not unsatisfied:
                return {"os": "windows"}
        except Exception:
            pass

    # Try Linux
    for probe in ["linux.pslist.PsList", "linux.vmcoreinfo.VMCoreInfo"]:
        if probe not in plugin_list:
            continue
        plugin_cls = plugin_list[probe]
        available = automagic_mod.available(ctx)
        automagics = automagic_mod.choose_automagic(available, plugin_cls)
        try:
            automagic_mod.run(automagics, ctx, plugin_cls,
                              base_config_path, progress_callback=None)
            plugin_config_path = iconfig.path_join(
                base_config_path, plugin_cls.__name__
            )
            unsatisfied = plugin_cls.unsatisfied(ctx, plugin_config_path)
            if not unsatisfied:
                return {"os": "linux"}
        except Exception:
            pass

    return {"os": "unknown"}


def list_plugins():
    """List all available volatility3 plugins."""
    framework, _, _, _ = setup_volatility()
    plugin_list = framework.list_plugins()
    windows_plugins = sorted(
        [n for n in plugin_list if n.startswith("windows.")])
    linux_plugins = sorted(
        [n for n in plugin_list if n.startswith("linux.")])
    other_plugins = sorted(
        [n for n in plugin_list
         if not n.startswith("windows.") and not n.startswith("linux.")])
    return {
        "windows": windows_plugins,
        "linux": linux_plugins,
        "other": other_plugins,
        "total": len(plugin_list)
    }


def main():
    parser = argparse.ArgumentParser(
        description="RootKitChecker / Volatility3 JSON runner")
    parser.add_argument("--image",        default=None,
                        help="Memory image path")
    parser.add_argument("--plugin",       default=None,
                        help="Plugin name (e.g. windows.pslist.PsList)")
    parser.add_argument("--args",         nargs="*",
                        help="Extra key=val plugin arguments")
    parser.add_argument("--detect-os",    action="store_true",
                        help="Detect OS type only")
    parser.add_argument("--list-plugins", action="store_true",
                        help="List all available plugins")
    args = parser.parse_args()

    try:
        if args.list_plugins:
            result = list_plugins()
        elif args.detect_os:
            if not args.image:
                print(json.dumps({"error": "--image required for --detect-os"}))
                sys.exit(1)
            result = detect_os(args.image)
        else:
            if not args.image:
                print(json.dumps({"error": "--image required"}))
                sys.exit(1)
            if not args.plugin:
                print(json.dumps({"error": "--plugin required"}))
                sys.exit(1)
            result = run_plugin(args.image, args.plugin, args.args)

        print(json.dumps(result, default=str, ensure_ascii=False))
        if isinstance(result, dict) and result.get("error"):
            sys.exit(1)

    except Exception as e:
        print(json.dumps({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "columns": [], "rows": []
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()
