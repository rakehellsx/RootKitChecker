#!/usr/bin/env python3
"""
vol_runner.py  –  Volatility3 plugin runner used by memscope C tool.

Usage:
    python vol_runner.py --image <path> --plugin <name> [--args key=val ...]
                         [--detect-os]

Output: JSON to stdout.
Errors: JSON {"error": "..."} to stdout with exit code 1.
"""

import sys
import os
import json
import argparse
import traceback
import logging

# Suppress volatility3 progress output
logging.disable(logging.CRITICAL)


def setup_volatility():
    """Import and configure volatility3 framework."""
    import volatility3.framework as framework
    import volatility3.plugins
    import volatility3.framework.constants as constants
    from volatility3.framework import contexts, automagic
    from volatility3.framework.configuration import requirements
    from volatility3.framework.interfaces import configuration as iconfig

    # Load all plugins
    volatility3.plugins.__path__ = list(constants.PLUGINS_PATH)
    framework.import_files(volatility3.plugins, True)
    return framework, contexts, automagic, constants


def render_treegrid(treegrid):
    """Convert a TreeGrid to a list of row dicts."""
    from volatility3.framework.interfaces.renderers import (
        BaseAbsentValue, TreeGrid
    )

    columns = [col.name for col in treegrid.columns]
    rows = []

    def visitor(node, accumulator):
        row = {}
        for i, col in enumerate(treegrid.columns):
            try:
                val = node.values[i]
                if isinstance(val, BaseAbsentValue):
                    row[col.name] = None
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

    from volatility3.framework import interfaces
    from volatility3.framework.configuration import requirements as req_mod
    from volatility3.framework.interfaces import configuration as iconfig

    # Build context
    ctx = contexts.Context()
    base_config_path = "plugins"

    # Set image location
    ctx.config["automagic.LayerStacker.single_location"] = (
        "file://" + os.path.abspath(image_path)
    )

    # Resolve plugin class
    plugin_list = framework.list_plugins()
    if plugin_name not in plugin_list:
        return {"error": f"Plugin '{plugin_name}' not found",
                "columns": [], "rows": []}

    plugin_cls = plugin_list[plugin_name]

    # Apply extra args
    if extra_args:
        for kv in extra_args:
            if "=" in kv:
                k, v = kv.split("=", 1)
                ctx.config[k] = v

    # Run automagic
    available = automagic_mod.available(ctx)
    automagics = automagic_mod.choose_automagic(available, plugin_cls)

    errors = automagic_mod.run(
        automagics, ctx, plugin_cls, base_config_path,
        progress_callback=None
    )

    # Check unsatisfied requirements
    plugin_config_path = iconfig.path_join(
        base_config_path, plugin_cls.__name__
    )
    unsatisfied = plugin_cls.unsatisfied(ctx, plugin_config_path)
    if unsatisfied:
        return {
            "error": f"Unsatisfied requirements: {list(unsatisfied.keys())}",
            "columns": [], "rows": []
        }

    # Instantiate and run
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
    for probe in ["linux.pslist.PsList", "linux.info.Info"]:
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


def main():
    parser = argparse.ArgumentParser(description="Volatility3 JSON runner")
    parser.add_argument("--image",   required=True, help="Memory image path")
    parser.add_argument("--plugin",  default=None,  help="Plugin name")
    parser.add_argument("--args",    nargs="*",     help="Extra key=val args")
    parser.add_argument("--detect-os", action="store_true",
                        help="Detect OS type only")
    args = parser.parse_args()

    try:
        if args.detect_os:
            result = detect_os(args.image)
        else:
            if not args.plugin:
                print(json.dumps({"error": "--plugin required"}))
                sys.exit(1)
            result = run_plugin(args.image, args.plugin, args.args)

        print(json.dumps(result, default=str, ensure_ascii=False))
        if result.get("error"):
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
