#!/bin/bash
# 启动 RootKitChecker Web 后端
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 默认配置
export MEMSCOPE_BIN="${MEMSCOPE_BIN:-$(cd "$SCRIPT_DIR/../.." && pwd)/build/memscope}"
export MEMSCOPE_VENV="${MEMSCOPE_VENV:-$(cd "$SCRIPT_DIR/../.." && pwd)/.venv}"
export MEMSCOPE_UPLOADS="${MEMSCOPE_UPLOADS:-$SCRIPT_DIR/uploads}"
export MEMSCOPE_RESULTS="${MEMSCOPE_RESULTS:-$SCRIPT_DIR/results}"
export MEMSCOPE_DUMP_DIR="${MEMSCOPE_DUMP_DIR:-$SCRIPT_DIR/module_dumps}"

echo "=== RootKitChecker Web Backend ==="
echo "  MEMSCOPE_BIN     : $MEMSCOPE_BIN"
echo "  MEMSCOPE_VENV    : $MEMSCOPE_VENV"
echo "  MEMSCOPE_UPLOADS : $MEMSCOPE_UPLOADS"
echo "  MEMSCOPE_RESULTS : $MEMSCOPE_RESULTS"
echo ""

mkdir -p "$MEMSCOPE_UPLOADS" "$MEMSCOPE_RESULTS" "$MEMSCOPE_DUMP_DIR"

uvicorn main:app --host 0.0.0.0 --port 8000 --reload
