#!/usr/bin/env bash
# =============================================================================
# setup_venv.sh  –  Create a Python virtualenv with volatility3 for memscope
# =============================================================================
# Usage:
#   ./scripts/setup_venv.sh [venv_path]
#
# Default venv path: ./venv
# =============================================================================

set -euo pipefail

VENV_PATH="${1:-.venv}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== memscope volatility3 environment setup ==="
echo "  Virtualenv path : $VENV_PATH"
echo ""

# -----------------------------------------------------------------------
# Find Python 3.8+
# -----------------------------------------------------------------------
PYTHON=""
for py in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$py" &>/dev/null; then
        VER=$("$py" -c "import sys; print(sys.version_info >= (3,8))" 2>/dev/null || true)
        if [ "$VER" = "True" ]; then
            PYTHON="$py"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.8+ not found. Please install Python first."
    exit 1
fi

echo "Using Python: $PYTHON ($($PYTHON --version))"

# -----------------------------------------------------------------------
# Create virtualenv
# -----------------------------------------------------------------------
if [ -d "$VENV_PATH" ]; then
    echo "Virtualenv already exists at $VENV_PATH, skipping creation."
else
    echo "Creating virtualenv..."
    if command -v uv &>/dev/null; then
        uv venv "$VENV_PATH" --python "$PYTHON"
    else
        "$PYTHON" -m venv "$VENV_PATH"
    fi
fi

# -----------------------------------------------------------------------
# Install volatility3
# -----------------------------------------------------------------------
echo "Installing volatility3..."
if command -v uv &>/dev/null; then
    uv pip install --python "$VENV_PATH/bin/python" volatility3
else
    "$VENV_PATH/bin/pip" install --upgrade pip
    "$VENV_PATH/bin/pip" install volatility3
fi

# -----------------------------------------------------------------------
# Verify
# -----------------------------------------------------------------------
echo ""
echo "Verifying installation..."
"$VENV_PATH/bin/python" -c "
import volatility3.framework as f
import volatility3.plugins
import volatility3.framework.constants as c
volatility3.plugins.__path__ = list(c.PLUGINS_PATH)
f.import_files(volatility3.plugins, True)
plugins = f.list_plugins()
win_count = sum(1 for k in plugins if k.startswith('windows.'))
lin_count = sum(1 for k in plugins if k.startswith('linux.'))
print(f'  volatility3 OK: {win_count} Windows plugins, {lin_count} Linux plugins')
"

# -----------------------------------------------------------------------
# Print usage instructions
# -----------------------------------------------------------------------
echo ""
echo "=== Setup complete ==="
echo ""
echo "To use memscope with this environment:"
echo ""
echo "  export MEMSCOPE_VENV=\"$(realpath "$VENV_PATH")\""
echo "  $PROJECT_DIR/build/memscope -i /path/to/image.vmem --pretty"
echo ""
echo "Or specify the venv directly:"
echo "  $PROJECT_DIR/build/memscope -i /path/to/image.vmem -v \"$(realpath "$VENV_PATH")\" --pretty"
echo ""
echo "Symbol tables for Linux analysis:"
echo "  Place .json.xz files in:"
echo "  $(realpath "$VENV_PATH")/lib/python*/site-packages/volatility3/symbols/linux/"
echo ""
echo "Symbol tables for Windows analysis:"
echo "  Automatically downloaded on first use, or place .zip files in:"
echo "  $(realpath "$VENV_PATH")/lib/python*/site-packages/volatility3/symbols/windows/"
