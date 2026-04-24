# =============================================================================
# memscope – Makefile
# =============================================================================
# Usage:
#   make              – build release binary in build/
#   make debug        – build debug binary
#   make clean        – remove build artifacts
#   make install      – install to PREFIX (default /usr/local)
#   make test         – run basic sanity test (requires a sample image)
# =============================================================================

CC      ?= gcc
PREFIX  ?= /usr/local
BUILD   := build
TARGET  := $(BUILD)/memscope

SRCS := src/main.c          \
        src/py_bridge.c     \
        src/windows_scan.c  \
        src/linux_scan.c    \
        src/json_output.c   \
        third_party/cjson/cJSON.c

INCS := -Iinclude -Ithird_party/cjson

CFLAGS_COMMON := -std=c11 -Wall -Wextra -Wno-unused-parameter \
                 -Wno-sign-compare
CFLAGS_RELEASE := $(CFLAGS_COMMON) -O2 -DNDEBUG
CFLAGS_DEBUG   := $(CFLAGS_COMMON) -g -O0 -DDEBUG

LDFLAGS := -lm

# -----------------------------------------------------------------------
# Default target: release build
# -----------------------------------------------------------------------
.PHONY: all release debug clean install test

all: release

release: $(BUILD)
	$(CC) $(CFLAGS_RELEASE) $(INCS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	@echo ""
	@echo "Build complete: $(TARGET)"
	@echo ""
	@echo "Usage:"
	@echo "  export MEMSCOPE_VENV=/path/to/vol3-venv"
	@echo "  ./$(TARGET) -i /path/to/image.vmem --pretty"
	@echo ""

debug: $(BUILD)
	$(CC) $(CFLAGS_DEBUG) $(INCS) $(SRCS) -o $(TARGET)_debug $(LDFLAGS)
	@echo "Debug build: $(TARGET)_debug"

$(BUILD):
	mkdir -p $(BUILD)

# -----------------------------------------------------------------------
# Clean
# -----------------------------------------------------------------------
clean:
	rm -rf $(BUILD)

# -----------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------
install: release
	install -d $(PREFIX)/bin
	install -m 755 $(TARGET) $(PREFIX)/bin/memscope
	install -d $(PREFIX)/share/memscope/scripts
	install -m 644 scripts/vol_runner.py \
	               $(PREFIX)/share/memscope/scripts/vol_runner.py
	@echo "Installed memscope to $(PREFIX)/bin/memscope"
	@echo "Installed vol_runner.py to $(PREFIX)/share/memscope/scripts/"

# -----------------------------------------------------------------------
# Quick test (set IMAGE to a real memory image path)
# -----------------------------------------------------------------------
IMAGE ?= /tmp/test.vmem
test: release
	@if [ ! -f "$(IMAGE)" ]; then \
	    echo "No test image found at $(IMAGE)."; \
	    echo "Set IMAGE=/path/to/image.vmem and re-run."; \
	    exit 0; \
	fi
	MEMSCOPE_VENV=$(MEMSCOPE_VENV) ./$(TARGET) -i $(IMAGE) --pretty
