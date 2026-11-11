#!/usr/bin/env bash
# ==============================================================================
# BVM02 Battery Monitor for Gen5W — Build Script
# Executes the cross-platform packaging, signing, and bundle pipeline.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
    exec python3 tools/build_package.py "$@"
elif command -v python >/dev/null 2>&1; then
    exec python tools/build_package.py "$@"
else
    echo "Error: Python 3 is required to execute the build pipeline." >&2
    exit 1
fi
