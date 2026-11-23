#!/usr/bin/env bash
set -Eeuo pipefail
exec python3 -B "$(dirname "${BASH_SOURCE[0]}")/test_rollback_anchor_runtime_assets.py"
