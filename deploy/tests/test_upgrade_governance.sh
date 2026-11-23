#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 "$ROOT/tools/upgrade-governance.py" inventory
python3 "$ROOT/tools/upgrade-governance.py" lint
python3 -m pytest -q "$ROOT/deploy/tests/test_upgrade_governance.py"
