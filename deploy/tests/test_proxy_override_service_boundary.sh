#!/usr/bin/env bash
set -Eeuo pipefail
exec python3 -B "$(dirname "${BASH_SOURCE[0]}")/test_proxy_override_service_boundary.py"
