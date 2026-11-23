#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python3 tools/upgrade-governance.py inventory
python3 tools/upgrade-governance.py lint
bash deploy/tests/test_sha256_packaging_contract.sh
bash deploy/tests/test_offline_release_hardening.sh
bash deploy/tests/test_customer_installer_contract.sh
bash deploy/tests/test_docker_cli_compat.sh
bash deploy/tests/test_install_docker_init.sh
bash deploy/tests/test_offline_promotion.sh
printf 'upgrade_phase_b=ok\n'
