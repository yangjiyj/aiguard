#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python3 tools/upgrade-governance.py inventory
python3 tools/upgrade-governance.py lint
python3 -m pytest -q deploy/tests/test_upgrade_governance.py
(cd apps/worker && PATH="/usr/local/go/bin:$PATH" GOWORK=off go test ./...)
bash deploy/tests/test_migration_version.sh
bash deploy/tests/test_upgrade_min_data_version.sh
bash deploy/tests/test_migration_runner.sh
bash deploy/tests/test_customer_content_projection_migration.sh
bash deploy/tests/test_backfill_framework.sh
bash deploy/tests/test_large_migrations_expand_only.sh
bash deploy/tests/test_evidence_run_agent_projection_migration.sh
bash deploy/tests/test_upgrade_script.sh
bash deploy/tests/test_bundle_upgrade_contract.sh
bash deploy/tests/test_installer_development_normalized_compose.sh
bash deploy/tests/test_bundle_upgrade_discovery.sh
bash deploy/tests/test_customer_installer_contract.sh
bash deploy/tests/test_sha256_packaging_contract.sh
printf 'upgrade_phase_a=ok\n'
