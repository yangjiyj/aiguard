#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LEGACY_MIGRATION="$ROOT/deploy/migrations/114_semantic_runtime_defaults.sql"
MIGRATION="$ROOT/deploy/migrations/139_semantic_bundled_defaults.sql"
BENCHMARK="$ROOT/deploy/docker-compose/judge-benchmark.sh"

test "$(sha256sum "$LEGACY_MIGRATION" | awk '{print $1}')" = \
  'e0fe4be1340f8e27533f1a0b14c93d718ca1a1b5717a0f050ba8b128d2a249e0'

for expected in \
  "('semantic_enabled', 'true', NOW())" \
  "('semantic_input_enabled', 'true', NOW())" \
  "('semantic_agent_enabled', 'true', NOW())" \
  "('semantic_output_enabled', 'false', NOW())" \
  "('security_audit_only', 'true', NOW())" \
  "('semantic_total_timeout', '9', NOW())" \
  "('judge_backend', 'bundled', NOW())" \
  "('judge_timeout', '8', NOW())" \
  "('tier1_enabled', 'true', NOW())" \
  "('tier1_low_threshold', '0.30', NOW())" \
  "('tier1_high_threshold', '0.70', NOW())"; do
  grep -Fq "$expected" "$MIGRATION"
done

for expected in '114_semantic_runtime_defaults.sql' 's.updated_at <= m.applied_at' 'ON CONFLICT (key) DO NOTHING'; do
  grep -Fq "$expected" "$MIGRATION"
done

for expected in \
  'TOTAL_TIMEOUT=9' \
  "('judge_timeout', '\${JUDGE_TIMEOUT}', NOW())" \
  "WHERE system_settings.value = '8';" \
  "WHERE system_settings.value = '9';"; do
  grep -Fq "$expected" "$BENCHMARK"
done

if grep -Eq "tier1_(low|high)_threshold" "$BENCHMARK"; then
  echo "benchmark must not write detection thresholds" >&2
  exit 1
fi
sh -n "$BENCHMARK"
printf 'semantic_delivery_defaults=ok\n'
