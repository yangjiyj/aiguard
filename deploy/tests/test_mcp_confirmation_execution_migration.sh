#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
migration="$root/deploy/migrations/116_mcp_confirmation_execution.sql"

grep -q "CREATE TABLE IF NOT EXISTS mcp_confirmation_executions" "$migration"
grep -q "replay_context_ciphertext LIKE 'enc:v1:%'" "$migration"
grep -q "execution_status IN ('pending','executing','executed','failed','unknown')" "$migration"
grep -q "FOREIGN KEY (confirmation_id, tenant_id)" "$migration"
grep -q "UNIQUE INDEX IF NOT EXISTS idx_mcp_confirmation_execution_attempt" "$migration"
grep -q "uq_mcp_confirmation_tenant_scope" "$migration"
grep -q "uq_mcp_confirmation_invocation" "$migration"
grep -q "ALTER COLUMN scope_key SET NOT NULL" "$migration"
grep -q "mcp_confirmation_evidence_link" "$migration"
grep -q "mcp_confirmation_approved_hashes" "$migration"
grep -q "result_ciphertext IS NULL OR result_ciphertext LIKE 'enc:v2:%'" "$migration"
grep -q "result_plaintext_bytes <= 8388608" "$migration"
grep -q "conrelid='mcp_confirmation_executions'::regclass" "$migration"

if grep -Eqi "tool_call_arguments[[:space:]]+TEXT.*mcp_confirmation" "$migration"; then
  echo "migration must not add plaintext MCP arguments" >&2
  exit 1
fi
