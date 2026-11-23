#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/122_header_contract_conflict_idempotency.sql"

grep -q "duplicate header_contract_conflict event_id exists" "$MIGRATION"
grep -q "uq_audit_operations_header_contract_conflict_id" "$MIGRATION"
grep -q "uq_audit_chain_header_contract_conflict_event_id" "$MIGRATION"
grep -q "WHERE event_type = 'header_contract_conflict'" "$MIGRATION"

DATABASE_URL="${HEADER_CONTRACT_TEST_DATABASE_URL:-${CONTENT_LOGS_TEST_DATABASE_URL:-}}"
if [[ -z "$DATABASE_URL" ]]; then
  echo "SKIP live PostgreSQL fixture: HEADER_CONTRACT_TEST_DATABASE_URL is not set"
  echo "PASS: migration duplicate guard and dedicated unique indexes are present"
  exit 0
fi

fresh="header_contract_fresh_${RANDOM}_$$"
existing="header_contract_existing_${RANDOM}_$$"
duplicate="header_contract_duplicate_${RANDOM}_$$"
fixture_pid=""
fixture_url=""
fixture_nonce="${RANDOM}${RANDOM}$$"
fixture_log="${TMPDIR:-/tmp}/jjdguard-header-contract-fixture-$$.log"
fixture_ready="${TMPDIR:-/tmp}/jjdguard-header-contract-fixture-$$.ready"
cleanup() {
  if [[ -n "$fixture_pid" ]]; then
    if [[ -n "$fixture_url" ]]; then
      curl -fsS -X POST "$fixture_url/__fixture/shutdown?nonce=$fixture_nonce" >/dev/null 2>&1 || true
    fi
    kill "$fixture_pid" >/dev/null 2>&1 || true
    wait "$fixture_pid" >/dev/null 2>&1 || true
  fi
  rm -f "$fixture_log" "$fixture_ready"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $fresh CASCADE; DROP SCHEMA IF EXISTS $existing CASCADE; DROP SCHEMA IF EXISTS $duplicate CASCADE" >/dev/null
}
trap cleanup EXIT

create_tables() {
  local schema="$1"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 >/dev/null <<SQL
CREATE SCHEMA $schema;
SET search_path TO $schema;
CREATE TABLE audit_operations (
  id text PRIMARY KEY, user_id text, action_type text NOT NULL, action_detail jsonb,
  target_type text, target_id text, ip_address text, created_at timestamptz DEFAULT now()
);
CREATE TABLE audit_chain (
  seq bigserial PRIMARY KEY, tenant_id text NOT NULL DEFAULT '', event_type text NOT NULL,
  event_id text NOT NULL, payload_json jsonb NOT NULL, prev_hash text, payload_hash text NOT NULL,
  chain_hash text NOT NULL, signature text NOT NULL, created_at timestamptz DEFAULT now()
);
SQL
}

# Fresh schema + repeated migration.
create_tables "$fresh"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 >/dev/null <<SQL
SET search_path TO $fresh;
\i $MIGRATION
\i $MIGRATION
SQL

# Existing non-conflicting data migrates successfully.
create_tables "$existing"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 >/dev/null <<SQL
SET search_path TO $existing;
INSERT INTO audit_chain(tenant_id,event_type,event_id,payload_json,payload_hash,chain_hash,signature)
VALUES ('','other_event','existing-id','{}','p','c','s');
\i $MIGRATION
SQL

# Existing duplicate critical identities must be rejected, not hidden.
create_tables "$duplicate"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 >/dev/null <<SQL
SET search_path TO $duplicate;
INSERT INTO audit_chain(tenant_id,event_type,event_id,payload_json,payload_hash,chain_hash,signature)
VALUES ('','header_contract_conflict','duplicate-id','{}','p1','c1','s1'),
       ('','header_contract_conflict','duplicate-id','{}','p2','c2','s2');
SQL
if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL
SET search_path TO $duplicate;
\i $MIGRATION
SQL
then
  echo "pre-existing duplicate critical identity unexpectedly migrated" >&2
  exit 1
fi

# Exercise the actual repositories against the migrated fresh schema. These tests
# cover N concurrent same-occurrence writes, exact-one rows in both tables, a
# second occurrence with identical payload, and same-ID/different-payload collision.
if [[ "$DATABASE_URL" == *"?"* ]]; then
  SCHEMA_URL="${DATABASE_URL}&search_path=$fresh"
else
  SCHEMA_URL="${DATABASE_URL}?search_path=$fresh"
fi
(cd "$ROOT/apps/control-plane" && CONTENT_LOGS_TEST_DATABASE_URL="$SCHEMA_URL" GOTOOLCHAIN=go1.25.0 /usr/local/go/bin/go test ./internal/repository -run 'HeaderContract' -count=1)
(cd "$ROOT/apps/control-plane" && CONTENT_LOGS_TEST_DATABASE_URL="$SCHEMA_URL" GOTOOLCHAIN=go1.25.0 /usr/local/go/bin/go test ./internal/handler -run 'HeaderContractConflict(Ingest|ThreeBoundaries)' -count=1)

(
  cd "$ROOT/apps/control-plane"
  CONTENT_LOGS_TEST_DATABASE_URL="$SCHEMA_URL" \
    HEADER_CONTRACT_CENTRAL_FIXTURE_ADDR=127.0.0.1:0 \
    HEADER_CONTRACT_CENTRAL_FIXTURE_READY_FILE="$fixture_ready" \
    HEADER_CONTRACT_CENTRAL_FIXTURE_NONCE="$fixture_nonce" \
    GOTOOLCHAIN=go1.25.0 /usr/local/go/bin/go test ./internal/handler \
      -run '^TestHeaderContractCentralFixtureServer$' -count=1 -timeout=2m
) >"$fixture_log" 2>&1 &
fixture_pid=$!
for _ in $(seq 1 50); do
  if ! kill -0 "$fixture_pid" >/dev/null 2>&1; then
    cat "$fixture_log" >&2
    echo "real central audit fixture exited before becoming ready" >&2
    exit 1
  fi
  if [[ -s "$fixture_ready" ]]; then
    fixture_url="$(<"$fixture_ready")"
    if curl -fsS "$fixture_url/__fixture/health?nonce=$fixture_nonce" >/dev/null 2>&1; then
      break
    fi
  fi
  sleep 0.2
done
if [[ -z "$fixture_url" ]] || ! kill -0 "$fixture_pid" >/dev/null 2>&1 || ! curl -fsS "$fixture_url/__fixture/health?nonce=$fixture_nonce" >/dev/null 2>&1; then
  cat "$fixture_log" >&2
  echo "real central audit fixture failed to start" >&2
  exit 1
fi

(cd "$ROOT/apps/gateway-core" && HEADER_CONTRACT_CENTRAL_URL="$fixture_url" GOTOOLCHAIN=go1.25.0 /usr/local/go/bin/go test ./internal/auth -run '^TestAuthHeaderConflictPersistsToRealCentral$' -count=1)
(cd "$ROOT/apps/gateway-core" && HEADER_CONTRACT_CENTRAL_URL="$fixture_url" GOTOOLCHAIN=go1.25.0 /usr/local/go/bin/go test ./internal/handler -run '^TestReverseProxyHeaderConflictPersistsToRealCentral$' -count=1)
(cd "$ROOT/apps/proxy-server" && HEADER_CONTRACT_CENTRAL_URL="$fixture_url" GOTOOLCHAIN=go1.25.0 /usr/local/go/bin/go test ./internal/handler -run '^TestProxy(HTTP|MITM)HeaderConflictPersistsToRealCentral$' -count=1)

require_evidence() {
  local url="$1" response status body
  response="$(curl -sS -w $'\n%{http_code}' "$url")"
  status="${response##*$'\n'}"
  body="${response%$'\n'*}"
  printf '%s\n' "$body"
  if [[ "$status" != "200" ]]; then
    printf 'evidence endpoint returned HTTP %s: %s\n' "$status" "$url" >&2
    return 1
  fi
}

require_evidence "$fixture_url/__fixture/evidence?request_id=r2-gateway-auth&service=gateway-core.api&kind=session_id"
require_evidence "$fixture_url/__fixture/evidence?request_id=r2-gateway-reverse&service=gateway-core.reverse-proxy&kind=agent_type"
require_evidence "$fixture_url/__fixture/evidence?request_id=r2-proxy-http&service=proxy-server.mitm&kind=agent_type"
require_evidence "$fixture_url/__fixture/evidence?request_id=r2-proxy-mitm&service=proxy-server.mitm&kind=agent_type"
curl -fsS -X POST "$fixture_url/__fixture/shutdown?nonce=$fixture_nonce" >/dev/null
wait "$fixture_pid"
fixture_pid=""

echo "PASS: migration plus real gateway auth, reverse proxy, proxy HTTP/MITM rejection, zero-downstream, exact dual persistence, redaction, and WORM verification"
