#!/usr/bin/env bash
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels policy-capability-catalog
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTROL_PLANE_DIR="$ROOT_DIR/apps/control-plane"
TEST_PATTERN='^(TestSecurityCapabilityMigrationCoversStaticEngineCategoriesExactly|TestSecurityCapabilityMigrationDynamicAllowlistIsExplicit|TestExactPolicyCapabilityBindingsMatchAuditedCatalog|TestDefaultPolicyCodesAreStableUniqueAndMigrationDoesNotAddRules|TestDefaultPolicyIdentityDoesNotDependOnDisplayName|TestPolicyCapabilityMigrationIsIdempotentAndPreservesPolicies|TestSeedDefaultSubRulesCreatesStableCodesAndExactBindings|TestSeedDefaultSubRulesRollsBackWhenCapabilityCatalogIsIncomplete|TestSeedDefaultSubRulesKeepsPoliciesWhenCapabilityIsDisabled|TestInitDetectorsUsesDistinctTenantDefaultsAndIsIdempotent|TestInitDetectorsConcurrentCallsBothSucceedWithoutDuplicateSeeds|TestIsSafeRuntimeRegexMatchesEngineContract|TestMaxRuntimeRegexPatternBytesIsEngineLimit|TestRuleIsCapabilityCatalogUsesStablePolicyCodeAfterRename|TestSecurityPolicyJSONHidesInternalCodesAndComponents|TestBuiltinRuleOverridePatchMigrationAllowsPartialOverrides|TestListSecurityPoliciesReturnsExactlyApplicable260AndHonestBasis|TestListSecurityPoliciesUsesTenantIndustryFromDatabase|TestCreateSecurityPolicyKeepsDraftsDisabledAndAddsConfiguredPolicies|TestCreateSecurityPolicyUsesStableRuleSetAndCanonicalPythonMatcher|TestUpdateSecurityPolicyMatcherPreservesScene|TestDisabledCapabilitiesRespectAnyBindingAndReportDegradation|TestSecurityPolicyUpdateValidatesCapabilitiesAndSystemOverrides|TestSystemPolicyRejectsMaskForNonMaskableCapability|TestSystemPolicyConcurrentPartialOverridesDoNotLoseFields|TestBatchUpdateSecurityPoliciesRejectsTrimmedDuplicatesAndCommitsSuccess|TestBatchUpdateSecurityPoliciesIsAtomicAcrossTenantAndSystem|TestSecurityPolicyEmptyIDIsNotFound|TestUpdateSecurityPolicyReplacesCapabilityBindings)$'
TEST_PATTERN="${TEST_PATTERN%)*}|TestListCompilableRulesUsesTenantCapabilityOverride|TestNewDefaultPolicyRuleIDUsesFullUUID)$"
POSTGRES_CONTAINER=''
RULES_TEST_POSTGRES_PASSWORD=''
TEST_OUTPUT="$(mktemp)"

cleanup() {
  local status=$?
  if [[ -n "$POSTGRES_CONTAINER" ]]; then
    docker rm -f -v "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
  fi
  RULES_TEST_POSTGRES_PASSWORD=''
  rm -f "$TEST_OUTPUT"
  return "$status"
}
trap cleanup EXIT

fail() {
  echo "[fail] $*" >&2
  exit 1
}

emit_test_output() {
  sed -E \
    -e 's#(postgres(ql)?://[^:/@[:space:]]+):[^@[:space:]]+@#\1:[redacted]@#g' \
    -e 's#([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][=:])[^[:space:],;]+#\1[redacted]#g' \
    "$TEST_OUTPUT"
}

random_postgres_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
    return 0
  fi
  if command -v od >/dev/null 2>&1 && [[ -r /dev/urandom ]]; then
    od -An -N 24 -tx1 /dev/urandom | tr -d ' \n'
    printf '\n'
    return 0
  fi
  fail "a secure random generator is required for controlled PostgreSQL"
}

start_controlled_postgres() {
  command -v docker >/dev/null 2>&1 || fail "Docker is required when RULES_TEST_DATABASE_URL is not set"
  docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable and no explicit PostgreSQL DSN was provided"

  POSTGRES_CONTAINER="jjdguard-policy-capability-${BASHPID}"
  RULES_TEST_POSTGRES_PASSWORD="$(random_postgres_password)"
  if ! POSTGRES_PASSWORD="$RULES_TEST_POSTGRES_PASSWORD" docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --rm \
    --name "$POSTGRES_CONTAINER" \
    --publish 127.0.0.1::5432 \
    --env POSTGRES_PASSWORD \
    --env POSTGRES_USER=jjdguard_policy_test \
    --env POSTGRES_DB=jjdguard_policy_test \
    postgres:16-alpine >/dev/null; then
    fail "failed to start controlled PostgreSQL container"
  fi

  local ready=0
  for _ in $(seq 1 60); do
    if docker exec "$POSTGRES_CONTAINER" pg_isready -h 127.0.0.1 -U jjdguard_policy_test -d jjdguard_policy_test >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ "$ready" == "1" ]] || fail "controlled PostgreSQL did not become ready"

  local binding port
  binding="$(docker port "$POSTGRES_CONTAINER" 5432/tcp 2>/dev/null | tail -n 1)"
  port="${binding##*:}"
  [[ "$port" =~ ^[0-9]+$ ]] || fail "unable to resolve controlled PostgreSQL port"
  RULES_TEST_DATABASE_URL="postgres://jjdguard_policy_test:${RULES_TEST_POSTGRES_PASSWORD}@127.0.0.1:${port}/jjdguard_policy_test?sslmode=disable"
  export RULES_TEST_DATABASE_URL
}

if [[ -z "${RULES_TEST_DATABASE_URL:-}" ]]; then
  start_controlled_postgres
fi

if ! command -v go >/dev/null 2>&1; then
  for go_dir in /usr/local/go/bin /usr/lib/go/bin /opt/go/bin; do
    if [[ -x "$go_dir/go" ]]; then
      PATH="$go_dir:$PATH"
      export PATH
      break
    fi
  done
fi
command -v go >/dev/null 2>&1 || fail "Go is required for the policy-capability gate"

set +e
(
  cd "$CONTROL_PLANE_DIR"
  GOWORK=off go test ./internal/repository ./internal/handler -run "$TEST_PATTERN" -count=1 -v
) >"$TEST_OUTPUT" 2>&1
test_status=$?
set -e

emit_test_output
[[ "$test_status" == "0" ]] || fail "policy-capability tests failed"
if grep -Fq -- '--- SKIP:' "$TEST_OUTPUT" || grep -Fq 'no tests to run' "$TEST_OUTPUT"; then
  fail "policy-capability test was skipped"
fi

for test_name in \
  TestSecurityCapabilityMigrationCoversStaticEngineCategoriesExactly \
  TestSecurityCapabilityMigrationDynamicAllowlistIsExplicit \
  TestExactPolicyCapabilityBindingsMatchAuditedCatalog \
  TestDefaultPolicyCodesAreStableUniqueAndMigrationDoesNotAddRules \
  TestDefaultPolicyIdentityDoesNotDependOnDisplayName \
  TestPolicyCapabilityMigrationIsIdempotentAndPreservesPolicies \
  TestSeedDefaultSubRulesCreatesStableCodesAndExactBindings \
  TestSeedDefaultSubRulesRollsBackWhenCapabilityCatalogIsIncomplete \
  TestSeedDefaultSubRulesKeepsPoliciesWhenCapabilityIsDisabled \
  TestInitDetectorsUsesDistinctTenantDefaultsAndIsIdempotent \
  TestInitDetectorsConcurrentCallsBothSucceedWithoutDuplicateSeeds \
  TestIsSafeRuntimeRegexMatchesEngineContract \
  TestMaxRuntimeRegexPatternBytesIsEngineLimit \
  TestRuleIsCapabilityCatalogUsesStablePolicyCodeAfterRename \
  TestSecurityPolicyJSONHidesInternalCodesAndComponents \
  TestBuiltinRuleOverridePatchMigrationAllowsPartialOverrides \
  TestListSecurityPoliciesReturnsExactlyApplicable260AndHonestBasis \
  TestListSecurityPoliciesUsesTenantIndustryFromDatabase \
  TestCreateSecurityPolicyKeepsDraftsDisabledAndAddsConfiguredPolicies \
  TestCreateSecurityPolicyUsesStableRuleSetAndCanonicalPythonMatcher \
  TestUpdateSecurityPolicyMatcherPreservesScene \
  TestDisabledCapabilitiesRespectAnyBindingAndReportDegradation \
  TestSecurityPolicyUpdateValidatesCapabilitiesAndSystemOverrides \
  TestSystemPolicyRejectsMaskForNonMaskableCapability \
  TestSystemPolicyConcurrentPartialOverridesDoNotLoseFields \
  TestBatchUpdateSecurityPoliciesRejectsTrimmedDuplicatesAndCommitsSuccess \
  TestBatchUpdateSecurityPoliciesIsAtomicAcrossTenantAndSystem \
  TestSecurityPolicyEmptyIDIsNotFound \
  TestListCompilableRulesUsesTenantCapabilityOverride \
  TestNewDefaultPolicyRuleIDUsesFullUUID \
  TestUpdateSecurityPolicyReplacesCapabilityBindings; do
  grep -Fq -- "--- PASS: $test_name" "$TEST_OUTPUT" || fail "missing PASS marker for $test_name"
done

echo '[ok] policy catalog, exact bindings, tenant CRUD, truthful readiness, rollback and concurrency passed'
