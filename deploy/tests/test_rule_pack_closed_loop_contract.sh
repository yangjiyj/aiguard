#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$ROOT_DIR/deploy/tests/test_rule_pack_closed_loop.sh"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

[[ -x "$GATE" ]] || fail "rule-pack closed-loop gate is missing or not executable"
bash -n "$GATE"

grep -Fq 'RULES_TEST_DATABASE_URL' "$GATE" || fail "gate must accept an explicit PostgreSQL DSN"
grep -Fq 'postgres:16-alpine' "$GATE" || fail "gate must provision a controlled PostgreSQL fallback"
grep -Fq 'pg_isready' "$GATE" || fail "gate must wait for PostgreSQL readiness"
grep -Fq 'POSTGRES_PASSWORD' "$GATE" || fail "controlled PostgreSQL must use an ephemeral credential"
if grep -Fq 'POSTGRES_HOST_AUTH_METHOD=trust' "$GATE"; then
  fail "controlled PostgreSQL must not expose passwordless trust authentication"
fi
grep -Fq -- "-run '^TestRulePackRealPostgresControlPlaneAndSecurityEngineClosedLoop$'" "$GATE" || fail "gate must target the exact cross-component test"
grep -Fq -- '--- SKIP:' "$GATE" || fail "gate must reject skipped tests"
grep -Fq 'docker rm -f -v' "$GATE" || fail "gate must clean up its temporary PostgreSQL container together with its anonymous volume"
grep -Eq '^trap .* EXIT$' "$GATE" || fail "gate must register an EXIT cleanup trap"
grep -Fq '[redacted]' "$GATE" || fail "gate must redact credentials from test output"
if grep -Eq '(^|[[:space:]])set[[:space:]]+-x' "$GATE"; then
  fail "gate must never enable shell tracing around credentials"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
fake_bin="$tmp_dir/bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
echo 'connect postgres://test-user:test-password@127.0.0.1/test password=test-password'
echo '--- SKIP: TestRulePackRealPostgresControlPlaneAndSecurityEngineClosedLoop (0.00s)'
echo 'PASS'
exit 0
EOF
cat >"$fake_bin/docker" <<'EOF'
#!/bin/sh
exit 127
EOF
chmod 700 "$fake_bin/go" "$fake_bin/docker"

set +e
RULES_TEST_DATABASE_URL='postgres://test-user:test-password@127.0.0.1/test' \
  PATH="$fake_bin:$PATH" bash "$GATE" >"$tmp_dir/skip.out" 2>&1
skip_status=$?
set -e
[[ "$skip_status" -ne 0 ]] || fail "a skipped exact test must fail the hard gate"
grep -Fq 'rule-pack closed-loop test was skipped' "$tmp_dir/skip.out" || fail "skip failure reason is missing"
grep -Fq '[redacted]' "$tmp_dir/skip.out" || fail "dynamic output did not redact credentials"
if grep -Fq 'test-password' "$tmp_dir/skip.out"; then
  fail "dynamic output leaked a credential"
fi

set +e
(
  unset RULES_TEST_DATABASE_URL
  PATH="$fake_bin:$PATH" bash "$GATE"
) >"$tmp_dir/docker.out" 2>&1
docker_status=$?
set -e
[[ "$docker_status" -ne 0 ]] || fail "missing Docker must fail without an explicit PostgreSQL DSN"
grep -Fq 'Docker daemon is unavailable' "$tmp_dir/docker.out" || fail "missing-Docker failure reason is missing"

echo '[ok] rule-pack closed-loop hard-gate contract passed'
