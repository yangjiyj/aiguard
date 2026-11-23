#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY="$ROOT/scripts/tests/fixtures/expected-plan1-deferred-legacy-files.txt"
MODE=strict
CANDIDATE=
if [[ "${1:-}" == "--write-candidate" ]]; then
  [[ $# -eq 2 && -n "${2:-}" ]] || { echo 'active-brand: --write-candidate requires a path' >&2; exit 64; }
  MODE=write
  CANDIDATE=$2
elif (($#)); then
  echo 'active-brand: unsupported argument' >&2
  exit 64
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
actual="$tmp/actual.tsv"
hard="$tmp/hard.tsv"

python3 - "$ROOT" "$actual" "$hard" <<'PY'
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
from collections import Counter

root = pathlib.Path(sys.argv[1])
actual_path = pathlib.Path(sys.argv[2])
hard_path = pathlib.Path(sys.argv[3])
raw_paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    cwd=root,
)
paths = [p for p in raw_paths.split(b"\0") if p]
retired = re.compile(r"(?i)new(?:[ _-]?api)|(?<![A-Za-z0-9])na_")
pairs: set[tuple[str, str]] = set()
hard_counts: Counter[str] = Counter()

control = {
    "scripts/tests/test_active_brand_contract.sh",
    "scripts/tests/fixtures/expected-plan1-deferred-legacy-files.txt",
}
neutral = {
    "deploy/migrations/prepare-jjdguard-neutral-baseline.sh",
    "deploy/migrations/jjdguard-neutral-baseline-manifest.tsv",
    "deploy/tests/test_jjdguard_neutral_baseline.sh",
}
license_paths = {
    "apps/control-plane/internal/license/license.go",
    "apps/control-plane/internal/license/license_test.go",
    "apps/control-plane/internal/license/e2e_renewal_test.go",
    "apps/control-plane/internal/license/testdata/e2e_gateway_license.json",
    "apps/control-plane/internal/handler/license.go",
    "apps/control-plane/internal/handler/license_test.go",
}
key_paths = {
    "packages/shared-go/authhelpers/authhelpers_test.go",
    "apps/control-plane/internal/repository/key_test.go",
    "apps/gateway-core/internal/auth/auth_test.go",
    "apps/gateway-core/internal/auth/scope_test.go",
    "apps/gateway-core/internal/auth/legacy_middleware_test.go",
}

def classify(path: str, line: str, match: str, is_binary: bool) -> str | None:
    low = line.lower()
    if path in control:
        return "control-file"
    if path in neutral:
        return "database-neutral-baseline"
    if is_binary:
        return "tracked-binary"
    if path.startswith("docs/") or path.startswith("CHANGELOG") or path.startswith("enterprise-ai-portal/docs/"):
        return "historical"
    if path == "scripts/tests/test_go_module_identity.sh":
        return "module-identity-fixture"
    if path in {"deploy/docker-compose/deploy-oneclick.sh", "deploy/docker-compose/deploy-offline.sh"} and "newapi-enterprise-local" in low:
        return "legacy-layout"
    if match.lower().startswith("na_") and path in key_paths:
        return "api-key-compat"
    if path in license_paths and ("enterprise" in low or "license" in low or "revocation" in low):
        return "license-compat"
    if "x-newapi-" in low or ("newapi" in low and "header" in path):
        return "header-compat"
    if "newapi_" in line or "NEWAPI_" in line:
        if path.endswith("config_test.go") or path == "apps/tier1-classifier/tests/test_health_auth.py" or path == "deploy/tests/test_jjdguard_compose_env_contract.sh":
            return "env-compat"
    if path.endswith("config_test.go") and "newapi" in low:
        return "env-compat"
    if match.lower().startswith("na_") and (path.endswith("_test.go") or "/test/" in path or "/tests/" in path):
        return "api-key-compat"
    if ("newapi.com" in low or "*.newapi.com" in low) and ("/test/" in path or "/tests/" in path or path.endswith("_test.go")):
        return "synthetic-fixture"
    if "x-newapi-" in low or "newapi-" in low and "header" in low:
        if "header" in path or path.endswith("apps/security-engine/tests/test_api.py"):
            return "header-compat"
    if "newapi_" in line or "NEWAPI_" in line:
        if "portal-proxy" in low or path.endswith("docker-compose.yml") or path.endswith("docker-compose.offline.yml"):
            return "opaque-portal-proxy"
        if path.startswith("enterprise-ai-portal/") or "tier1-classifier" in path:
            return "env-compat"
    if path == "deploy/docker-compose/tests/identity-sso-e2e.sh" and any(
        key in line for key in ("NEWAPI_CP_URL", "NEWAPI_PORTAL_API_SECRET")
    ):
        return "opaque-portal-proxy"
    if "newapi-net" in low:
        return "legacy-network"
    if path.endswith(".egg-info/PKG-INFO") or ".egg-info/" in path:
        return "generated-fixture"
    if path in {"deploy/lib/drift-audit.py", "deploy/migrate-private.sh"}:
        return "database-identifier"
    db_words = ("postgres", "database", "dsn", "db_", "psql", "schema", "migration", "-u newapi", "-d newapi")
    if any(word in low for word in db_words):
        return "database-identifier"
    return None

for raw in paths:
    try:
        path = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        hard_counts["<invalid-utf8-path>"] += 1
        continue
    if path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
        hard_counts[path] += 1
        continue
    full = root / path
    try:
        data = full.read_bytes()
    except OSError:
        hard_counts[path] += 1
        continue
    is_binary = b"\0" in data
    text = data.decode("utf-8", "replace")
    records = [(path, path)] + [(line, path) for line in text.splitlines()]
    for value, record_path in records:
        for found in retired.finditer(value):
            category = classify(record_path, value, found.group(0), is_binary)
            if category is None:
                hard_counts[record_path] += 1
            else:
                pairs.add((category, record_path))

with actual_path.open("w", encoding="utf-8", newline="\n") as handle:
    for category, path in sorted(pairs, key=lambda row: (row[0].encode(), row[1].encode())):
        handle.write(f"{category}\t{path}\n")
with hard_path.open("w", encoding="utf-8", newline="\n") as handle:
    for path, count in sorted(hard_counts.items(), key=lambda row: row[0].encode()):
        handle.write(f"{path}\t{count}\n")
PY

if [[ -s "$hard" ]]; then
  while IFS=$'\t' read -r path count; do
    printf 'active-brand: hard-failure path=%s category=unclassified count=%s\n' "$path" "$count" >&2
  done <"$hard"
  echo 'active-brand: hard failures must be fixed before deferred inventory can be written' >&2
  exit 1
fi

validate_inventory() {
  local file=$1
  [[ -f "$file" ]] || { echo "active-brand: inventory missing: ${file#$ROOT/}" >&2; return 1; }
  [[ "$(tail -c 1 "$file" | od -An -tuC | tr -d ' ')" == 10 ]] || {
    echo 'active-brand: inventory must end in LF' >&2; return 1;
  }
  LC_ALL=C sort -c -u "$file" || { echo 'active-brand: inventory must be C-sorted and unique' >&2; return 1; }
  awk -F '\t' '
    NF != 2 ||
    $1 !~ /^[a-z0-9-]+$/ ||
    $2 == "" || $2 ~ /^\// || $2 ~ /(^|\/)\.\.($|\/)/ ||
    $2 ~ /[*?[]/ { exit 1 }
  ' "$file" || { echo 'active-brand: invalid inventory row' >&2; return 1; }
}

if [[ "$MODE" == write ]]; then
  install -m 0600 "$actual" "$CANDIDATE"
  printf 'active-brand: candidate=%s entries=%s\n' "$CANDIDATE" "$(wc -l <"$actual" | tr -d ' ')"
  exit 0
fi

validate_inventory "$INVENTORY"
if ! cmp -s "$actual" "$INVENTORY"; then
  comm -3 "$INVENTORY" "$actual" | awk '{print "active-brand: inventory-drift category/path-only " $0}' >&2
  exit 1
fi
printf 'active_brand_contract=ok deferred_entries=%s hard_failures=0\n' "$(wc -l <"$actual" | tr -d ' ')"
