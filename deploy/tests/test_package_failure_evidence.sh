#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COLLECTOR="$ROOT/deploy/docker-compose/collect-package-failure-evidence.sh"
RUN_PACKAGER="$ROOT/deploy/docker-compose/package-offline-run.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
[[ -x "$COLLECTOR" ]] || fail "failure evidence collector is missing: $COLLECTOR"
grep -Fq 'collect-package-failure-evidence.sh' "$RUN_PACKAGER" || fail 'run packager does not invoke the evidence collector'
grep -Fq 'rm -rf -- "$work"' "$RUN_PACKAGER" || fail 'run packager does not unconditionally remove work payload'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
output="$tmp/output"
work="$tmp/jjdguard-run.fixture"
outside="$tmp/outside-sentinel"
mkdir -p "$work/logs" "$output"
printf '%s\n' keep >"$outside"
printf '%s\n' 'normal diagnostic line' 'password=must-not-leak' 'Authorization: Bearer must-not-leak' 'cookie=session-must-not-leak' >"$work/logs/build.log"
printf '%s\n' 'candidate failed before signing' >"$work/failure-summary.tsv"
printf '%s\n' '{}' >"$work/run-manifest.json"
printf '%s\n' 'DB_PASSWORD=must-not-leak' >"$work/.env"
printf '%s\n' private >"$work/release-private.pem"
printf '%s\n' cookie >"$work/browser.cookie"
printf '%s\n' image >"$work/images.tar"
printf '%s\n' bundle >"$work/jjdguard-full.tar.gz"
printf '%s\n' payload >"$work/payload.bin"
truncate -s 300M "$work/logs/huge.log"

"$COLLECTOR" --output-dir "$output" --work-dir "$work" --exit-code 73
failure_root="$output/evidence/failures"
mapfile -t records < <(find "$failure_root" -mindepth 1 -maxdepth 1 -type d | sort)
[[ "${#records[@]}" == 1 ]] || fail 'collector did not create exactly one failure record'
record="${records[0]}"
[[ -f "$record/logs/build.log" && -f "$record/failure-summary.tsv" && -f "$record/run-manifest.json" && -f "$record/evidence-index.tsv" ]] || fail 'allowed evidence is missing'
for forbidden in .env release-private.pem browser.cookie images.tar jjdguard-full.tar.gz payload.bin logs/huge.log; do
  [[ ! -e "$record/$forbidden" && ! -L "$record/$forbidden" ]] || fail "forbidden evidence retained: $forbidden"
done
if rg -n --hidden --glob '*' 'must-not-leak' "$record" >/dev/null; then
  fail 'sensitive diagnostic content was retained'
fi
grep -Fq '[REDACTED]' "$record/logs/build.log" || fail 'sensitive log values were not redacted'
grep -Fq $'dropped\t.env\tsensitive-name' "$record/evidence-index.tsv" || fail '.env drop reason is missing'
grep -Fq $'dropped\tlogs/huge.log\ttoo-large' "$record/evidence-index.tsv" || fail 'large log drop reason is missing'
[[ "$(du -sb "$record" | awk '{print $1}')" -le $((256 * 1024 * 1024)) ]] || fail 'failure evidence exceeds 256 MiB cap'
[[ "$(cat "$outside")" == keep ]] || fail 'collector touched a path outside evidence/failures'

# Retention must be bounded to the ten newest records and never traverse a
# symlinked evidence root.
for number in $(seq 1 11); do
  mkdir -p "$failure_root/old-$number"
  printf '%s\n' old >"$failure_root/old-$number/summary.txt"
  touch -d "$((20 + number)) days ago" "$failure_root/old-$number"
done
"$COLLECTOR" --output-dir "$output" --work-dir "$work" --exit-code 74
[[ "$(find "$failure_root" -mindepth 1 -maxdepth 1 -type d | wc -l)" -le 10 ]] || fail 'retention exceeds ten records'

link_output="$tmp/link-output"
ln -s "$output" "$link_output"
if "$COLLECTOR" --output-dir "$link_output" --work-dir "$work" --exit-code 75 >/dev/null 2>&1; then
  fail 'collector accepted a symlinked output root'
fi

# The packager's EXIT trap must retain bounded evidence then remove its original
# jjdguard-run.* payload even when a failure occurs after work allocation.
trap_output="$tmp/trap-output"
trap_tmp="$tmp/trap-tmp"
mkdir -p "$trap_output" "$trap_tmp"
openssl genpkey -algorithm Ed25519 -out "$tmp/test-release.key" >/dev/null 2>&1
chmod 0400 "$tmp/test-release.key"
set +e
JJD_RELEASE_TESTING=1 JJD_TEST_FORCE_PACKAGE_FAILURE=1 TMPDIR="$trap_tmp" \
  OFFLINE_MANIFEST_SIGNING_KEY_FILE="$tmp/test-release.key" \
  "$RUN_PACKAGER" amd64 "$trap_output" >/dev/null 2>&1
trap_status=$?
set -e
[[ "$trap_status" == 73 ]] || fail "forced packager failure exit code drifted: $trap_status"
[[ ! -e "$trap_tmp"/jjdguard-run.* ]] || fail 'packager left its original jjdguard-run work directory'
find "$trap_output/evidence/failures" -type f -name forced-failure.log -print -quit | grep -q . || fail 'packager trap did not retain allowed failure evidence'

echo '[ok] failure evidence allowlist, redaction, bounds, retention, and path containment passed'
