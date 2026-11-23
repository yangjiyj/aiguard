#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner="$repo_root/deploy/acceptance/run-vm-matrix.sh"
tmpdir=$(mktemp -d)
upstream_pid=
bad_upstream_pid=
snapshot_sparse_low_space=
cleanup() {
  if [[ -n "$upstream_pid" ]]; then
    kill "$upstream_pid" >/dev/null 2>&1 || true
    wait "$upstream_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$bad_upstream_pid" ]]; then
    kill "$bad_upstream_pid" >/dev/null 2>&1 || true
    wait "$bad_upstream_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$snapshot_sparse_low_space" ]]; then
    rm -f -- "$snapshot_sparse_low_space"
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT

# First implementation slice: FAIL records must be structured, redacted, and
# unable to escape their evidence root. record-step.py does not exist yet, so
# this invocation is deliberately the next real red test.
record_step="$repo_root/deploy/acceptance/record-step.py"
evidence_root="$tmpdir/evidence"
mkdir -p "$evidence_root"
chmod 700 "$evidence_root"
mkdir -p "$evidence_root/logs"
step_log="$evidence_root/logs/step.log"
printf '%s\n' 'step_recorded' > "$step_log"
safe_record="$evidence_root/records/path-escape.json"

python3 "$record_step" \
  --evidence-root "$evidence_root" \
  --output "$safe_record" \
  --scenario path-escape \
  --step reject-unsafe-output \
  --status FAIL \
  --exit-code 65 \
  --started-at 2026-08-09T00:00:00Z \
  --finished-at 2026-08-09T00:00:01Z \
  --log "$step_log" \
  --details-json '{"password":"never-record","token":"never-record","cookie":"never-record","raw_payload":"never-record","summary":"unsafe output rejected"}'

python3 - "$safe_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["schema"] == "jjdguard-vm-step-record/v1"
assert record["status"] == "FAIL"
assert record["exit_code"] == 65
assert len(record["log_sha256"]) == 64
serialized = json.dumps(record, sort_keys=True)
for forbidden in ("password", "token", "cookie", "raw payload", "never-record"):
    assert forbidden not in serialized, serialized
PY

# A raw log is part of the final evidence snapshot, so a hash alone must not
# turn sensitive content into admissible evidence.
sensitive_log="$evidence_root/logs/sensitive.log"
sensitive_record="$evidence_root/records/sensitive-log.json"
printf '%s\n' 'password=never-record token=never-record cookie=never-record raw payload=never-record prompt=never-record secret=never-record' > "$sensitive_log"
set +e
python3 "$record_step" \
  --evidence-root "$evidence_root" \
  --output "$sensitive_record" \
  --scenario sensitive-log \
  --step reject-raw-content \
  --status FAIL \
  --exit-code 67 \
  --started-at 2026-08-09T00:00:00Z \
  --finished-at 2026-08-09T00:00:01Z \
  --log "$sensitive_log"
sensitive_log_exit=$?
set -e
[[ "$sensitive_log_exit" -ne 0 ]] || { printf 'record-step accepted sensitive raw log content\n' >&2; exit 1; }
[[ ! -e "$sensitive_record" ]] || { printf 'record-step wrote evidence for sensitive raw log content\n' >&2; exit 1; }

# Key names frequently seen in HTTP client traces must be rejected even when
# they do not exactly equal the generic token/cookie spellings above.
for sensitive_key in access_token session_cookie rawPayload; do
  sensitive_key_log="$evidence_root/logs/$sensitive_key.log"
  sensitive_key_record="$evidence_root/records/$sensitive_key.json"
  printf '%s=never-record\n' "$sensitive_key" > "$sensitive_key_log"
  set +e
  python3 "$record_step" \
    --evidence-root "$evidence_root" \
    --output "$sensitive_key_record" \
    --scenario sensitive-log \
    --step reject-sensitive-key \
    --status FAIL \
    --exit-code 67 \
    --started-at 2026-08-09T00:00:00Z \
    --finished-at 2026-08-09T00:00:01Z \
    --log "$sensitive_key_log"
  sensitive_key_exit=$?
  set -e
  [[ "$sensitive_key_exit" -ne 0 ]] || { printf 'record-step accepted %s raw log content\n' "$sensitive_key" >&2; exit 1; }
  [[ ! -e "$sensitive_key_record" ]] || { printf 'record-step wrote evidence for %s raw log content\n' "$sensitive_key" >&2; exit 1; }
done

# The recorder can be called directly, without the formal writer as a later
# guard. Payload and prompt values in otherwise safe field names must therefore
# be redacted before the step record ever reaches disk.
for sensitive_detail in payload prompt; do
  sensitive_detail_record="$evidence_root/records/sensitive-$sensitive_detail-value.json"
  python3 "$record_step" \
    --evidence-root "$evidence_root" \
    --output "$sensitive_detail_record" \
    --scenario sensitive-detail \
    --step redact-sensitive-value \
    --status FAIL \
    --exit-code 67 \
    --started-at 2026-08-09T00:00:00Z \
    --finished-at 2026-08-09T00:00:01Z \
    --log "$step_log" \
    --details-json "{\"os\":\"$sensitive_detail=private\"}"
  python3 - "$sensitive_detail_record" "$sensitive_detail" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
term = sys.argv[2] + "=private"
raw = path.read_bytes()
if term.encode("utf-8") in raw:
    raise SystemExit("record-step retained sensitive " + sys.argv[2] + " detail")
record = json.loads(raw)
assert record["details"] == {"os": "[redacted]"}
PY
done

set +e
python3 "$record_step" \
  --evidence-root "$evidence_root" \
  --output "$tmpdir/escaped.json" \
  --scenario path-escape \
  --step reject-unsafe-output \
  --status FAIL \
  --exit-code 65 \
  --started-at 2026-08-09T00:00:00Z \
  --finished-at 2026-08-09T00:00:01Z \
  --log "$step_log"
escape_exit=$?
set -e
[[ "$escape_exit" -ne 0 ]] || { printf 'record-step accepted an escaping output path\n' >&2; exit 1; }
[[ ! -e "$tmpdir/escaped.json" ]] || { printf 'record-step wrote outside evidence root\n' >&2; exit 1; }

# Logs are evidence too: their file descriptor must be anchored below the
# evidence root, and the recorder itself owns status/exit-code semantics.
outside_log="$tmpdir/outside.log"
printf '%s\n' 'outside-log' > "$outside_log"
set +e
python3 "$record_step" \
  --evidence-root "$evidence_root" \
  --output "$evidence_root/records/outside-log.json" \
  --scenario log-boundary \
  --step reject-outside-log \
  --status FAIL \
  --exit-code 66 \
  --started-at 2026-08-09T00:00:00Z \
  --finished-at 2026-08-09T00:00:01Z \
  --log "$outside_log"
outside_log_exit=$?
set -e
[[ "$outside_log_exit" -ne 0 ]] || { printf 'record-step accepted a log outside evidence root\n' >&2; exit 1; }
[[ ! -e "$evidence_root/records/outside-log.json" ]] || { printf 'record-step wrote evidence for an outside log\n' >&2; exit 1; }

mkdir -p "$tmpdir/external-log-parent"
printf '%s\n' 'external-log' > "$tmpdir/external-log-parent/log.txt"
ln -s "$tmpdir/external-log-parent" "$evidence_root/log-link"
set +e
python3 "$record_step" \
  --evidence-root "$evidence_root" \
  --output "$evidence_root/records/linked-log.json" \
  --scenario log-boundary \
  --step reject-linked-log \
  --status FAIL \
  --exit-code 66 \
  --started-at 2026-08-09T00:00:00Z \
  --finished-at 2026-08-09T00:00:01Z \
  --log "$evidence_root/log-link/log.txt"
linked_log_exit=$?
set -e
[[ "$linked_log_exit" -ne 0 ]] || { printf 'record-step accepted an intermediate log symlink\n' >&2; exit 1; }

mkfifo "$evidence_root/logs/fifo.log"
set +e
python3 "$record_step" \
  --evidence-root "$evidence_root" \
  --output "$evidence_root/records/fifo-log.json" \
  --scenario log-boundary \
  --step reject-fifo-log \
  --status FAIL \
  --exit-code 66 \
  --started-at 2026-08-09T00:00:00Z \
  --finished-at 2026-08-09T00:00:01Z \
  --log "$evidence_root/logs/fifo.log"
fifo_log_exit=$?
set -e
[[ "$fifo_log_exit" -ne 0 ]] || { printf 'record-step accepted a FIFO log\n' >&2; exit 1; }

for semantics in pass-nonzero fail-zero; do
  if [[ "$semantics" == pass-nonzero ]]; then
    status=PASS
    code=1
  else
    status=FAIL
    code=0
  fi
  set +e
  python3 "$record_step" \
    --evidence-root "$evidence_root" \
    --output "$evidence_root/records/$semantics.json" \
    --scenario log-boundary \
    --step enforce-status-exit \
    --status "$status" \
    --exit-code "$code" \
    --started-at 2026-08-09T00:00:00Z \
    --finished-at 2026-08-09T00:00:01Z \
    --log "$step_log"
  semantics_exit=$?
  set -e
  [[ "$semantics_exit" -ne 0 ]] || { printf 'record-step accepted invalid %s semantics\n' "$semantics" >&2; exit 1; }
done

# Direct CLI callers do not get the runner's root validation. They still must
# reject a root whose intermediate component resolves through a symlink.
recorder_root_parent="$tmpdir/recorder-root-parent"
recorder_root_external="$tmpdir/recorder-root-external"
mkdir -p "$recorder_root_parent" "$recorder_root_external/evidence/logs"
printf '%s\n' 'direct-recorder-root' > "$recorder_root_external/evidence/logs/input.log"
ln -s "$recorder_root_external" "$recorder_root_parent/middle"
set +e
python3 "$record_step" \
  --evidence-root "$recorder_root_parent/middle/evidence" \
  --output "$recorder_root_parent/middle/evidence/records/intermediate-root.json" \
  --scenario root-boundary \
  --step reject-intermediate-root-symlink \
  --status FAIL \
  --exit-code 68 \
  --started-at 2026-08-09T00:00:00Z \
  --finished-at 2026-08-09T00:00:01Z \
  --log "$recorder_root_parent/middle/evidence/logs/input.log"
recorder_root_exit=$?
set -e
[[ "$recorder_root_exit" -ne 0 ]] || { printf 'record-step accepted an intermediate evidence-root symlink\n' >&2; exit 1; }
[[ ! -e "$recorder_root_external/evidence/records/intermediate-root.json" ]] || {
  printf 'record-step wrote through an intermediate evidence-root symlink\n' >&2
  exit 1
}

# The index must use the exact verifier-facing schema and must not hash unsafe
# filesystem nodes. evidence-index.py is intentionally absent for this red run.
evidence_index="$repo_root/deploy/acceptance/evidence-index.py"
receipt_verifier="$repo_root/deploy/acceptance/verify-acceptance-receipt.py"
# Signed platform identity must bind the product name and the exact agent-kit
# bytes inside the same verified payload, without relaxing gateway identity.
python3 - "$receipt_verifier" <<'PY'
import hashlib
import importlib.util
import json
import sys

spec = importlib.util.spec_from_file_location("platform_acceptance", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def rejected(action, label):
    try:
        action()
    except SystemExit as error:
        if "acceptance receipt rejected" in str(error):
            return
        raise
    raise SystemExit(f"accepted {label}")

kit_path = "deploy/docker-compose/agent-kit/install.sh"
kit_content = b"agent kit fixture\n"
kit_name = b"install.sh"
digest = hashlib.sha256(len(kit_name).to_bytes(4, "big") + kit_name + hashlib.sha256(kit_content).digest()).hexdigest()
run = {
    "schema": "jjdguard-offline-run-manifest/v2", "product": "Agent Platform",
    "version": "1.0", "target_arch": "amd64", "bundle_profile": "lite",
    "include_chat": "0", "artifact_stage": "candidate", "source_revision": "a" * 40,
    "source_tree": "b" * 40, "image_provenance_sha256": "c" * 64,
    "sbom_index_sha256": "d" * 64, "payload_sha256": "e" * 64,
    "payload_size": 123, "built_at": "2026-09-23T00:00:00Z",
}
run = module.parse_run_manifest(encoded(run), 123)
run["signed"] = True
manifest = {
    "schema": "offline-manifest/v2", "product": "agent-platform", "version": run["version"],
    "source_revision": run["source_revision"], "source_tree": run["source_tree"],
    "image_provenance_sha256": run["image_provenance_sha256"],
    "sbom_index_sha256": run["sbom_index_sha256"], "target_arch": "amd64",
    "bundle_profile": "lite", "include_chat": "0", "artifact_stage": "candidate",
    "min_data_version": "001_init.sql", "manifest_signature": "ed25519-domain-v2",
    "built_at": "2026-09-23T00:00:00Z", "bundle": "agent-platform-1.0",
    "product_profile": "agent-platform", "product_name": run["product"],
    "product_version": "1.0", "product_slug": "agent-platform", "agent_kit_sha256": digest,
}
root = manifest["bundle"]
module.parse_inner_manifest(encoded(manifest), run, root, "inner manifest")
unsigned_run = dict(run, signed=False)
rejected(lambda: module.parse_inner_manifest(encoded(manifest), unsigned_run, root, "inner manifest"), "unsigned platform run")
unsigned_manifest = dict(manifest, manifest_signature="sha256-only")
rejected(lambda: module.parse_inner_manifest(encoded(unsigned_manifest), unsigned_run, root, "inner manifest"), "unsigned platform manifest")
module.validate_agent_kit({kit_path: hashlib.sha256(kit_content).digest()}, manifest)
for key, invalid in (("product_name", "Other"), ("product_profile", "gateway"),
                     ("agent_kit_sha256", "invalid"), ("manifest_signature", "sha256-only")):
    changed = dict(manifest, **{key: invalid})
    rejected(lambda changed=changed: module.parse_inner_manifest(encoded(changed), run, root, "inner manifest"), key)
rejected(lambda: module.validate_agent_kit({kit_path: hashlib.sha256(b"tampered").digest()}, manifest), "agent-kit tamper")
rejected(lambda: module.validate_agent_kit({}, manifest), "missing agent-kit")
gateway = {key: value for key, value in manifest.items() if key not in module.PLATFORM_MANIFEST_KEYS}
gateway.update(product="jjdguard-enterprise", bundle="jjdguard-1.0")
rejected(lambda: module.parse_inner_manifest(encoded(gateway), run, "jjdguard-1.0", "inner manifest"), "platform run as gateway")
gateway_run = dict(run, product="JJDGuard")
module.parse_inner_manifest(encoded(gateway), gateway_run, "jjdguard-1.0", "inner manifest")
unsigned_gateway = dict(gateway_run, signed=False)
unsigned_gateway_manifest = dict(gateway, manifest_signature="sha256-only")
module.parse_inner_manifest(encoded(unsigned_gateway_manifest), unsigned_gateway, "jjdguard-1.0", "inner manifest")
rejected(lambda: module.parse_inner_manifest(encoded(manifest), gateway_run, root, "inner manifest"), "gateway run as platform")
PY
index_record="$evidence_root/index/evidence-index.json"
artifact_json='{"run_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","run_size":1,"inner_tar_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'
release_json='{"source_revision":"cccccccccccccccccccccccccccccccccccccccc","source_tree":"dddddddddddddddddddddddddddddddddddddddd","image_provenance_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","sbom_index_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}'

# A sparse candidate must fail from its logical size or the artifact parent's
# available space before the verifier creates an O_TMPFILE snapshot. The low
# space fixture lives on tmpfs, so it cannot materialize the multi-gigabyte
# logical length even if this boundary regresses.
snapshot_sparse_oversize="$tmpdir/snapshot-oversize.run"
[[ -d /dev/shm && -w /dev/shm ]] || { printf 'test host lacks writable /dev/shm for sparse snapshot coverage\n' >&2; exit 1; }
: > "$snapshot_sparse_oversize"
snapshot_sparse_low_space=$(mktemp -p /dev/shm 'jjdguard-snapshot-low-space.XXXXXX')
python3 - "$receipt_verifier" "$snapshot_sparse_oversize" "$snapshot_sparse_low_space" <<'PY'
import importlib.util
import os
import pathlib
import sys

verifier_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("receipt_verifier", verifier_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
oversize = pathlib.Path(sys.argv[2])
low_space = pathlib.Path(sys.argv[3])
available = os.statvfs(low_space.parent).f_bavail * os.statvfs(low_space.parent).f_frsize
if (
    available <= module.SNAPSHOT_SIDECAR_HEADROOM_BYTES
    or available >= module.MAX_RUN_ARTIFACT_BYTES
):
    raise SystemExit("tmpfs capacity cannot exercise sparse low-space coverage")
os.truncate(oversize, module.MAX_RUN_ARTIFACT_BYTES + 1)
os.truncate(low_space, available - module.SNAPSHOT_SIDECAR_HEADROOM_BYTES + 8 * 1024 * 1024)
PY
sparse_snapshot_cases=(
  "$snapshot_sparse_oversize|run artifact exceeds the snapshot size limit"
  "$snapshot_sparse_low_space|insufficient free space for run artifact snapshot"
)
for sparse_snapshot_case in "${sparse_snapshot_cases[@]}"; do
  IFS='|' read -r sparse_snapshot_artifact sparse_snapshot_reason <<<"$sparse_snapshot_case"
  sparse_snapshot_log="$tmpdir/$(basename "$sparse_snapshot_artifact").log"
  set +e
  python3 "$receipt_verifier" \
    --receipt "$tmpdir/unused-receipt.json" \
    --artifact "$sparse_snapshot_artifact" \
    --evidence-index "$tmpdir/unused-index.json" \
    --public-key "$tmpdir/unused-public-key.pem" \
    --source-repository "$repo_root" \
    --authoritative-remote 'https://invalid.example/jjdguard.git' >"$sparse_snapshot_log" 2>&1
  sparse_snapshot_exit=$?
  set -e
  [[ "$sparse_snapshot_exit" -ne 0 ]] || { printf 'verifier accepted sparse snapshot fixture\n' >&2; exit 1; }
  grep -F "$sparse_snapshot_reason" "$sparse_snapshot_log" >/dev/null || {
    cat "$sparse_snapshot_log" >&2
    printf 'verifier did not reject sparse snapshot fixture before copying\n' >&2
    exit 1
  }
done
rm -f -- "$snapshot_sparse_low_space"
snapshot_sparse_low_space=

index_root_parent="$tmpdir/index-root-parent"
index_root_external="$tmpdir/index-root-external"
mkdir -p "$index_root_parent" "$index_root_external/evidence"
printf '%s\n' 'direct-index-root' > "$index_root_external/evidence/input.log"
ln -s "$index_root_external" "$index_root_parent/middle"
set +e
python3 "$evidence_index" \
  --evidence-root "$index_root_parent/middle/evidence" \
  --output "$index_root_parent/middle/evidence/index/intermediate-root.json" \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --entry input.log
index_root_exit=$?
set -e
[[ "$index_root_exit" -ne 0 ]] || { printf 'evidence index accepted an intermediate evidence-root symlink\n' >&2; exit 1; }
[[ ! -e "$index_root_external/evidence/index/intermediate-root.json" ]] || {
  printf 'evidence index wrote through an intermediate evidence-root symlink\n' >&2
  exit 1
}

# A direct caller may use a relative evidence root while providing paths made
# absolute by its own working directory. Both forms must describe one root.
relative_index_root="$tmpdir/direct-relative-index-evidence"
relative_index_output="$relative_index_root/index/absolute-output.json"
relative_index_entry="$relative_index_root/input.log"
mkdir -p "$relative_index_root"
chmod 700 "$relative_index_root"
printf '%s\n' 'direct-relative-index' > "$relative_index_entry"
set +e
(
  cd "$tmpdir"
  python3 "$evidence_index" \
    --evidence-root direct-relative-index-evidence \
    --output "$relative_index_output" \
    --artifact-json "$artifact_json" \
    --release-json "$release_json" \
    --entry "$relative_index_entry"
)
relative_index_exit=$?
set -e
[[ "$relative_index_exit" -eq 0 ]] || { printf 'evidence index rejected matching relative and absolute root paths\n' >&2; exit 1; }
[[ -f "$relative_index_output" ]] || { printf 'evidence index did not write the relative-root index\n' >&2; exit 1; }

# A formal writer must not trust that every evidence log arrived through
# record-step.py. This forged manifest has valid schema, hashes, sizes, and
# required records, but one raw log carries a credential-shaped value.
formal_sensitive_root="$tmpdir/formal-sensitive-evidence"
formal_sensitive_log="$tmpdir/formal-sensitive.log"
python3 - "$formal_sensitive_root" "$artifact_json" "$release_json" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(mode=0o700)
artifact = json.loads(sys.argv[2])
release = json.loads(sys.argv[3])
scenarios = [
    "n1-install", "clean-install", "offline-reboot", "upgrade-n1-r7",
    "rollback-r7-n1", "reupgrade-n1-r7", "tamper-run", "tamper-manifest",
    "tamper-sbom", "tamper-provenance", "tamper-receipt", "browser-login",
    "model-api", "model-stream", "security-benign", "security-block",
    "security-audit", "portal-proxy-idp-chat",
]
specs = [
    ("vm-lifecycle", "vm-lifecycle", "verify-boot-id", {"boot_id_before": "before", "boot_id_after": "after"}),
    ("vm-metadata", "vm-metadata", "collect-runtime", {"os": "Ubuntu", "kernel": "6.0", "arch": "x86_64", "vcpu": "2", "ram_kib": "1024", "docker_before": "docker|24.0"}),
    ("network", "network", "verify-offline", {"public_network": "blocked", "probe_exit": "1"}),
    ("vm-postcheck", "vm-postcheck", "collect-runtime", {"docker_after": "docker|24.0", "version_sequence": "n1->r7", "image_ids": "sha256:" + "a" * 64}),
]
for scenario in scenarios:
    specs.extend((
        (scenario, scenario, "execute", {"migration_probe": "PASS", "business_probe": "PASS"}),
        (scenario + ".migration-probe", scenario, "migration-probe", {"probe": "migration"}),
        (scenario + ".business-probe", scenario, "business-probe", {"probe": "business"}),
    ))
entries = []
for record_id, scenario, step, details in specs:
    log_raw = b"access_token=never-record\n" if record_id == "n1-install" else b"formal-evidence\n"
    log_path = root / "logs" / (record_id + ".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(log_raw)
    record = {
        "schema": "jjdguard-vm-step-record/v1",
        "scenario": scenario,
        "step": step,
        "status": "PASS",
        "started_at": "2026-08-09T00:00:00Z",
        "finished_at": "2026-08-09T00:00:01Z",
        "exit_code": 0,
        "log_sha256": hashlib.sha256(log_raw).hexdigest(),
        "log_bytes": len(log_raw),
        "details": details,
    }
    record_path = root / "records" / (record_id + ".json")
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    for path in (record_path, log_path):
        entries.append({"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
(root / "evidence-index.json").write_text(json.dumps({
    "schema": "jjdguard-acceptance-evidence-index/v1",
    "artifact": artifact,
    "release": release,
    "entries": entries,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
set +e
python3 "$evidence_index" \
  --evidence-root "$formal_sensitive_root" \
  --output evidence-index.json \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --write-formal-receipt .formal-receipts/sensitive-receipt.json \
  --completed-at 2026-08-09T00:00:02Z >"$formal_sensitive_log" 2>&1
formal_sensitive_exit=$?
set -e
[[ "$formal_sensitive_exit" -ne 0 ]] || { printf 'formal writer accepted a sensitive forged evidence log\n' >&2; exit 1; }
grep -F 'formal evidence log contains sensitive content: n1-install' "$formal_sensitive_log" >/dev/null || {
  cat "$formal_sensitive_log" >&2
  printf 'formal writer did not identify the sensitive evidence log\n' >&2
  exit 1
}
[[ ! -e "$formal_sensitive_root/.formal-receipts/sensitive-receipt.json" ]] || {
  printf 'formal writer emitted a receipt for sensitive evidence\n' >&2
  exit 1
}

# The formal writer also receives records directly. Rebuild the same manifest
# with a safe log but inject the credential-shaped value only into metadata.
formal_sensitive_details_log="$tmpdir/formal-sensitive-details.log"
python3 - "$formal_sensitive_root" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
log_path = root / "logs" / "n1-install.log"
log_raw = b"formal-evidence\n"
log_path.write_bytes(log_raw)
record_path = root / "records" / "n1-install.json"
record = json.loads(record_path.read_text(encoding="utf-8"))
record["log_sha256"] = hashlib.sha256(log_raw).hexdigest()
record["log_bytes"] = len(log_raw)
record_path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
metadata_path = root / "records" / "vm-metadata.json"
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
metadata["details"]["os"] = "access_token=never-record"
metadata_path.write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
index_path = root / "evidence-index.json"
index = json.loads(index_path.read_text(encoding="utf-8"))
for entry in index["entries"]:
    path = root / entry["path"]
    entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
index_path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
set +e
python3 "$evidence_index" \
  --evidence-root "$formal_sensitive_root" \
  --output evidence-index.json \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --write-formal-receipt .formal-receipts/sensitive-details-receipt.json \
  --completed-at 2026-08-09T00:00:02Z >"$formal_sensitive_details_log" 2>&1
formal_sensitive_details_exit=$?
set -e
[[ "$formal_sensitive_details_exit" -ne 0 ]] || { printf 'formal writer accepted sensitive forged record details\n' >&2; exit 1; }
grep -F 'formal evidence details contain sensitive content: vm-metadata' "$formal_sensitive_details_log" >/dev/null || {
  cat "$formal_sensitive_details_log" >&2
  printf 'formal writer did not identify sensitive record details\n' >&2
  exit 1
}
[[ ! -e "$formal_sensitive_root/.formal-receipts/sensitive-details-receipt.json" ]] || {
  printf 'formal writer emitted a receipt for sensitive record details\n' >&2
  exit 1
}

# Formal receipt generation must apply the same payload/prompt policy as the
# recorder, even when an attacker forges a complete manifest and places the
# sensitive-looking text inside an otherwise allowed metadata field.
for formal_sensitive_detail in payload prompt; do
  formal_sensitive_detail_log="$tmpdir/formal-sensitive-$formal_sensitive_detail-details.log"
  formal_sensitive_detail_receipt=".formal-receipts/sensitive-$formal_sensitive_detail-details-receipt.json"
  python3 - "$formal_sensitive_root" "$formal_sensitive_detail" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
detail_name = sys.argv[2]
metadata_path = root / "records" / "vm-metadata.json"
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
metadata["details"]["os"] = detail_name + "=private"
metadata_path.write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
index_path = root / "evidence-index.json"
index = json.loads(index_path.read_text(encoding="utf-8"))
for entry in index["entries"]:
    path = root / entry["path"]
    entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
index_path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  set +e
  python3 "$evidence_index" \
    --evidence-root "$formal_sensitive_root" \
    --output evidence-index.json \
    --artifact-json "$artifact_json" \
    --release-json "$release_json" \
    --write-formal-receipt "$formal_sensitive_detail_receipt" \
    --completed-at 2026-08-09T00:00:02Z >"$formal_sensitive_detail_log" 2>&1
  formal_sensitive_detail_exit=$?
  set -e
  [[ "$formal_sensitive_detail_exit" -ne 0 ]] || {
    cat "$formal_sensitive_detail_log" >&2
    printf 'formal writer accepted %s in forged record details\n' "$formal_sensitive_detail" >&2
    exit 1
  }
  grep -F 'formal evidence details contain sensitive content: vm-metadata' "$formal_sensitive_detail_log" >/dev/null || {
    cat "$formal_sensitive_detail_log" >&2
    printf 'formal writer did not identify forged %s record details\n' "$formal_sensitive_detail" >&2
    exit 1
  }
  [[ ! -e "$formal_sensitive_root/$formal_sensitive_detail_receipt" ]] || {
    printf 'formal writer emitted a receipt for forged %s record details\n' "$formal_sensitive_detail" >&2
    exit 1
  }
done

python3 "$evidence_index" \
  --evidence-root "$evidence_root" \
  --output "$index_record" \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --entry records/path-escape.json

python3 - "$index_record" <<'PY'
import json
import sys

index = json.load(open(sys.argv[1], encoding="utf-8"))
assert index["schema"] == "jjdguard-acceptance-evidence-index/v1"
assert index["entries"] and index["entries"][0]["path"] == "records/path-escape.json"
assert len(index["entries"][0]["sha256"]) == 64
PY

# The acceptance verifier must bind receipt and index bytes to the same
# descriptor it validated. This probe swaps each path only after the
# verifier's own real regular-file guard returns; the parser and validators
# remain the unmodified production implementation.
python3 - "$receipt_verifier" "$tmpdir/receipt-index-toctou" <<'PY'
import hashlib
import importlib.util
import json
import pathlib
import sys


def load_verifier(path):
    spec = importlib.util.spec_from_file_location("receipt_index_toctou", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load acceptance verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def replace_after_regular_guard(module, path, replacement, invoke, label):
    original = module.require_regular
    triggered = False

    def guarded(candidate, candidate_label):
        nonlocal triggered
        result = original(candidate, candidate_label)
        if pathlib.Path(candidate) == path:
            path.unlink()
            path.symlink_to(replacement)
            triggered = True
        return result

    module.require_regular = guarded
    try:
        invoke()
    except SystemExit:
        if not triggered:
            raise SystemExit(f"{label} TOCTOU probe did not reach the regular-file guard")
        return
    finally:
        module.require_regular = original
    raise SystemExit(f"verifier accepted forged {label} after its lstat guard")


verifier_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
root.mkdir()
module = load_verifier(verifier_path)
identity = {
    "run_sha256": "a" * 64,
    "run_size": 1,
    "inner_tar_sha256": "b" * 64,
    "source_revision": "c" * 40,
    "source_tree": "d" * 40,
    "image_provenance_sha256": "e" * 64,
    "sbom_index_sha256": "f" * 64,
}
artifact = {key: identity[key] for key in ("run_sha256", "run_size", "inner_tar_sha256")}
release = {
    key: identity[key]
    for key in ("source_revision", "source_tree", "image_provenance_sha256", "sbom_index_sha256")
}
evidence_root = root / "evidence"
entry = evidence_root / "logs" / "proof.log"
entry.parent.mkdir(parents=True)
entry.write_bytes(b"safe evidence\n")
forged_index = {
    "schema": "jjdguard-acceptance-evidence-index/v1",
    "artifact": artifact,
    "release": release,
    "entries": [{"path": "logs/proof.log", "sha256": hashlib.sha256(entry.read_bytes()).hexdigest()}],
}
index_path = root / "evidence-index.json"
forged_index_path = root / "outside-forged-index.json"
index_path.write_text('{"untrusted":"index"}', encoding="utf-8")
forged_index_path.write_bytes(canonical(forged_index))
expected_index_sha256 = hashlib.sha256(forged_index_path.read_bytes()).hexdigest()
replace_after_regular_guard(
    module,
    index_path,
    forged_index_path,
    lambda: module.validate_evidence_index(index_path, identity, evidence_root),
    "evidence index",
)

forged_receipt = {
    "schema": "jjdguard-acceptance-receipt/v1",
    "status": "PASS",
    "artifact": artifact,
    "release": release,
    "scenarios": {scenario: "PASS" for scenario in module.REQUIRED_SCENARIOS},
    "evidence_index_sha256": expected_index_sha256,
    "non_promotable_reasons": [],
    "completed_at": "2026-08-09T00:00:02Z",
}
receipt_path = root / "receipt.json"
forged_receipt_path = root / "outside-forged-receipt.json"
receipt_path.write_text('{"status":"FAIL"}', encoding="utf-8")
forged_receipt_path.write_bytes(canonical(forged_receipt))
replace_after_regular_guard(
    module,
    receipt_path,
    forged_receipt_path,
    lambda: module.validate_receipt(receipt_path, expected_index_sha256, identity),
    "PASS receipt",
)
PY

# The candidate artifact is adversarial input. Every stage of its verification
# must read one opened object, rather than reopening the path for the final
# SHA-256 and size. This probe swaps B for D after B reached the inner-chain
# boundary; the resulting identity must still describe B.
python3 - "$receipt_verifier" "$tmpdir/artifact-identity-toctou" <<'PY'
import hashlib
import importlib.util
import io
import os
import pathlib
import sys


def load_verifier(path):
    spec = importlib.util.spec_from_file_location("artifact_identity_toctou", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load acceptance verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Member:
    def __init__(self, name, raw):
        self.name = name
        self.size = len(raw)
        self.pax_headers = {}

    def isfile(self):
        return True

    def issparse(self):
        return False

    def issym(self):
        return False

    def islnk(self):
        return False


class FakeOuter:
    def __init__(self, files):
        self.files = files
        self.members = [Member(name, raw) for name, raw in files.items()]

    @classmethod
    def open(cls, *, fileobj, mode):
        del fileobj, mode
        return cls(FILES)

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False

    def __iter__(self):
        return iter(self.members)

    def extractfile(self, member):
        return io.BytesIO(self.files[member.name])


root = pathlib.Path(sys.argv[2])
root.mkdir()
run = root / "candidate.run"
replacement = root / "replacement.run"
candidate_b = b"candidate-B-verified\n"
candidate_d = b"candidate-D-not-verified-and-longer\n"
run.write_bytes(candidate_b)
replacement.write_bytes(candidate_d)
FILES = {
    "payload.tar.gz": b"payload-B",
    "run-manifest.json": b"{}",
    "run-manifest.sig": b"signature",
}

module = load_verifier(pathlib.Path(sys.argv[1]))
payload_sha256 = hashlib.sha256(FILES["payload.tar.gz"]).hexdigest()
module.verify_header_signature = lambda *unused: (0, b"public-key")
module.ExtensionFreeTarFile = FakeOuter
module.parse_run_manifest = lambda raw, size: {
    "payload_sha256": payload_sha256,
    "version": "B",
    "source_revision": "a" * 40,
    "source_tree": "b" * 40,
    "image_provenance_sha256": "c" * 64,
    "sbom_index_sha256": "d" * 64,
}
module.verify_ed25519 = lambda *unused: None
module.authoritative_syft_hash = lambda *unused: "e" * 64
module.source_archive_sha256 = lambda *unused: "f" * 64


def verify_inner_then_replace(*unused):
    if run.read_bytes() != candidate_b:
        raise SystemExit("inner-chain fixture did not start from candidate B")
    replacement.replace(run)


module.verify_inner_bundle_chain = verify_inner_then_replace
identity = module.read_run_identity(run, root / "unused-public-key", root, "https://invalid.example/jjdguard.git")
if identity["run_sha256"] != hashlib.sha256(candidate_b).hexdigest() or identity["run_size"] != len(candidate_b):
    raise SystemExit("artifact identity was recomputed from replacement D after B validation")

# A pathname replacement is not the only race: a writer holding the original
# inode can change bytes in place, fsync, and restore mtime. The verifier must
# keep reading its immutable private snapshot rather than accepting D from the
# same descriptor after B has passed the inner-chain boundary.
same_inode_run = root / "same-inode-candidate.run"
same_inode_b = b"B" * 96
same_inode_d = b"D" * len(same_inode_b)
same_inode_run.write_bytes(same_inode_b)
same_inode_before = same_inode_run.stat()


def verify_inner_then_mutate_same_inode(*unused):
    if same_inode_run.read_bytes() != same_inode_b:
        raise SystemExit("same-inode fixture did not start from candidate B")
    with same_inode_run.open("r+b", buffering=0) as stream:
        stream.write(same_inode_d)
        stream.flush()
        os.fsync(stream.fileno())
    os.utime(
        same_inode_run,
        ns=(same_inode_before.st_atime_ns, same_inode_before.st_mtime_ns),
    )
    after = same_inode_run.stat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        same_inode_before.st_dev,
        same_inode_before.st_ino,
        same_inode_before.st_size,
        same_inode_before.st_mtime_ns,
    ):
        raise SystemExit("same-inode fixture did not preserve visible metadata")


module.verify_inner_bundle_chain = verify_inner_then_mutate_same_inode
same_inode_identity = module.read_run_identity(
    same_inode_run,
    root / "unused-public-key",
    root,
    "https://invalid.example/jjdguard.git",
)
if (
    same_inode_identity["run_sha256"] != hashlib.sha256(same_inode_b).hexdigest()
    or same_inode_identity["run_size"] != len(same_inode_b)
):
    raise SystemExit("artifact identity accepted same-inode mutation after inner validation")
PY

# Each index invocation must retain one evidence-root descriptor. Reopening the
# root for each entry lets a rename race mix hashes from the old root with data
# and output in a new same-name directory. The wrapper only schedules that
# filesystem rename after the real first-entry hash has completed.
python3 - "$evidence_index" "$tmpdir/index-root-replacement" "$artifact_json" "$release_json" <<'PY'
import hashlib
import importlib.util
import json
import pathlib
import sys


def load_indexer(path):
    spec = importlib.util.spec_from_file_location("index_root_replacement", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence indexer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


indexer_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
artifact = sys.argv[3]
release = sys.argv[4]
root.mkdir(mode=0o700)
first = root / "first.log"
second = root / "second.log"
first_raw = b"trusted-first\n"
second_raw = b"trusted-second\n"
replacement_raw = b"attacker-second\n"
first.write_bytes(first_raw)
second.write_bytes(second_raw)
original_root = root.with_name(root.name + "-original")
module = load_indexer(indexer_path)
original_hash = module.hash_regular_entry
calls = 0


def hash_then_replace(*args, **kwargs):
    global calls
    digest = original_hash(*args, **kwargs)
    calls += 1
    if calls == 1:
        root.rename(original_root)
        root.mkdir(mode=0o700)
        (root / "second.log").write_bytes(replacement_raw)
    return digest


module.hash_regular_entry = hash_then_replace
sys.argv = [
    str(indexer_path),
    "--evidence-root", str(root),
    "--output", "index/evidence-index.json",
    "--artifact-json", artifact,
    "--release-json", release,
    "--entry", "first.log",
    "--entry", "second.log",
]
status = module.main()
if status != 0:
    raise SystemExit(f"index root-replacement probe returned {status}")
if calls != 2:
    raise SystemExit(f"index root-replacement probe expected two hashes, got {calls}")
original_index = original_root / "index" / "evidence-index.json"
replacement_index = root / "index" / "evidence-index.json"
if not original_index.is_file() or replacement_index.exists():
    raise SystemExit("evidence index mixed a replaced root")
index = json.loads(original_index.read_text(encoding="utf-8"))
hashes = {entry["path"]: entry["sha256"] for entry in index["entries"]}
if hashes != {
    "first.log": hashlib.sha256(first_raw).hexdigest(),
    "second.log": hashlib.sha256(second_raw).hexdigest(),
}:
    raise SystemExit("evidence index read a replacement root entry")
PY

# A step record binds a log hash and then writes JSON. Those two operations
# must share the same root descriptor so a root replacement cannot redirect
# the output after trusted log bytes were read.
python3 - "$record_step" "$tmpdir/record-root-replacement" <<'PY'
import hashlib
import importlib.util
import json
import pathlib
import sys


def load_recorder(path):
    spec = importlib.util.spec_from_file_location("record_root_replacement", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence recorder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


recorder_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
root.mkdir(mode=0o700)
trusted_log = b"trusted-log\n"
log_path = root / "logs" / "step.log"
log_path.parent.mkdir()
log_path.write_bytes(trusted_log)
original_root = root.with_name(root.name + "-original")
module = load_recorder(recorder_path)
original_hash = module.hash_regular_file
calls = 0


def hash_then_replace(*args, **kwargs):
    global calls
    result = original_hash(*args, **kwargs)
    calls += 1
    if calls == 1:
        root.rename(original_root)
        root.mkdir(mode=0o700)
        replacement_log = root / "logs" / "step.log"
        replacement_log.parent.mkdir()
        replacement_log.write_bytes(b"attacker-log\n")
    return result


module.hash_regular_file = hash_then_replace
sys.argv = [
    str(recorder_path),
    "--evidence-root", str(root),
    "--output", "records/root-replacement.json",
    "--scenario", "root-replacement",
    "--step", "bind-log-and-record",
    "--status", "FAIL",
    "--exit-code", "69",
    "--started-at", "2026-08-09T00:00:00Z",
    "--finished-at", "2026-08-09T00:00:01Z",
    "--log", "logs/step.log",
]
status = module.main()
if status != 0:
    raise SystemExit(f"record root-replacement probe returned {status}")
if calls != 1:
    raise SystemExit(f"record root-replacement probe expected one hash, got {calls}")
original_record = original_root / "records" / "root-replacement.json"
replacement_record = root / "records" / "root-replacement.json"
if not original_record.is_file() or replacement_record.exists():
    raise SystemExit("record-step mixed a replaced root")
record = json.loads(original_record.read_text(encoding="utf-8"))
if record["log_sha256"] != hashlib.sha256(trusted_log).hexdigest():
    raise SystemExit("record-step did not bind the original root log")
PY

# An individual evidence leaf must also bind the lstat result to the descriptor
# that is hashed. Swap in a same-sized regular file only after the real lstat;
# accepting it would put uninspected bytes in an otherwise valid index.
python3 - "$evidence_index" "$tmpdir/index-leaf-replacement" <<'PY'
import importlib.util
import pathlib
import sys


def load_indexer(path):
    spec = importlib.util.spec_from_file_location("index_leaf_replacement", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence indexer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


indexer_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
root.mkdir(mode=0o700)
entry = root / "proof.log"
replacement = root / "proof.log.replacement"
entry.write_bytes(b"trusted\n")
replacement.write_bytes(b"forged!\n")
if entry.stat().st_size != replacement.stat().st_size:
    raise SystemExit("leaf replacement fixture is not same-sized")

module = load_indexer(indexer_path)
root_fd = module.open_directory(root)
original_stat = module.os.stat
state = {"swapped": False}


def stat_then_replace(path, *args, **kwargs):
    listed = original_stat(path, *args, **kwargs)
    if not state["swapped"] and path == "proof.log" and kwargs.get("dir_fd") is not None:
        replacement.replace(entry)
        state["swapped"] = True
    return listed


module.os.stat = stat_then_replace
try:
    try:
        module.hash_regular_entry(root_fd, ("proof.log",))
    except module.IndexError:
        if not state["swapped"]:
            raise SystemExit("index leaf-replacement probe did not reach lstat")
    else:
        raise SystemExit("evidence index accepted a same-sized replaced leaf")
finally:
    module.os.stat = original_stat
    module.os.close(root_fd)
PY

# record-step must bind both a hashed log and a parsed record leaf to the same
# regular-file descriptor it inspected. Each probe swaps a same-sized file only
# after the production lstat returns.
python3 - "$record_step" "$tmpdir/record-leaf-replacement" <<'PY'
import importlib.util
import pathlib
import sys


def load_recorder(path):
    spec = importlib.util.spec_from_file_location("record_leaf_replacement", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence recorder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expect_same_size_swap_rejected(module, path, invoke, label):
    replacement = path.with_name(path.name + ".replacement")
    replacement.write_bytes(path.read_bytes().replace(b"trusted", b"forged!"))
    if path.stat().st_size != replacement.stat().st_size:
        raise SystemExit(f"{label} replacement fixture is not same-sized")
    original_stat = module.os.stat
    state = {"swapped": False}

    def stat_then_replace(candidate, *args, **kwargs):
        listed = original_stat(candidate, *args, **kwargs)
        if not state["swapped"] and candidate == path.name and kwargs.get("dir_fd") is not None:
            replacement.replace(path)
            state["swapped"] = True
        return listed

    module.os.stat = stat_then_replace
    try:
        try:
            invoke()
        except module.RecordError:
            if not state["swapped"]:
                raise SystemExit(f"{label} probe did not reach lstat")
            return
        raise SystemExit(f"record-step accepted a same-sized replaced {label}")
    finally:
        module.os.stat = original_stat


recorder_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
root.mkdir(mode=0o700)
log_path = root / "logs" / "proof.log"
record_path = root / "records" / "record.json"
log_path.parent.mkdir()
record_path.parent.mkdir()
log_path.write_bytes(b"trusted\n")
record_path.write_bytes(b'{"marker":"trusted"}\n')

module = load_recorder(recorder_path)
root_fd = module.open_root(root)
try:
    expect_same_size_swap_rejected(
        module,
        log_path,
        lambda: module.hash_regular_file(root_fd, ("logs", "proof.log")),
        "log leaf",
    )
    expect_same_size_swap_rejected(
        module,
        record_path,
        lambda: module.read_json_under_root(root_fd, ("records", "record.json"), "record"),
        "record leaf",
    )
finally:
    module.os.close(root_fd)
PY

# A failed write may race with another trusted process replacing the output
# name. Cleanup must remove only the inode this transaction created, never a
# replacement sentinel. Exercise both structured writers at their first real
# os.write failure.
python3 - "$evidence_index" "$record_step" "$tmpdir/write-cleanup-replacement" <<'PY'
import errno
import importlib.util
import pathlib
import sys


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load " + name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def replace_before_write(module, replacement, output):
    original_write = module.os.write
    state = {"swapped": False}

    def fail_after_replace(descriptor, view):
        del descriptor, view
        if not state["swapped"]:
            replacement.replace(output)
            state["swapped"] = True
        raise OSError(errno.ENOSPC, "injected write failure")

    module.os.write = fail_after_replace
    return original_write, state


root = pathlib.Path(sys.argv[3])
root.mkdir(mode=0o700)
indexer = load_module(pathlib.Path(sys.argv[1]), "write_cleanup_indexer")
recorder = load_module(pathlib.Path(sys.argv[2]), "write_cleanup_recorder")
failures = []

index_dir = root / "index"
index_dir.mkdir(mode=0o700)
index_output = index_dir / "target.json"
index_replacement = root / "index-replacement.json"
index_replacement.write_bytes(b"index-sentinel\n")
index_root_fd = indexer.open_directory(root)
index_original_write, index_state = replace_before_write(indexer, index_replacement, index_output)
try:
    try:
        indexer.write_json(root, index_root_fd, ("index", "target.json"), {"schema": "test"})
    except indexer.IndexError:
        pass
    else:
        failures.append("indexer accepted injected write failure")
finally:
    indexer.os.write = index_original_write
    indexer.os.close(index_root_fd)
if not index_state["swapped"]:
    failures.append("indexer cleanup probe did not reach os.write")
elif not index_output.is_file() or index_output.read_bytes() != b"index-sentinel\n":
    failures.append("indexer cleanup deleted replacement inode")

record_dir = root / "records"
record_dir.mkdir(mode=0o700)
record_output = record_dir / "target.json"
record_replacement = root / "record-replacement.json"
record_replacement.write_bytes(b"record-sentinel\n")
record_root_fd = recorder.open_root(root)
record_original_write, record_state = replace_before_write(recorder, record_replacement, record_output)
try:
    try:
        recorder.write_json_under_root(root, record_root_fd, ("records", "target.json"), {"schema": "test"})
    except recorder.RecordError:
        pass
    else:
        failures.append("record-step accepted injected write failure")
finally:
    recorder.os.write = record_original_write
    recorder.os.close(record_root_fd)
if not record_state["swapped"]:
    failures.append("record-step cleanup probe did not reach os.write")
elif not record_output.is_file() or record_output.read_bytes() != b"record-sentinel\n":
    failures.append("record-step cleanup deleted replacement inode")

if failures:
    raise SystemExit("; ".join(failures))
PY

# A capacity-limited record write must fail closed and remove the partial JSON;
# one successful short os.write is not durable structured evidence.
python3 - "$record_step" "$tmpdir/record-capacity-limit" <<'PY'
import importlib.util
import pathlib
import resource
import signal
import sys


def load_recorder(path):
    spec = importlib.util.spec_from_file_location("record_capacity_limit", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence recorder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


recorder_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
root.mkdir(mode=0o700)
output = root / "records" / "capacity.json"
record = {"schema": "test", "details": {"marker": "x" * 256}}
module = load_recorder(recorder_path)
root_fd = module.open_root(root)
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
if hard != resource.RLIM_INFINITY and hard < 64:
    raise SystemExit("record capacity probe cannot set a 64-byte file limit")
previous_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (64, hard))
try:
    try:
        module.write_json_under_root(root, root_fd, ("records", "capacity.json"), record)
    except (module.RecordError, OSError):
        pass
    else:
        raise SystemExit("record-step accepted a capacity-truncated record")
finally:
    resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
    signal.signal(signal.SIGXFSZ, previous_handler)
    module.os.close(root_fd)
if output.exists():
    raise SystemExit("record-step retained a partial capacity-truncated record")
PY

# A capacity-limited append must not leave a partial event in an otherwise
# admissible log. The existing bytes are retained exactly when the append fails.
python3 - "$record_step" "$tmpdir/append-capacity-limit" <<'PY'
import importlib.util
import pathlib
import resource
import signal
import sys


def load_recorder(path):
    spec = importlib.util.spec_from_file_location("append_capacity_limit", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence recorder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


recorder_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
root.mkdir(mode=0o700)
log_path = root / "logs" / "append.log"
log_path.parent.mkdir()
original = b"before\n"
log_path.write_bytes(original)
event = "x" * 128
module = load_recorder(recorder_path)
root_fd = module.open_root(root)
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
limit = len(original) + 16
if hard != resource.RLIM_INFINITY and hard < limit:
    raise SystemExit("append capacity probe cannot set its file limit")
previous_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard))
try:
    try:
        module.append_log(root_fd, ("logs", "append.log"), event)
    except (module.RecordError, OSError):
        pass
    else:
        raise SystemExit("record-step accepted a capacity-truncated log append")
finally:
    resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
    signal.signal(signal.SIGXFSZ, previous_handler)
    module.os.close(root_fd)
if log_path.read_bytes() != original:
    raise SystemExit("record-step retained a partial capacity-truncated log event")
PY

# Deep evidence paths must not accumulate one descriptor per component. This
# runs the real indexer below a deliberately small descriptor budget.
python3 - "$evidence_index" "$tmpdir/index-deep-low-nofile" "$artifact_json" "$release_json" <<'PY'
import importlib.util
import pathlib
import resource
import sys


def load_indexer(path):
    spec = importlib.util.spec_from_file_location("index_deep_low_nofile", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence indexer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


indexer_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
artifact = sys.argv[3]
release = sys.argv[4]
root.mkdir(mode=0o700)
parts = tuple(f"deep-{number:03d}" for number in range(96))
entry = root.joinpath(*parts, "proof.log")
entry.parent.mkdir(parents=True)
entry.write_bytes(b"deep descriptor budget evidence\n")
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
if hard < 32:
    raise SystemExit("deep descriptor-budget probe cannot set a 32-fd limit")
module = load_indexer(indexer_path)
sys.argv = [
    str(indexer_path),
    "--evidence-root", str(root),
    "--output", "index/evidence-index.json",
    "--artifact-json", artifact,
    "--release-json", release,
    "--entry", "/".join((*parts, "proof.log")),
]
resource.setrlimit(resource.RLIMIT_NOFILE, (32, hard))
try:
    status = module.main()
finally:
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
if status != 0 or not (root / "index" / "evidence-index.json").is_file():
    raise SystemExit("evidence index exhausted the descriptor budget on a deep path")
PY

# A real filesystem capacity limit can make os.write return a short write.
# The indexer must reject and remove a partial index instead of treating that
# truncated JSON as durable evidence.
python3 - "$evidence_index" "$tmpdir/index-capacity-limit" "$artifact_json" "$release_json" <<'PY'
import importlib.util
import pathlib
import resource
import signal
import sys


def load_indexer(path):
    spec = importlib.util.spec_from_file_location("index_capacity_limit", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence indexer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


indexer_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
artifact = sys.argv[3]
release = sys.argv[4]
root.mkdir(mode=0o700)
(root / "proof.log").write_bytes(b"capacity-limited evidence\n")
output = root / "index" / "evidence-index.json"
module = load_indexer(indexer_path)
sys.argv = [
    str(indexer_path),
    "--evidence-root", str(root),
    "--output", "index/evidence-index.json",
    "--artifact-json", artifact,
    "--release-json", release,
    "--entry", "proof.log",
]
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
if hard != resource.RLIM_INFINITY and hard < 64:
    raise SystemExit("capacity probe cannot set a 64-byte file limit")
previous_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (64, hard))
try:
    status = module.main()
finally:
    resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
    signal.signal(signal.SIGXFSZ, previous_handler)
if status == 0:
    raise SystemExit("evidence index accepted a capacity-truncated write")
if output.exists():
    raise SystemExit("evidence index retained a partial capacity-truncated file")
PY

# The indexer must bound evidence fan-out before hashing an unbounded caller
# supplied list. Formal evidence needs 116 files, so this fixture is just one
# beyond the deliberately generous direct-index limit.
python3 - "$evidence_index" "$tmpdir/index-entry-capacity" "$artifact_json" "$release_json" <<'PY'
import importlib.util
import pathlib
import sys


def load_indexer(path):
    spec = importlib.util.spec_from_file_location("index_entry_capacity", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence indexer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


indexer_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
artifact = sys.argv[3]
release = sys.argv[4]
root.mkdir(mode=0o700)
entries = []
for number in range(257):
    name = f"entry-{number:03d}.log"
    (root / name).write_bytes(b"bounded fanout evidence\n")
    entries.append(name)
module = load_indexer(indexer_path)
sys.argv = [
    str(indexer_path),
    "--evidence-root", str(root),
    "--output", "index/evidence-index.json",
    "--artifact-json", artifact,
    "--release-json", release,
    *[argument for entry in entries for argument in ("--entry", entry)],
]
status = module.main()
if status == 0:
    raise SystemExit("evidence index accepted an unbounded entry fan-out")
if (root / "index" / "evidence-index.json").exists():
    raise SystemExit("evidence index wrote output after fan-out rejection")
PY

# Counting files alone does not bound the bytes read from a caller-controlled
# evidence root. Each fixture file is below the per-file limit and the list is
# below the fan-out limit, but their aggregate must still fail closed.
python3 - "$evidence_index" "$tmpdir/index-total-capacity" "$artifact_json" "$release_json" <<'PY'
import importlib.util
import pathlib
import sys


def load_indexer(path):
    spec = importlib.util.spec_from_file_location("index_total_capacity", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence indexer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


indexer_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
artifact = sys.argv[3]
release = sys.argv[4]
root.mkdir(mode=0o700)
entries = []
for number in range(9):
    name = f"large-{number}.log"
    (root / name).write_bytes(b"x" * (1024 * 1024))
    entries.append(name)
module = load_indexer(indexer_path)
sys.argv = [
    str(indexer_path),
    "--evidence-root", str(root),
    "--output", "index/evidence-index.json",
    "--artifact-json", artifact,
    "--release-json", release,
    *[argument for entry in entries for argument in ("--entry", entry)],
]
status = module.main()
if status == 0:
    raise SystemExit("evidence index accepted an over-capacity evidence total")
if (root / "index" / "evidence-index.json").exists():
    raise SystemExit("evidence index wrote output after total-capacity rejection")
PY

# A scenario-only index is hash-consistent but not promotable evidence. Formal
# receipt generation must require VM lifecycle/runtime/network/postcheck and
# each scenario's execute, migration, and business records and logs.
formal_minimal_root="$tmpdir/formal-minimal-evidence"
formal_minimal_log="$tmpdir/formal-minimal.log"
python3 - "$formal_minimal_root" "$artifact_json" "$release_json" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(mode=0o700)
artifact = json.loads(sys.argv[2])
release = json.loads(sys.argv[3])
names = [
    "n1-install", "clean-install", "offline-reboot", "upgrade-n1-r7",
    "rollback-r7-n1", "reupgrade-n1-r7", "tamper-run", "tamper-manifest",
    "tamper-sbom", "tamper-provenance", "tamper-receipt", "browser-login",
    "model-api", "model-stream", "security-benign", "security-block",
    "security-audit", "portal-proxy-idp-chat",
]
entries = []
for name in names:
    log_path = root / "logs" / (name + ".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(b"")
    log_sha256 = hashlib.sha256(b"").hexdigest()
    record = {
        "schema": "jjdguard-vm-step-record/v1",
        "scenario": name,
        "step": "execute",
        "status": "PASS",
        "started_at": "2026-08-09T00:00:00Z",
        "finished_at": "2026-08-09T00:00:01Z",
        "exit_code": 0,
        "log_sha256": log_sha256,
        "log_bytes": 0,
        "details": {"migration_probe": "PASS", "business_probe": "PASS"},
    }
    record_path = root / "records" / (name + ".json")
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    for path in (record_path, log_path):
        entries.append({
            "path": str(path.relative_to(root)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
(root / "evidence-index.json").write_text(json.dumps({
    "schema": "jjdguard-acceptance-evidence-index/v1",
    "artifact": artifact,
    "release": release,
    "entries": entries,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
set +e
python3 "$evidence_index" \
  --evidence-root "$formal_minimal_root" \
  --output evidence-index.json \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --write-formal-receipt .formal-receipts/receipt.json \
  --completed-at 2026-08-09T00:00:02Z >"$formal_minimal_log" 2>&1
formal_minimal_exit=$?
set -e
[[ "$formal_minimal_exit" -ne 0 ]] || { printf 'formal writer accepted a scenario-only evidence manifest\n' >&2; exit 1; }
grep -F 'formal evidence manifest is incomplete' "$formal_minimal_log" >/dev/null || {
  cat "$formal_minimal_log" >&2
  printf 'formal writer did not identify the missing evidence manifest\n' >&2
  exit 1
}
[[ ! -e "$formal_minimal_root/.formal-receipts/receipt.json" ]] || { printf 'formal writer emitted a receipt for incomplete evidence\n' >&2; exit 1; }

# A verified staged receipt is published with an fd-anchored, no-overwrite
# link. The private staging hard link is retained because a later pathname
# unlink cannot prove it still belongs to this transaction.
formal_stage_dir="$evidence_root/.formal-receipts"
formal_stage="$formal_stage_dir/staged-receipt.json"
formal_published="$evidence_root/published-receipt.json"
mkdir -p "$formal_stage_dir"
printf '%s\n' '{"schema":"jjdguard-acceptance-receipt/v1"}' > "$formal_stage"
chmod 600 "$formal_stage"
formal_stage_sha256="$(sha256sum "$formal_stage" | awk '{print $1}')"
python3 "$evidence_index" \
  --evidence-root "$evidence_root" \
  --publish-formal-receipt .formal-receipts/staged-receipt.json \
  --expected-staged-sha256 "$formal_stage_sha256" \
  --receipt published-receipt.json
[[ -f "$formal_stage" && -f "$formal_published" ]] || { printf 'formal receipt was not atomically published and retained\n' >&2; exit 1; }
python3 - "$formal_stage" "$formal_published" <<'PY'
import pathlib
import stat
import sys

staged, published = map(pathlib.Path, sys.argv[1:])
staged_metadata = staged.stat()
published_metadata = published.stat()
assert stat.S_IMODE(staged_metadata.st_mode) == 0o600
assert stat.S_IMODE(published_metadata.st_mode) == 0o600
assert (staged_metadata.st_dev, staged_metadata.st_ino) == (published_metadata.st_dev, published_metadata.st_ino)
PY

formal_rejected_stage="$formal_stage_dir/rejected-receipt.json"
formal_rejected_target="$tmpdir/formal-rejected-target.json"
formal_rejected_receipt="$evidence_root/preexisting-receipt.json"
printf '%s\n' '{"schema":"jjdguard-acceptance-receipt/v1"}' > "$formal_rejected_stage"
chmod 600 "$formal_rejected_stage"
formal_rejected_stage_sha256="$(sha256sum "$formal_rejected_stage" | awk '{print $1}')"
printf '%s\n' 'outside-unchanged' > "$formal_rejected_target"
ln -s "$formal_rejected_target" "$formal_rejected_receipt"
set +e
python3 "$evidence_index" \
  --evidence-root "$evidence_root" \
  --publish-formal-receipt .formal-receipts/rejected-receipt.json \
  --expected-staged-sha256 "$formal_rejected_stage_sha256" \
  --receipt preexisting-receipt.json
formal_publish_exit=$?
set -e
[[ "$formal_publish_exit" -ne 0 ]] || { printf 'formal publisher overwrote an existing receipt path\n' >&2; exit 1; }
[[ "$(<"$formal_rejected_target")" == outside-unchanged ]] || { printf 'formal publisher wrote through a receipt symlink\n' >&2; exit 1; }
[[ -f "$formal_rejected_stage" ]] || { printf 'formal publisher discarded a receipt after failed publication\n' >&2; exit 1; }
formal_discard_log="$tmpdir/formal-discard.log"
set +e
python3 "$evidence_index" \
  --evidence-root "$evidence_root" \
  --discard-formal-receipt .formal-receipts/rejected-receipt.json >"$formal_discard_log" 2>&1
formal_discard_exit=$?
set -e
[[ "$formal_discard_exit" -ne 0 ]] || { printf 'formal staged discard unexpectedly succeeded\n' >&2; exit 1; }
grep -F 'manual disposal' "$formal_discard_log" >/dev/null || {
  cat "$formal_discard_log" >&2
  printf 'formal staged discard did not require manual disposal\n' >&2
  exit 1
}
[[ -f "$formal_rejected_stage" ]] || { printf 'formal staged discard removed retained evidence\n' >&2; exit 1; }

# Interrupted-publication cleanup is conservatively rejected because no
# pathname unlink can prove that either hard link still belongs to the run.
formal_drift_stage="$formal_stage_dir/drifted-receipt.json"
formal_drift_final="$evidence_root/drifted-receipt.json"
printf '%s\n' verified-before-interrupt > "$formal_drift_stage"
chmod 600 "$formal_drift_stage"
formal_drift_sha256="$(sha256sum "$formal_drift_stage" | awk '{print $1}')"
ln "$formal_drift_stage" "$formal_drift_final"
printf '%s\n' drifted-before-cleanup > "$formal_drift_stage"
formal_drift_log="$tmpdir/formal-drift.log"
set +e
python3 "$evidence_index" \
  --evidence-root "$evidence_root" \
  --discard-interrupted-formal-receipt .formal-receipts/drifted-receipt.json \
  --expected-staged-sha256 "$formal_drift_sha256" \
  --receipt drifted-receipt.json >"$formal_drift_log" 2>&1
formal_drift_exit=$?
set -e
[[ "$formal_drift_exit" -ne 0 ]] || { printf 'interrupted cleanup unexpectedly succeeded\n' >&2; exit 1; }
grep -F 'manual disposal' "$formal_drift_log" >/dev/null || {
  cat "$formal_drift_log" >&2
  printf 'interrupted cleanup did not require manual disposal\n' >&2
  exit 1
}
[[ -f "$formal_drift_final" ]] || { printf 'interrupted cleanup removed a drifted final receipt\n' >&2; exit 1; }
[[ "$(<"$formal_drift_final")" == drifted-before-cleanup ]] || {
  printf 'interrupted cleanup changed a drifted final receipt\n' >&2
  exit 1
}
[[ -f "$formal_drift_stage" && "$(<"$formal_drift_stage")" == drifted-before-cleanup ]] || {
  printf 'interrupted cleanup changed retained drifted staging\n' >&2
  exit 1
}

# Receipt cleanup must not use a checked pathname as proof that a later unlink
# still belongs to this transaction. Exercise publication rollback, interrupted
# recovery, and explicit staging discard with real replacement inodes.
python3 - "$evidence_index" "$tmpdir/formal-cleanup-replacement" <<'PY'
import hashlib
import importlib.util
import os
import pathlib
import sys


def load_indexer(path):
    spec = importlib.util.spec_from_file_location("formal_cleanup_replacement", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load evidence indexer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_private(path, content):
    path.write_bytes(content)
    path.chmod(0o600)


root = pathlib.Path(sys.argv[2])
root.mkdir(mode=0o700)
stage_dir = root / ".formal-receipts"
stage_dir.mkdir(mode=0o700)
module = load_indexer(pathlib.Path(sys.argv[1]))
failures = []

# A final replacement after the publisher's no-overwrite link must survive a
# rollback failure. The old helper inspected that replacement then unlinked it.
rollback_stage = stage_dir / "rollback-stage.json"
rollback_final = root / "rollback-final.json"
rollback_replacement = root / "rollback-replacement.json"
rollback_content = b'{"schema":"jjdguard-acceptance-receipt/v1"}\n'
rollback_sentinel = b"rollback-replacement-sentinel\n"
write_private(rollback_stage, rollback_content)
write_private(rollback_replacement, rollback_sentinel)
rollback_hash = hashlib.sha256(rollback_content).hexdigest()
root_fd = module.open_directory(root)
original_link = module.os.link
rollback_state = {"swapped": False, "failed": False}


def replace_after_publish_link(source, destination, *args, **kwargs):
    result = original_link(source, destination, *args, **kwargs)
    if os.fspath(destination) == rollback_final.name and not rollback_state["swapped"]:
        rollback_replacement.replace(rollback_final)
        rollback_state["swapped"] = True
    return result


module.os.link = replace_after_publish_link
try:
    try:
        module.publish_formal_receipt(
            root,
            root_fd,
            (".formal-receipts", rollback_stage.name),
            (rollback_final.name,),
            rollback_hash,
        )
    except module.IndexError:
        rollback_state["failed"] = True
finally:
    module.os.link = original_link
    module.os.close(root_fd)
if not rollback_state["swapped"]:
    failures.append("formal rollback replacement probe did not reach publication link")
elif not rollback_final.is_file() or rollback_final.read_bytes() != rollback_sentinel:
    failures.append("formal rollback cleanup deleted replacement final receipt")
if not rollback_state["failed"]:
    failures.append("formal rollback cleanup returned success")

# The recovery path reads a linked final before cleanup. Swap that final only
# after its cleanup stat returns, which makes the following pathname unlink
# target a different inode on the old implementation.
interrupted_stage = stage_dir / "interrupted-stage.json"
interrupted_final = root / "interrupted-final.json"
interrupted_replacement = root / "interrupted-replacement.json"
interrupted_content = b'{"schema":"jjdguard-acceptance-receipt/v1","state":"linked"}\n'
interrupted_sentinel = b"interrupted-replacement-sentinel\n"
write_private(interrupted_stage, interrupted_content)
os.link(interrupted_stage, interrupted_final)
write_private(interrupted_replacement, interrupted_sentinel)
interrupted_hash = hashlib.sha256(interrupted_content).hexdigest()
root_fd = module.open_directory(root)
original_stat = module.os.stat
interrupted_state = {"final_stats": 0, "swapped": False, "failed": False}


def replace_after_cleanup_stat(path, *args, **kwargs):
    result = original_stat(path, *args, **kwargs)
    if os.fspath(path) == interrupted_final.name:
        interrupted_state["final_stats"] += 1
        if interrupted_state["final_stats"] == 2:
            interrupted_replacement.replace(interrupted_final)
            interrupted_state["swapped"] = True
    return result


module.os.stat = replace_after_cleanup_stat
try:
    try:
        module.discard_interrupted_formal_publication(
            root,
            root_fd,
            (".formal-receipts", interrupted_stage.name),
            (interrupted_final.name,),
            interrupted_hash,
        )
    except module.IndexError:
        interrupted_state["failed"] = True
finally:
    module.os.stat = original_stat
    module.os.close(root_fd)
if interrupted_state["swapped"]:
    if not interrupted_final.is_file() or interrupted_final.read_bytes() != interrupted_sentinel:
        failures.append("interrupted cleanup deleted replacement final receipt")
elif not interrupted_final.is_file() or interrupted_final.read_bytes() != interrupted_content:
    failures.append("interrupted cleanup changed final receipt without reaching cleanup stat")
if not interrupted_state["failed"]:
    failures.append("interrupted cleanup returned success")

# Explicit staged-receipt cleanup has the same stat-to-unlink gap. A safe
# implementation may refuse before stat; otherwise the replacement must stay.
discard_stage = stage_dir / "discard-stage.json"
discard_replacement = root / "discard-replacement.json"
discard_content = b'{"schema":"jjdguard-acceptance-receipt/v1","state":"staged"}\n'
discard_sentinel = b"discard-replacement-sentinel\n"
write_private(discard_stage, discard_content)
write_private(discard_replacement, discard_sentinel)
root_fd = module.open_directory(root)
original_stat = module.os.stat
discard_state = {"swapped": False, "failed": False}


def replace_after_discard_stat(path, *args, **kwargs):
    result = original_stat(path, *args, **kwargs)
    if os.fspath(path) == discard_stage.name and not discard_state["swapped"]:
        discard_replacement.replace(discard_stage)
        discard_state["swapped"] = True
    return result


module.os.stat = replace_after_discard_stat
try:
    try:
        module.discard_formal_receipt(root_fd, (".formal-receipts", discard_stage.name))
    except module.IndexError:
        discard_state["failed"] = True
finally:
    module.os.stat = original_stat
    module.os.close(root_fd)
if discard_state["swapped"]:
    if not discard_stage.is_file() or discard_stage.read_bytes() != discard_sentinel:
        failures.append("staged cleanup deleted replacement receipt")
elif not discard_stage.is_file() or discard_stage.read_bytes() != discard_content:
    failures.append("staged cleanup changed receipt without reaching discard stat")
if not discard_state["failed"]:
    failures.append("staged cleanup returned success")

if failures:
    raise SystemExit("; ".join(failures))
PY

# Evidence indexing must fail closed when fd-anchoring flags are unavailable;
# conditional fallback would permit symlink traversal on weaker platforms.
python3 - "$evidence_index" "$evidence_root" "$artifact_json" "$release_json" <<'PY'
import os
import pathlib
import runpy
import sys

script, root, artifact, release = sys.argv[1:]
for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_TMPFILE"):
    original = getattr(os, flag, None)
    assert original is not None, flag
    output = pathlib.Path(root) / "index" / ("missing-" + flag + ".json")
    delattr(os, flag)
    try:
        sys.argv = [
            script,
            "--evidence-root", root,
            "--output", str(output),
            "--artifact-json", artifact,
            "--release-json", release,
            "--entry", "records/path-escape.json",
        ]
        try:
            runpy.run_path(script, run_name="__main__")
        except SystemExit as error:
            assert error.code == 2, (flag, error.code)
        else:
            raise AssertionError("evidence index accepted missing " + flag)
    finally:
        setattr(os, flag, original)
    assert not output.exists(), output
PY

ln -s "$step_log" "$evidence_root/linked-log"
set +e
python3 "$evidence_index" \
  --evidence-root "$evidence_root" \
  --output "$evidence_root/index/linked.json" \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --entry linked-log
linked_exit=$?
set -e
[[ "$linked_exit" -ne 0 ]] || { printf 'evidence index accepted a symlink\n' >&2; exit 1; }
[[ ! -e "$evidence_root/index/linked.json" ]] || { printf 'evidence index wrote after symlink rejection\n' >&2; exit 1; }

mkfifo "$evidence_root/fifo-log"
set +e
python3 "$evidence_index" \
  --evidence-root "$evidence_root" \
  --output "$evidence_root/index/fifo.json" \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --entry fifo-log
fifo_exit=$?
set -e
[[ "$fifo_exit" -ne 0 ]] || { printf 'evidence index accepted a FIFO\n' >&2; exit 1; }
[[ ! -e "$evidence_root/index/fifo.json" ]] || { printf 'evidence index wrote after FIFO rejection\n' >&2; exit 1; }

set +e
python3 "$evidence_index" \
  --evidence-root "$evidence_root" \
  --output "$evidence_root/index/escape.json" \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --entry ../step.log
index_escape_exit=$?
set -e
[[ "$index_escape_exit" -ne 0 ]] || { printf 'evidence index accepted an escaping entry\n' >&2; exit 1; }
[[ ! -e "$evidence_root/index/escape.json" ]] || { printf 'evidence index wrote after path rejection\n' >&2; exit 1; }

# VM/QGA execution is an explicitly live action, even when a test substitutes
# virsh. Without the opt-in, the runner must stop before invoking that binary.
no_optin_matrix="$tmpdir/no-optin-matrix.json"
no_optin_marker="$tmpdir/no-optin-virsh-called"
no_optin_log="$tmpdir/no-optin.log"
no_optin_evidence="$tmpdir/no-optin-evidence"
no_optin_virsh="$tmpdir/no-optin-virsh"
printf '%s\n' '{"expected_arch":"x86_64","scenarios":[]}' > "$no_optin_matrix"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf invoked > "$FAKE_VIRSH_MARKER"' \
  'exit 97' > "$no_optin_virsh"
chmod +x "$no_optin_virsh"
set +e
FAKE_VIRSH_MARKER="$no_optin_marker" bash "$runner" \
  --virsh "$no_optin_virsh" \
  --domain fixture-vm \
  --evidence-root "$no_optin_evidence" \
  --matrix "$no_optin_matrix" >"$no_optin_log" 2>&1
no_optin_exit=$?
set -e
[[ "$no_optin_exit" -ne 0 ]] || { printf 'runner accepted VM execution without explicit opt-in\n' >&2; exit 1; }
grep -F 'requires --allow-live-vm' "$no_optin_log" >/dev/null || {
  cat "$no_optin_log" >&2
  printf 'runner did not explain the missing live-VM opt-in\n' >&2
  exit 1
}
[[ ! -e "$no_optin_marker" ]] || { printf 'runner invoked virsh without explicit opt-in\n' >&2; exit 1; }

# A caller can pre-create the evidence root. Group- or other-writable roots
# are not a safe ownership boundary, so the recorder must fail before the
# runner can invoke QGA through virsh.
for unsafe_root_mode in 0770 0702; do
  unsafe_root_evidence="$tmpdir/unsafe-root-evidence-$unsafe_root_mode"
  unsafe_root_log="$tmpdir/unsafe-root-$unsafe_root_mode.log"
  unsafe_root_marker="$tmpdir/unsafe-root-$unsafe_root_mode-virsh-called"
  mkdir -p "$unsafe_root_evidence"
  chmod "$unsafe_root_mode" "$unsafe_root_evidence"
  set +e
  FAKE_VIRSH_MARKER="$unsafe_root_marker" bash "$runner" \
    --virsh "$no_optin_virsh" \
    --allow-live-vm \
    --qga-attempts 1 \
    --domain fixture-vm \
    --evidence-root "$unsafe_root_evidence" \
    --matrix "$no_optin_matrix" >"$unsafe_root_log" 2>&1
  unsafe_root_exit=$?
  set -e
  [[ "$unsafe_root_exit" -ne 0 ]] || { printf 'runner accepted unsafe evidence root mode %s\n' "$unsafe_root_mode" >&2; exit 1; }
  grep -F 'evidence root ownership boundary is unsafe' "$unsafe_root_log" >/dev/null || {
    cat "$unsafe_root_log" >&2
    printf 'runner did not explain unsafe evidence root mode %s\n' "$unsafe_root_mode" >&2
    exit 1
  }
  [[ ! -e "$unsafe_root_marker" ]] || { printf 'runner invoked virsh with unsafe evidence root mode %s\n' "$unsafe_root_mode" >&2; exit 1; }
  [[ ! -e "$unsafe_root_evidence/logs/vm-lifecycle.log" ]] || {
    printf 'runner wrote a lifecycle log below unsafe evidence root mode %s\n' "$unsafe_root_mode" >&2
    exit 1
  }
done

# Evidence roots and matrix inputs must be opened one directory at a time. A
# harmless-looking final path below an intermediate symlink must be rejected
# before the runner can create evidence outside the requested root or invoke
# virsh.
root_link_parent="$tmpdir/root-link-parent"
root_link_external="$tmpdir/root-link-external"
root_link_matrix="$tmpdir/root-link-matrix.json"
root_link_marker="$tmpdir/root-link-virsh-called"
root_link_log="$tmpdir/root-link.log"
mkdir -p "$root_link_parent" "$root_link_external"
ln -s "$root_link_external" "$root_link_parent/middle"
printf '%s\n' '{"expected_arch":"x86_64","scenarios":[]}' > "$root_link_matrix"
set +e
FAKE_VIRSH_MARKER="$root_link_marker" bash "$runner" \
  --virsh "$no_optin_virsh" \
  --allow-live-vm \
  --qga-attempts 1 \
  --domain fixture-vm \
  --evidence-root "$root_link_parent/middle/evidence" \
  --matrix "$root_link_matrix" >"$root_link_log" 2>&1
root_link_exit=$?
set -e
[[ "$root_link_exit" -ne 0 ]] || { printf 'runner accepted an intermediate evidence-root symlink\n' >&2; exit 1; }
grep -F 'cannot canonicalize evidence root' "$root_link_log" >/dev/null || {
  cat "$root_link_log" >&2
  printf 'runner did not explain the unsafe evidence-root hierarchy\n' >&2
  exit 1
}
[[ ! -e "$root_link_marker" ]] || { printf 'runner invoked virsh through an intermediate evidence-root symlink\n' >&2; exit 1; }
[[ ! -e "$root_link_external/evidence" ]] || { printf 'runner created evidence through an intermediate symlink\n' >&2; exit 1; }

matrix_link_parent="$tmpdir/matrix-link-parent"
matrix_link_external="$tmpdir/matrix-link-external"
matrix_link_evidence="$tmpdir/matrix-link-evidence"
matrix_link_marker="$tmpdir/matrix-link-virsh-called"
matrix_link_log="$tmpdir/matrix-link.log"
mkdir -p "$matrix_link_parent" "$matrix_link_external"
ln -s "$matrix_link_external" "$matrix_link_parent/middle"
printf '%s\n' '{"expected_arch":"x86_64","scenarios":[]}' > "$matrix_link_external/matrix.json"
set +e
FAKE_VIRSH_MARKER="$matrix_link_marker" bash "$runner" \
  --virsh "$no_optin_virsh" \
  --allow-live-vm \
  --qga-attempts 1 \
  --domain fixture-vm \
  --evidence-root "$matrix_link_evidence" \
  --matrix "$matrix_link_parent/middle/matrix.json" >"$matrix_link_log" 2>&1
matrix_link_exit=$?
set -e
[[ "$matrix_link_exit" -ne 0 ]] || { printf 'runner accepted an intermediate matrix symlink\n' >&2; exit 1; }
grep -F 'matrix is invalid' "$matrix_link_log" >/dev/null || {
  cat "$matrix_link_log" >&2
  printf 'runner did not explain the unsafe matrix hierarchy\n' >&2
  exit 1
}
[[ ! -e "$matrix_link_marker" ]] || { printf 'runner invoked virsh through an intermediate matrix symlink\n' >&2; exit 1; }

# QGA returns the same boot ID before and after a successful virsh reboot. The
# runner must fail closed and persist a redacted FAIL record for this VM-only
# condition; no actual VM or network is used.
boot_bin="$tmpdir/boot-bin"
mkdir -p "$boot_bin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'case "${1:-}" in' \
  '  reboot) exit 0 ;;' \
  '  qemu-agent-command)' \
  '    request="${*: -1}"' \
  '    case "$request" in' \
  "      *guest-exec-status*) printf '%s\\n' '{\"return\":{\"exited\":true,\"exitcode\":0,\"out-data\":\"Ym9vdC1zdGFibGUK\"}}' ;;" \
  "      *guest-exec*) printf '%s\\n' '{\"return\":{\"pid\":7}}' ;;" \
  '      *) exit 64 ;;' \
  '    esac ;;' \
  '  *) exit 64 ;;' \
  'esac' > "$boot_bin/virsh"
chmod +x "$boot_bin/virsh"
boot_matrix="$tmpdir/boot-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","scenarios":[]}' > "$boot_matrix"
boot_evidence="$tmpdir/boot-evidence"

set +e
bash "$runner" \
  --virsh "$boot_bin/virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$boot_evidence" \
  --matrix "$boot_matrix"
boot_exit=$?
set -e
[[ "$boot_exit" -ne 0 ]] || { printf 'runner accepted an unchanged boot ID\n' >&2; exit 1; }
boot_record="$boot_evidence/records/vm-lifecycle.json"
[[ -f "$boot_record" ]] || { printf 'runner did not write boot-ID FAIL evidence\n' >&2; exit 1; }
python3 - "$boot_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "FAIL"
assert record["scenario"] == "vm-lifecycle"
assert record["details"]["reason"] == "boot_id_unchanged"
assert "boot-stable" not in json.dumps(record, sort_keys=True)
PY

# A reboot that changes boot ID still cannot promote a package built for a
# different architecture. The runner must make the QGA architecture mismatch a
# structured FAIL record before it attempts any scenario.
arch_bin="$tmpdir/arch-bin"
arch_state="$tmpdir/arch-state"
mkdir -p "$arch_bin" "$arch_state"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'case "${1:-}" in' \
  '  reboot) exit 0 ;;' \
  '  qemu-agent-command)' \
  '    request="${*: -1}"' \
  '    case "$request" in' \
  '      *guest-exec-status*)' \
  '        case "$request" in' \
  "          *11*) printf '%s\\n' '{\"return\":{\"exited\":true,\"exitcode\":0,\"out-data\":\"Ym9vdC1hCg==\"}}' ;;" \
  "          *12*) printf '%s\\n' '{\"return\":{\"exited\":true,\"exitcode\":0,\"out-data\":\"Ym9vdC1iCg==\"}}' ;;" \
  "          *21*) printf '%s\\n' '{\"return\":{\"exited\":true,\"exitcode\":0,\"out-data\":\"YWFyY2g2NAo=\"}}' ;;" \
  '          *) exit 64 ;;' \
  '        esac ;;' \
  '      *guest-exec*)' \
  '        if [[ "$request" == *"/proc/sys/kernel/random/boot_id"* ]]; then' \
  '          count_file="$FAKE_QGA_STATE/boot-count"' \
  '          count=0; [[ -f "$count_file" ]] && count=$(<"$count_file")' \
  '          count=$((count + 1)); printf "%s" "$count" > "$count_file"' \
  "          if [[ \"\$count\" -eq 1 ]]; then printf '%s\\n' '{\"return\":{\"pid\":11}}'; else printf '%s\\n' '{\"return\":{\"pid\":12}}'; fi" \
  '        elif [[ "$request" == *"uname -m"* ]]; then' \
  "          printf '%s\\n' '{\"return\":{\"pid\":21}}'" \
  '        else' \
  '          exit 64' \
  '        fi ;;' \
  '      *) exit 64 ;;' \
  '    esac ;;' \
  '  *) exit 64 ;;' \
  'esac' > "$arch_bin/virsh"
chmod +x "$arch_bin/virsh"
arch_matrix="$tmpdir/arch-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","scenarios":[]}' > "$arch_matrix"
arch_evidence="$tmpdir/arch-evidence"

set +e
FAKE_QGA_STATE="$arch_state" bash "$runner" \
  --virsh "$arch_bin/virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$arch_evidence" \
  --matrix "$arch_matrix"
arch_exit=$?
set -e
[[ "$arch_exit" -ne 0 ]] || { printf 'runner accepted an architecture mismatch\n' >&2; exit 1; }
arch_record="$arch_evidence/records/vm-metadata.json"
[[ -f "$arch_record" ]] || { printf 'runner did not write architecture FAIL evidence\n' >&2; exit 1; }
python3 - "$arch_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "FAIL"
assert record["details"]["reason"] == "architecture_mismatch"
assert "aarch64" in json.dumps(record, sort_keys=True)
PY

# Reusable fake libvirt/QGA transport. It executes no guest commands: command
# strings select canned QGA responses, and a mode can only mutate a named local
# test log to exercise the runner's post-record integrity check.
fixture_virsh="$tmpdir/fixture-virsh.py"
printf '%s\n' \
  '#!/usr/bin/env python3' \
  'import base64' \
  'import json' \
  'import os' \
  'import pathlib' \
  'import subprocess' \
  'import sys' \
  '' \
  'state = pathlib.Path(os.environ["FAKE_QGA_STATE"])' \
  'state.mkdir(mode=0o700, parents=True, exist_ok=True)' \
  '' \
  'def emit(value):' \
  '    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")' \
  '' \
  'def next_pid(response):' \
  '    counter = state / "pid"' \
  '    value = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0' \
  '    value += 1' \
  '    counter.write_text(str(value), encoding="utf-8")' \
  '    (state / ("pid-" + str(value) + ".json")).write_text(json.dumps(response), encoding="utf-8")' \
  '    return value' \
  '' \
  'def response_for(command):' \
  '    if command == "cat /proc/sys/kernel/random/boot_id":' \
  '        counter = state / "boot"' \
  '        value = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0' \
  '        value += 1' \
  '        counter.write_text(str(value), encoding="utf-8")' \
  '        return {"exit_code": 0, "stdout": "boot-a\n" if value == 1 else "boot-b\n"}' \
  '    if command == "uname -m":' \
  '        if os.environ.get("FAKE_QGA_MODE") == "architecture-nul":' \
  '            return {"exit_code": 0, "stdout_b64": base64.b64encode(b"x86_64\x00\n").decode("ascii")}' \
  '        if os.environ.get("FAKE_QGA_MODE") == "architecture-crlf":' \
  '            return {"exit_code": 0, "stdout_b64": base64.b64encode(b"x86_64\r\n").decode("ascii")}' \
  '        if os.environ.get("FAKE_QGA_MODE") == "architecture-oversize":' \
  '            return {"exit_code": 0, "stdout_b64": base64.b64encode(b"QGA_LIMIT_ARCH_SENTINEL" + b"a" * 129).decode("ascii")}' \
  '        return {"exit_code": 0, "stdout": os.environ.get("FAKE_QGA_ARCH", "x86_64") + "\n"}' \
  '    if command == "cat /etc/os-release":' \
  '        if os.environ.get("FAKE_QGA_MODE") == "metadata-decoded-oversize": return {"exit_code": 0, "stdout_b64": base64.b64encode(b"QGA_LIMIT_METADATA_SENTINEL" + b"a" * (1024 * 1024)).decode("ascii")}' \
  '        if os.environ.get("FAKE_QGA_MODE") == "metadata-payload": return {"exit_code": 0, "stdout": "payload=private\n"}' \
  '        if os.environ.get("FAKE_QGA_MODE") == "metadata-prompt": return {"exit_code": 0, "stdout": "prompt=private\n"}' \
  '        return {"exit_code": 0, "stdout": "PRETTY_NAME=Fixture OS\n"}' \
  '    if command == "uname -r": return {"exit_code": 0, "stdout": "6.1.0-fixture\n"}' \
  '    if command == "nproc": return {"exit_code": 0, "stdout": "4\n"}' \
  '    if command == "awk \"/MemTotal/ {print \\$2}\" /proc/meminfo": return {"exit_code": 0, "stdout": "1048576\n"}' \
  '    if command.startswith("docker version --format"): return {"exit_code": 0, "stdout": "27.0|27.0\n"}' \
  '    if command == "network-probe":' \
  '        if os.environ.get("FAKE_QGA_MODE") == "network-reachable": return {"exit_code": 0, "stdout": "public-ok\n"}' \
  '        return {"exit_code": 7, "stdout": "offline\n"}' \
  '    if command == "migration-baseline-probe":' \
  '        return {"exit_code": 0, "stdout": json.dumps({"schema":"jjdguard-home-migration-baseline/v1","artifact":{"run_sha256":"b" * 64,"run_size":1,"inner_tar_sha256":"c" * 64},"release":{"source_revision":"d" * 40,"source_tree":"e" * 40,"image_provenance_sha256":"f" * 64,"sbom_index_sha256":"0" * 64},"ledgers":[{"name":"schema_migrations_before","entries":[{"version":"001_fixture.sql","checksum":"1" * 64}]},{"name":"schema_migrations_after","entries":[{"version":"001_fixture.sql","checksum":"1" * 64},{"version":"002_fixture.sql","checksum":"2" * 64}]}]}) + "\n"}' \
  '    if command == "fail-scenario": return {"exit_code": 42, "stdout": "scenario-failed\n"}' \
  '    if command == "qga-limit-scenario" and os.environ.get("FAKE_QGA_MODE") == "scenario-decoded-oversize": return {"exit_code": 0, "stdout_b64": base64.b64encode(b"QGA_LIMIT_SCENARIO_SENTINEL" + b"a" * (1024 * 1024)).decode("ascii")}' \
  '    if command == "qga-limit-migration-probe" and os.environ.get("FAKE_QGA_MODE") == "migration-probe-decoded-oversize": return {"exit_code": 0, "stdout_b64": base64.b64encode(b"QGA_LIMIT_MIGRATION_PROBE_SENTINEL" + b"a" * (1024 * 1024)).decode("ascii")}' \
  '    if command == "qga-limit-business-probe" and os.environ.get("FAKE_QGA_MODE") == "business-probe-decoded-oversize": return {"exit_code": 0, "stdout_b64": base64.b64encode(b"QGA_LIMIT_BUSINESS_PROBE_SENTINEL" + b"a" * (1024 * 1024)).decode("ascii")}' \
  '    if command == "tamper-log":' \
  '        target = os.environ.get("FAKE_TAMPER_PATH")' \
  '        if target: pathlib.Path(target).open("a", encoding="utf-8").write("tampered\n")' \
  '        return {"exit_code": 0, "stdout": "ok\n"}' \
  '    if command == "replace-log-invalid-status": return {"invalid_status": True}' \
  '    return {"exit_code": 0, "stdout": "ok\n"}' \
  '' \
  'if len(sys.argv) < 2: raise SystemExit(64)' \
  'if sys.argv[1] == "reboot": raise SystemExit(0)' \
  'if sys.argv[1] != "qemu-agent-command": raise SystemExit(64)' \
  'try: request = json.loads(sys.argv[-1])' \
  'except json.JSONDecodeError: raise SystemExit(64)' \
  'if request.get("execute") == "guest-exec":' \
  '    command = request.get("arguments", {}).get("arg", [""])[-1]' \
  '    if os.environ.get("FAKE_QGA_MODE") == "pid-control-unbounded":' \
  '        emit({"return": {"pid": 1}, "padding": "QGA_LIMIT_UNBOUNDED_SENTINEL" * 1024})' \
  '        while True:' \
  '            sys.stdout.write("QGA_LIMIT_UNBOUNDED_SENTINEL")' \
  '            sys.stdout.flush()' \
  '    elif os.environ.get("FAKE_QGA_MODE") == "pid-control-oversize":' \
  '        emit({"return": {"pid": 1}, "padding": "QGA_LIMIT_PID_SENTINEL" * 1024})' \
  '    elif os.environ.get("FAKE_QGA_MODE") == "pid-control-parent-exit-child-unbounded":' \
  '        child = subprocess.Popen([sys.executable, "-c", base64.b64decode("aW1wb3J0IGpzb24sIG9zLCBzaWduYWwsIHN5cywgdGltZQpwYXJlbnRfcGlkID0gaW50KHN5cy5hcmd2WzFdKQp3aGlsZSBvcy5nZXRwcGlkKCkgPT0gcGFyZW50X3BpZDoKICAgIHRpbWUuc2xlZXAoMC4wMDEpCnNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1BJUEUsIHNpZ25hbC5TSUdfSUdOKQpzeXMuc3Rkb3V0LndyaXRlKGpzb24uZHVtcHMoeyJyZXR1cm4iOiB7InBpZCI6IDF9LCAicGFkZGluZyI6ICJRR0FfTElNSVRfUEFSRU5UX0VYSVRfQ0hJTERfU0VOVElORUwiICogNjAwfSwgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKSArICJcbiIpCnN5cy5zdGRvdXQuZmx1c2goKQp3aGlsZSBUcnVlOgogICAgdHJ5OgogICAgICAgIHN5cy5zdGRvdXQud3JpdGUoIlFHQV9MSU1JVF9QQVJFTlRfRVhJVF9DSElMRF9TRU5USU5FTCIpCiAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgpCiAgICBleGNlcHQgQnJva2VuUGlwZUVycm9yOgogICAgICAgIHRpbWUuc2xlZXAoMC4wMSkK").decode("ascii"), str(os.getpid())])' \
  '        (state / "parent-exit-child.pid").write_text(str(child.pid), encoding="utf-8")' \
  '        raise SystemExit(0)' \
  '    else:' \
  '        emit({"return": {"pid": next_pid(response_for(command))}})' \
  'elif request.get("execute") == "guest-exec-status":' \
  '    pid = request.get("arguments", {}).get("pid")' \
  '    path = state / ("pid-" + str(pid) + ".json")' \
  '    if not path.is_file(): raise SystemExit(64)' \
  '    response = json.loads(path.read_text(encoding="utf-8"))' \
  '    if response.get("invalid_status"):' \
  '        target = os.environ.get("FAKE_REPLACE_PATH")' \
  '        replacement = os.environ.get("FAKE_REPLACE_TARGET")' \
  '        if target and replacement:' \
  '            pathlib.Path(target).unlink()' \
  '            os.symlink(replacement, target)' \
  '        emit({"return": {"exited": "invalid"}})' \
  '        raise SystemExit(0)' \
  '    output = response.get("stdout_b64")' \
  '    if output is None:' \
  '        output = base64.b64encode(response.get("stdout", "").encode("utf-8")).decode("ascii")' \
  '    if os.environ.get("FAKE_QGA_MODE") == "status-control-oversize":' \
  '        emit({"return": {"exited": True, "exitcode": 0, "out-data": ""}, "padding": "QGA_LIMIT_STATUS_SENTINEL" * 65536})' \
  '    else:' \
  '        emit({"return": {"exited": True, "exitcode": response["exit_code"], "out-data": output}})' \
  'else: raise SystemExit(64)' > "$fixture_virsh"
chmod +x "$fixture_virsh"

# QGA architecture output is external input. A malformed or over-limit value
# must still persist a redacted metadata FAIL record rather than making details
# serialization abort after the mismatch has already been detected.
unsafe_arch_matrix="$tmpdir/unsafe-arch-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","scenarios":[]}' > "$unsafe_arch_matrix"
unsafe_arch_overlong="$(python3 - <<'PY'
print("a" * 1025)
PY
)"
unsafe_arch_values=("$unsafe_arch_overlong" $'aarch64\x01')
unsafe_arch_index=0
for unsafe_arch in "${unsafe_arch_values[@]}"; do
  unsafe_arch_index=$((unsafe_arch_index + 1))
  unsafe_arch_state="$tmpdir/unsafe-arch-state-$unsafe_arch_index"
  unsafe_arch_evidence="$tmpdir/unsafe-arch-evidence-$unsafe_arch_index"
  mkdir -p "$unsafe_arch_state"
  set +e
  FAKE_QGA_STATE="$unsafe_arch_state" \
  FAKE_QGA_ARCH="$unsafe_arch" \
  bash "$runner" \
    --virsh "$fixture_virsh" \
    --allow-live-vm \
    --domain fixture-vm \
    --evidence-root "$unsafe_arch_evidence" \
    --matrix "$unsafe_arch_matrix"
  unsafe_arch_exit=$?
  set -e
  [[ "$unsafe_arch_exit" -ne 0 ]] || { printf 'runner accepted unsafe QGA architecture output\n' >&2; exit 1; }
  unsafe_arch_record="$unsafe_arch_evidence/records/vm-metadata.json"
  if [[ "$unsafe_arch" == "$unsafe_arch_overlong" ]]; then
    unsafe_arch_reason=qga_limit_exceeded
  else
    unsafe_arch_reason=qga_architecture_invalid
  fi
  [[ -f "$unsafe_arch_record" ]] || { printf 'runner did not write unsafe-architecture FAIL evidence\n' >&2; exit 1; }
  python3 - "$unsafe_arch_record" "$unsafe_arch_reason" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "FAIL"
assert record["exit_code"] == 76
assert record["details"] == {"reason": sys.argv[2]}
assert "actual_arch" not in record["details"]
PY
done

# The QGA architecture protocol carries raw bytes under base64. This fixture
# generates the NUL in Python itself rather than trying to smuggle it through
# an environment variable or Bash string. An implementation that decodes into
# command substitution before validation silently sees x86_64 and writes PASS.
nul_arch_state="$tmpdir/nul-arch-state"
nul_arch_evidence="$tmpdir/nul-arch-evidence"
nul_arch_log="$tmpdir/nul-arch.log"
mkdir -p "$nul_arch_state"
set +e
FAKE_QGA_STATE="$nul_arch_state" \
FAKE_QGA_MODE=architecture-nul \
bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$nul_arch_evidence" \
  --matrix "$unsafe_arch_matrix" >"$nul_arch_log" 2>&1
nul_arch_exit=$?
set -e
nul_arch_record="$nul_arch_evidence/records/vm-metadata.json"
if [[ "$nul_arch_exit" -ne 76 ]]; then
  [[ -f "$nul_arch_record" ]] || {
    cat "$nul_arch_log" >&2
    printf 'runner did not write metadata while handling a NUL QGA architecture\n' >&2
    exit 1
  }
  python3 - "$nul_arch_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "PASS", record
assert record["details"]["arch"] == "x86_64", record
PY
  cat "$nul_arch_log" >&2
  printf 'runner accepted a NUL QGA architecture and wrote PASS metadata\n' >&2
  exit 1
fi
if grep -F 'ignored null byte in input' "$nul_arch_log" >/dev/null; then
  cat "$nul_arch_log" >&2
  printf 'runner decoded raw NUL before architecture validation\n' >&2
  exit 1
fi
[[ -f "$nul_arch_record" ]] || { printf 'runner did not write NUL architecture FAIL evidence\n' >&2; exit 1; }
python3 - "$nul_arch_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
serialized = json.dumps(record, sort_keys=True)
encoded = serialized.encode("utf-8")
assert record["status"] == "FAIL"
assert record["exit_code"] == 76
assert record["details"] == {"reason": "qga_architecture_invalid"}
assert "x86_64" not in serialized
assert b"\x00" not in encoded
assert "\\u0000" not in serialized
PY

# A legal base64 envelope can still be too large for an acceptance probe. The
# transport parser must reject it before copying raw bytes into Bash or
# architecture normalization; the failure remains a redacted FAIL/76 record.
oversize_arch_state="$tmpdir/oversize-arch-state"
oversize_arch_evidence="$tmpdir/oversize-arch-evidence"
oversize_arch_log="$tmpdir/oversize-arch.log"
mkdir -p "$oversize_arch_state"
set +e
FAKE_QGA_STATE="$oversize_arch_state" \
FAKE_QGA_MODE=architecture-oversize \
bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$oversize_arch_evidence" \
  --matrix "$unsafe_arch_matrix" >"$oversize_arch_log" 2>&1
oversize_arch_exit=$?
set -e
[[ "$oversize_arch_exit" -eq 76 ]] || {
  cat "$oversize_arch_log" >&2
  printf 'runner did not classify oversized QGA architecture output as FAIL/76\n' >&2
  exit 1
}
oversize_metadata_log="$oversize_arch_evidence/logs/vm-metadata.log"
grep -Fx 'qga_limit_exceeded' "$oversize_metadata_log" >/dev/null || {
  cat "$oversize_arch_log" >&2
  [[ -f "$oversize_metadata_log" ]] && cat "$oversize_metadata_log" >&2
  printf 'runner did not reject oversized QGA output at the transport boundary\n' >&2
  exit 1
}
oversize_arch_record="$oversize_arch_evidence/records/vm-metadata.json"
python3 - "$oversize_arch_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "FAIL"
assert record["exit_code"] == 76
assert record["details"] == {"reason": "qga_limit_exceeded"}
PY

# Every QGA transport limit is a security boundary, regardless of whether the
# response is a PID control envelope, a status envelope, a normal text value,
# or an architecture value. Each must stop with the same redacted FAIL/76
# contract and must never copy the untrusted bytes into evidence or runner logs.
qga_limit_scenario_matrix="$tmpdir/qga-limit-scenario-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","network_probe":"network-probe","scenarios":[{"name":"qga-limit-scenario","command":"qga-limit-scenario","migration_probe":"qga-limit-migration-probe","business_probe":"qga-limit-business-probe"}]}' > "$qga_limit_scenario_matrix"
qga_limit_cases=(
  'metadata-decoded-oversize|vm-metadata|QGA_LIMIT_METADATA_SENTINEL|metadata'
  'pid-control-oversize|vm-lifecycle|QGA_LIMIT_PID_SENTINEL|metadata'
  'pid-control-unbounded|vm-lifecycle|QGA_LIMIT_UNBOUNDED_SENTINEL|metadata'
  'pid-control-parent-exit-child-unbounded|vm-lifecycle|QGA_LIMIT_PARENT_EXIT_CHILD_SENTINEL|metadata|parent-exit-child.pid'
  'status-control-oversize|vm-lifecycle|QGA_LIMIT_STATUS_SENTINEL|metadata'
  'architecture-oversize|vm-metadata|QGA_LIMIT_ARCH_SENTINEL|metadata'
  'scenario-decoded-oversize|qga-limit-scenario|QGA_LIMIT_SCENARIO_SENTINEL|scenario'
  'migration-probe-decoded-oversize|qga-limit-scenario.migration-probe|QGA_LIMIT_MIGRATION_PROBE_SENTINEL|scenario'
  'business-probe-decoded-oversize|qga-limit-scenario.business-probe|QGA_LIMIT_BUSINESS_PROBE_SENTINEL|scenario'
)
qga_limit_failures=()
for qga_limit_case in "${qga_limit_cases[@]}"; do
  IFS='|' read -r qga_limit_mode qga_limit_record_id qga_limit_sentinel qga_limit_matrix_kind qga_limit_child_pid_file <<<"$qga_limit_case"
  if [[ "$qga_limit_matrix_kind" == scenario ]]; then
    qga_limit_matrix="$qga_limit_scenario_matrix"
  else
    qga_limit_matrix="$unsafe_arch_matrix"
  fi
  qga_limit_state="$tmpdir/qga-limit-$qga_limit_mode-state"
  qga_limit_evidence="$tmpdir/qga-limit-$qga_limit_mode-evidence"
  qga_limit_log="$tmpdir/qga-limit-$qga_limit_mode.log"
  mkdir -p "$qga_limit_state"
  set +e
  if [[ "$qga_limit_mode" == pid-control-unbounded ]]; then
    timeout -k 1s 4s env \
      FAKE_QGA_STATE="$qga_limit_state" \
      FAKE_QGA_MODE="$qga_limit_mode" \
      bash "$runner" \
        --virsh "$fixture_virsh" \
        --allow-live-vm \
        --domain fixture-vm \
        --evidence-root "$qga_limit_evidence" \
        --matrix "$qga_limit_matrix" >"$qga_limit_log" 2>&1
  else
    FAKE_QGA_STATE="$qga_limit_state" \
    FAKE_QGA_MODE="$qga_limit_mode" \
    bash "$runner" \
      --virsh "$fixture_virsh" \
      --allow-live-vm \
      --domain fixture-vm \
      --evidence-root "$qga_limit_evidence" \
      --matrix "$qga_limit_matrix" >"$qga_limit_log" 2>&1
  fi
  qga_limit_exit=$?
  set -e
  if [[ "$qga_limit_exit" -ne 76 ]]; then
    qga_limit_failures+=("$qga_limit_mode returned $qga_limit_exit instead of 76")
  fi
  qga_limit_record="$qga_limit_evidence/records/$qga_limit_record_id.json"
  if [[ ! -f "$qga_limit_record" ]]; then
    qga_limit_failures+=("$qga_limit_mode did not write its FAIL record")
  elif ! python3 - "$qga_limit_record" "$qga_limit_sentinel" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
record = json.loads(raw)
serialized = json.dumps(record, sort_keys=True)
assert record["status"] == "FAIL", record
assert record["exit_code"] == 76, record
assert record["details"] == {"reason": "qga_limit_exceeded"}, record
assert sys.argv[2] not in serialized, record
PY
  then
    qga_limit_failures+=("$qga_limit_mode wrote the wrong FAIL receipt")
  fi
  qga_limit_step_log="$qga_limit_evidence/logs/$qga_limit_record_id.log"
  if ! grep -Fx 'qga_limit_exceeded' "$qga_limit_step_log" >/dev/null 2>&1; then
    qga_limit_failures+=("$qga_limit_mode did not record qga_limit_exceeded")
  fi
  if grep -R -F -- "$qga_limit_sentinel" "$qga_limit_evidence" "$qga_limit_log" >/dev/null 2>&1; then
    qga_limit_failures+=("$qga_limit_mode leaked its raw QGA sentinel")
  fi
  if [[ -n "$qga_limit_child_pid_file" ]] && ! python3 - "$qga_limit_state/$qga_limit_child_pid_file" <<'PY'
import os
import pathlib
import signal
import sys
import time

path = pathlib.Path(sys.argv[1])
try:
    pid = int(path.read_text(encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit(1)
deadline = time.monotonic() + 2
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        raise SystemExit(0)
    time.sleep(0.02)
try:
    os.kill(pid, signal.SIGKILL)
except ProcessLookupError:
    pass
raise SystemExit(1)
PY
  then
    qga_limit_failures+=("$qga_limit_mode left its parent-exited producer running")
  fi
done
if (( ${#qga_limit_failures[@]} > 0 )); then
  printf 'QGA limit cases did not yield redacted FAIL/76:\n' >&2
  printf ' - %s\n' "${qga_limit_failures[@]}" >&2
  exit 1
fi

# Terminal CRLF is the one text normalization permitted for the architecture
# probe. The fixture produces these bytes in Python, not in a Bash variable.
# The small matrix intentionally stops later at the formal-input boundary; the
# PASS metadata record proves this architecture value itself was accepted.
crlf_arch_state="$tmpdir/crlf-arch-state"
crlf_arch_evidence="$tmpdir/crlf-arch-evidence"
crlf_arch_log="$tmpdir/crlf-arch.log"
mkdir -p "$crlf_arch_state"
set +e
FAKE_QGA_STATE="$crlf_arch_state" \
FAKE_QGA_MODE=architecture-crlf \
bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$crlf_arch_evidence" \
  --matrix "$unsafe_arch_matrix" >"$crlf_arch_log" 2>&1
crlf_arch_exit=$?
set -e
[[ "$crlf_arch_exit" -ne 76 ]] || {
  cat "$crlf_arch_log" >&2
  printf 'runner rejected terminal CRLF in a QGA architecture\n' >&2
  exit 1
}
crlf_arch_record="$crlf_arch_evidence/records/vm-metadata.json"
[[ -f "$crlf_arch_record" ]] || { printf 'runner did not write CRLF architecture metadata\n' >&2; exit 1; }
python3 - "$crlf_arch_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "PASS"
assert record["details"]["arch"] == "x86_64"
PY

# The runner sends QGA metadata through record-step.py, so its raw payload and
# prompt values must receive the same redaction as a direct recorder caller.
for qga_sensitive_mode in metadata-payload metadata-prompt; do
  qga_sensitive_name=${qga_sensitive_mode#metadata-}
  qga_sensitive_state="$tmpdir/$qga_sensitive_mode-state"
  qga_sensitive_evidence="$tmpdir/$qga_sensitive_mode-evidence"
  qga_sensitive_log="$tmpdir/$qga_sensitive_mode.log"
  mkdir -p "$qga_sensitive_state"
  set +e
  FAKE_QGA_STATE="$qga_sensitive_state" \
  FAKE_QGA_MODE="$qga_sensitive_mode" \
  bash "$runner" \
    --virsh "$fixture_virsh" \
    --allow-live-vm \
    --domain fixture-vm \
    --evidence-root "$qga_sensitive_evidence" \
    --matrix "$unsafe_arch_matrix" >"$qga_sensitive_log" 2>&1
  qga_sensitive_exit=$?
  set -e
  qga_sensitive_record="$qga_sensitive_evidence/records/vm-metadata.json"
  [[ -f "$qga_sensitive_record" ]] || {
    cat "$qga_sensitive_log" >&2
    printf 'runner did not write %s metadata evidence\n' "$qga_sensitive_name" >&2
    exit 1
  }
  python3 - "$qga_sensitive_record" "$qga_sensitive_name" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
term = sys.argv[2] + "=private"
raw = path.read_bytes()
if term.encode("utf-8") in raw:
    raise SystemExit("runner retained sensitive " + sys.argv[2] + " metadata")
record = json.loads(raw)
assert record["status"] == "PASS"
assert record["details"]["os"] == "[redacted]"
PY
done

# A non-zero guest scenario must keep its raw output out of evidence while
# retaining the real exit code in a scenario-specific FAIL record.
scenario_matrix="$tmpdir/scenario-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","network_probe":"network-probe","scenarios":[{"name":"n1-install","command":"fail-scenario"}]}' > "$scenario_matrix"
scenario_state="$tmpdir/scenario-state"
scenario_evidence="$tmpdir/scenario-evidence"
mkdir -p "$scenario_state"
set +e
FAKE_QGA_STATE="$scenario_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$scenario_evidence" \
  --matrix "$scenario_matrix"
scenario_exit=$?
set -e
[[ "$scenario_exit" -ne 0 ]] || { printf 'runner accepted a non-zero scenario\n' >&2; exit 1; }
scenario_record="$scenario_evidence/records/n1-install.json"
[[ -f "$scenario_record" ]] || { printf 'runner did not write scenario FAIL evidence\n' >&2; exit 1; }
python3 - "$scenario_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "FAIL"
assert record["exit_code"] == 42
assert record["details"]["reason"] == "scenario_exit_nonzero"
assert "scenario-failed" not in json.dumps(record, sort_keys=True)
PY

# Replacing a step log after create but before runner append must not redirect a
# host write through a symlink. The fake returns malformed QGA status only
# after replacing the scenario log, forcing the runner's append failure path.
append_race_matrix="$tmpdir/append-race-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","network_probe":"network-probe","scenarios":[{"name":"n1-install","command":"replace-log-invalid-status"}]}' > "$append_race_matrix"
append_race_state="$tmpdir/append-race-state"
append_race_evidence="$tmpdir/append-race-evidence"
append_race_target="$tmpdir/append-race-target.log"
printf '%s\n' 'outside-unchanged' > "$append_race_target"
mkdir -p "$append_race_state"
set +e
FAKE_QGA_STATE="$append_race_state" \
FAKE_REPLACE_PATH="$append_race_evidence/logs/n1-install.log" \
FAKE_REPLACE_TARGET="$append_race_target" \
bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$append_race_evidence" \
  --matrix "$append_race_matrix"
append_race_exit=$?
set -e
[[ "$append_race_exit" -ne 0 ]] || { printf 'runner accepted a replaced log\n' >&2; exit 1; }
[[ "$(<"$append_race_target")" == outside-unchanged ]] || { printf 'runner appended through a replaced log symlink\n' >&2; exit 1; }

# Migration and business probes are independently executable VM steps. Their
# real non-zero guest exit must survive into the scenario FAIL record.
probe_matrix="$tmpdir/probe-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","network_probe":"network-probe","scenarios":[{"name":"n1-install","command":"success-scenario","migration_probe":"fail-scenario","business_probe":"business-n1-install"}]}' > "$probe_matrix"
probe_state="$tmpdir/probe-state"
probe_evidence="$tmpdir/probe-evidence"
mkdir -p "$probe_state"
set +e
FAKE_QGA_STATE="$probe_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$probe_evidence" \
  --matrix "$probe_matrix"
probe_exit=$?
set -e
[[ "$probe_exit" -ne 0 ]] || { printf 'runner accepted a non-zero migration probe\n' >&2; exit 1; }
probe_record="$probe_evidence/records/n1-install.migration-probe.json"
[[ -f "$probe_record" ]] || { printf 'runner did not write migration-probe FAIL evidence\n' >&2; exit 1; }
python3 - "$probe_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "FAIL"
assert record["exit_code"] == 42
assert record["scenario"] == "n1-install"
assert record["step"] == "migration-probe"
assert record["details"]["reason"] == "migration_probe_nonzero"
PY

# The matrix is for offline delivery. If its in-guest network probe can reach
# the public internet, the runner must stop before scenarios and emit evidence.
network_matrix="$tmpdir/network-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","network_probe":"network-probe","scenarios":[]}' > "$network_matrix"
network_state="$tmpdir/network-state"
network_evidence="$tmpdir/network-evidence"
mkdir -p "$network_state"
set +e
FAKE_QGA_MODE=network-reachable FAKE_QGA_STATE="$network_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$network_evidence" \
  --matrix "$network_matrix"
network_exit=$?
set -e
[[ "$network_exit" -ne 0 ]] || { printf 'runner accepted public network access\n' >&2; exit 1; }
network_record="$network_evidence/records/network.json"
[[ -f "$network_record" ]] || { printf 'runner did not write public-network FAIL evidence\n' >&2; exit 1; }
python3 - "$network_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "FAIL"
assert record["details"]["reason"] == "public_network_reachable"
assert "public-ok" not in json.dumps(record, sort_keys=True)
PY

# The runner must validate hashes recorded for immutable step logs before it
# can produce a receipt. The fake QGA mutates metadata.log only after that
# record has been written, simulating host-side evidence tampering.
integrity_matrix="$tmpdir/integrity-matrix.json"
printf '%s\n' '{"expected_arch":"x86_64","network_probe":"network-probe","scenarios":[{"name":"n1-install","command":"tamper-log"}]}' > "$integrity_matrix"
integrity_state="$tmpdir/integrity-state"
integrity_evidence="$tmpdir/integrity-evidence"
mkdir -p "$integrity_state"
set +e
FAKE_QGA_STATE="$integrity_state" \
FAKE_TAMPER_PATH="$integrity_evidence/logs/vm-metadata.log" \
bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$integrity_evidence" \
  --matrix "$integrity_matrix"
integrity_exit=$?
set -e
[[ "$integrity_exit" -ne 0 ]] || { printf 'runner accepted a changed step log\n' >&2; exit 1; }
integrity_record="$integrity_evidence/records/evidence-integrity.json"
[[ -f "$integrity_record" ]] || { printf 'runner did not write log-hash FAIL evidence\n' >&2; exit 1; }
python3 - "$integrity_record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["status"] == "FAIL"
assert record["details"]["reason"] == "log_hash_mismatch"
assert "tampered" not in json.dumps(record, sort_keys=True)
PY

# A complete fixture matrix may produce evidence, but cannot claim a formal
# PASS receipt without the real artifact, source repository, public key, and
# independent verifier inputs. The record set must nevertheless be complete
# and indexable with the exact existing verifier-facing index schema.
success_matrix="$tmpdir/success-matrix.json"
python3 - "$success_matrix" <<'PY'
import json
import sys

names = [
    "n1-install", "clean-install", "offline-reboot", "upgrade-n1-r7",
    "rollback-r7-n1", "reupgrade-n1-r7", "tamper-run", "tamper-manifest",
    "tamper-sbom", "tamper-provenance", "tamper-receipt", "browser-login",
    "model-api", "model-stream", "security-benign", "security-block",
    "security-audit", "portal-proxy-idp-chat",
]
matrix = {
    "expected_arch": "x86_64",
    "network_probe": "network-probe",
    "version_sequence": ["n1", "r7"],
    "image_ids": ["sha256:" + "a" * 64],
    "artifact": {
        "run_sha256": "b" * 64,
        "run_size": 1,
        "inner_tar_sha256": "c" * 64,
    },
    "release": {
        "source_revision": "d" * 40,
        "source_tree": "e" * 40,
        "image_provenance_sha256": "f" * 64,
        "sbom_index_sha256": "0" * 64,
    },
    "scenarios": [
        {
            "name": name,
            "command": "success-" + name,
            "migration_probe": "migration-" + name,
            "business_probe": "business-" + name,
        }
        for name in names
    ],
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(matrix, stream, separators=(",", ":"))
PY

# A formal release needs the exact schema_migrations ledgers observed around
# the real VM upgrade. They must be captured through QGA and included in the
# closed evidence index, not inferred from the source tree by home recovery.
baseline_evidence="$tmpdir/baseline-evidence"
baseline_state="$tmpdir/baseline-state"
baseline_log="$tmpdir/baseline.log"
mkdir -p "$baseline_state"
set +e
FAKE_QGA_STATE="$baseline_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$baseline_evidence" \
  --matrix "$success_matrix" \
  --home-migration-baseline-command migration-baseline-probe >"$baseline_log" 2>&1
baseline_exit=$?
set -e
[[ "$baseline_exit" -eq 89 ]] || {
  cat "$baseline_log" >&2
  printf 'runner did not capture a migration baseline before the formal boundary\n' >&2
  exit 1
}
python3 - "$baseline_evidence/evidence-index.json" "$baseline_evidence/home-migration-baseline.json" <<'PY'
import hashlib
import json
import pathlib
import sys

index_path, baseline_path = map(pathlib.Path, sys.argv[1:])
index = json.loads(index_path.read_text(encoding="utf-8"))
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
assert "home-migration-baseline.json" in {entry["path"] for entry in index["entries"]}
assert baseline["schema"] == "jjdguard-home-migration-baseline/v1"
assert [ledger["name"] for ledger in baseline["ledgers"]] == [
    "schema_migrations_before",
    "schema_migrations_after",
]
assert all(ledger["entries"] for ledger in baseline["ledgers"])
assert index_path.is_file()
assert hashlib.sha256(baseline_path.read_bytes()).hexdigest() in {
    entry["sha256"] for entry in index["entries"]
}
PY

success_state="$tmpdir/success-state"
success_evidence="$tmpdir/success-evidence"
formal_missing_log="$tmpdir/formal-missing.log"
mkdir -p "$success_state"
set +e
FAKE_QGA_STATE="$success_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$success_evidence" \
  --matrix "$success_matrix" \
  --home-migration-baseline-command migration-baseline-probe \
  --verify-formal \
  --receipt "$success_evidence/receipt.json" >"$formal_missing_log" 2>&1
success_exit=$?
set -e
[[ "$success_exit" -ne 0 ]] || { printf 'runner claimed a formal PASS without verifier inputs\n' >&2; exit 1; }
grep -F 'formal verification inputs are incomplete' "$formal_missing_log" >/dev/null || {
  cat "$formal_missing_log" >&2
  printf 'runner did not reject incomplete formal verification inputs\n' >&2
  exit 1
}
success_index="$success_evidence/evidence-index.json"
[[ -f "$success_index" ]] || { printf 'runner did not produce complete evidence index\n' >&2; exit 1; }
[[ ! -e "$success_evidence/receipt.json" ]] || { printf 'runner wrote a receipt without verifier inputs\n' >&2; exit 1; }
python3 - "$success_evidence" "$success_index" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
index = json.load(open(sys.argv[2], encoding="utf-8"))
assert index["schema"] == "jjdguard-acceptance-evidence-index/v1"
assert index["artifact"]["run_size"] == 1
assert len(index["entries"]) >= 112
paths = {entry["path"] for entry in index["entries"]}
assert "records/vm-lifecycle.json" in paths
assert "records/vm-metadata.json" in paths
assert "records/vm-postcheck.json" in paths
assert "records/model-stream.json" in paths
assert "logs/vm-metadata.log" in paths
assert "records/model-api.migration-probe.json" in paths
assert "logs/model-api.migration-probe.log" in paths
assert "records/model-api.business-probe.json" in paths
assert "logs/model-api.business-probe.log" in paths

lifecycle = json.load(open(root / "records" / "vm-lifecycle.json", encoding="utf-8"))
metadata = json.load(open(root / "records" / "vm-metadata.json", encoding="utf-8"))
postcheck = json.load(open(root / "records" / "vm-postcheck.json", encoding="utf-8"))
scenario = json.load(open(root / "records" / "model-api.json", encoding="utf-8"))
migration_probe = json.load(open(root / "records" / "model-api.migration-probe.json", encoding="utf-8"))
business_probe = json.load(open(root / "records" / "model-api.business-probe.json", encoding="utf-8"))
for record in (lifecycle, metadata, postcheck, scenario, migration_probe, business_probe):
    for key in ("started_at", "finished_at", "exit_code", "status", "log_sha256"):
        assert key in record
assert lifecycle["details"]["boot_id_before"] == "boot-a"
assert metadata["details"]["os"] == "PRETTY_NAME=Fixture OS"
for key in ("kernel", "arch", "vcpu", "ram_kib", "docker_before"):
    assert key in metadata["details"]
assert postcheck["details"]["docker_after"] == "27.0|27.0"
assert postcheck["details"]["version_sequence"] == "n1->r7"
assert postcheck["details"]["image_ids"] == "sha256:" + "a" * 64
assert scenario["details"]["migration_probe"] == "PASS"
assert scenario["details"]["business_probe"] == "PASS"
assert migration_probe["scenario"] == "model-api"
assert migration_probe["step"] == "migration-probe"
assert migration_probe["status"] == "PASS"
assert migration_probe["exit_code"] == 0
assert business_probe["scenario"] == "model-api"
assert business_probe["step"] == "business-probe"
assert business_probe["status"] == "PASS"
assert business_probe["exit_code"] == 0
PY

# The runner accepts a relative evidence root, but every recorder/indexer path
# must remain root-relative after it has been made absolute once. Otherwise a
# later verification turns "relative-evidence/records/..." into a nested
# "relative-evidence/relative-evidence/..." path.
relative_root_parent="$tmpdir/relative-root-parent"
relative_root_name="relative-evidence"
relative_state="$tmpdir/relative-root-state"
relative_log="$tmpdir/relative-root.log"
mkdir -p "$relative_root_parent" "$relative_state"
set +e
(
  cd "$relative_root_parent"
  FAKE_QGA_STATE="$relative_state" bash "$runner" \
    --virsh "$fixture_virsh" \
    --allow-live-vm \
    --domain fixture-vm \
    --evidence-root "$relative_root_name" \
    --matrix "$success_matrix"
) >"$relative_log" 2>&1
relative_exit=$?
set -e
[[ "$relative_exit" -ne 0 ]] || { printf 'relative-root fixture claimed a formal PASS\n' >&2; exit 1; }
relative_index="$relative_root_parent/$relative_root_name/evidence-index.json"
[[ -f "$relative_index" ]] || {
  cat "$relative_log" >&2
  printf 'runner did not index a relative evidence root\n' >&2
  exit 1
}
[[ ! -e "$relative_root_parent/$relative_root_name/$relative_root_name/evidence-index.json" ]] || {
  printf 'runner nested a relative evidence root inside itself\n' >&2
  exit 1
}

# A syntactically complete formal request still cannot promote fixture data.
# The runner must invoke the unmodified verifier and remove any provisional
# receipt when the real candidate input is invalid.
formal_invalid_evidence="$tmpdir/formal-invalid-evidence"
formal_invalid_state="$tmpdir/formal-invalid-state"
formal_invalid_artifact="$tmpdir/not-a-candidate.run"
formal_invalid_public_key="$tmpdir/not-a-release.pub"
formal_invalid_log="$tmpdir/formal-invalid.log"
mkdir -p "$formal_invalid_state"
printf '%s\n' 'not a signed candidate artifact' > "$formal_invalid_artifact"
printf '%s\n' 'not a release public key' > "$formal_invalid_public_key"

# A formal receipt is only useful for home recovery when it binds the actual
# before/after schema migration ledgers. Do not let an otherwise complete
# formal request reach the verifier without that evidence.
formal_baseline_missing_evidence="$tmpdir/formal-baseline-missing-evidence"
formal_baseline_missing_state="$tmpdir/formal-baseline-missing-state"
formal_baseline_missing_log="$tmpdir/formal-baseline-missing.log"
mkdir -p "$formal_baseline_missing_state"
set +e
FAKE_QGA_STATE="$formal_baseline_missing_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$formal_baseline_missing_evidence" \
  --matrix "$success_matrix" \
  --verify-formal \
  --artifact "$formal_invalid_artifact" \
  --public-key "$formal_invalid_public_key" \
  --source-repository "$repo_root" \
  --authoritative-remote 'https://invalid.example/jjdguard.git' \
  --receipt "$formal_baseline_missing_evidence/receipt.json" >"$formal_baseline_missing_log" 2>&1
formal_baseline_missing_exit=$?
set -e
[[ "$formal_baseline_missing_exit" -ne 0 ]] || { printf 'runner accepted a formal request without migration baseline evidence\n' >&2; exit 1; }
grep -F 'formal verification requires --home-migration-baseline-command' "$formal_baseline_missing_log" >/dev/null || {
  cat "$formal_baseline_missing_log" >&2
  printf 'runner did not reject missing migration baseline before formal verification\n' >&2
  exit 1
}
[[ ! -e "$formal_baseline_missing_evidence" ]] || {
  printf 'runner touched VM evidence before enforcing the migration baseline input\n' >&2
  exit 1
}
[[ ! -e "$formal_baseline_missing_evidence/receipt.json" ]] || {
  printf 'runner published a receipt without migration baseline evidence\n' >&2
  exit 1
}

set +e
FAKE_QGA_STATE="$formal_invalid_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$formal_invalid_evidence" \
  --matrix "$success_matrix" \
  --home-migration-baseline-command migration-baseline-probe \
  --verify-formal \
  --artifact "$formal_invalid_artifact" \
  --public-key "$formal_invalid_public_key" \
  --source-repository "$repo_root" \
  --authoritative-remote 'https://invalid.example/jjdguard.git' \
  --receipt "$formal_invalid_evidence/receipt.json" >"$formal_invalid_log" 2>&1
formal_invalid_exit=$?
set -e
[[ "$formal_invalid_exit" -ne 0 ]] || { printf 'runner promoted an invalid formal candidate\n' >&2; exit 1; }
grep -F 'formal verification failed' "$formal_invalid_log" >/dev/null || {
  cat "$formal_invalid_log" >&2
  printf 'runner did not report verifier failure\n' >&2
  exit 1
}
[[ ! -e "$formal_invalid_evidence/receipt.json" ]] || {
  printf 'runner retained a promotable receipt after verifier failure\n' >&2
  exit 1
}
python3 - "$formal_invalid_evidence/evidence-index.json" <<'PY'
import json
import sys

index = json.load(open(sys.argv[1], encoding="utf-8"))
scenarios = (
    "n1-install", "clean-install", "offline-reboot", "upgrade-n1-r7",
    "rollback-r7-n1", "reupgrade-n1-r7", "tamper-run", "tamper-manifest",
    "tamper-sbom", "tamper-provenance", "tamper-receipt", "browser-login",
    "model-api", "model-stream", "security-benign", "security-block",
    "security-audit", "portal-proxy-idp-chat",
)
record_ids = {"vm-lifecycle", "vm-metadata", "network", "vm-postcheck"}
for scenario in scenarios:
    record_ids.update((scenario, scenario + ".migration-probe", scenario + ".business-probe"))
expected_paths = {
    prefix + record_id + suffix
    for record_id in record_ids
    for prefix, suffix in (("records/", ".json"), ("logs/", ".log"))
}
expected_paths.add("home-migration-baseline.json")
paths = {entry["path"] for entry in index["entries"]}
assert len(paths) == 117
assert paths == expected_paths
for required in (
    "records/vm-lifecycle.json",
    "logs/vm-metadata.log",
    "records/model-api.migration-probe.json",
    "logs/model-api.business-probe.log",
):
    assert required in paths
PY

# The final receipt is published only after the existing verifier accepts a
# root-anchored temporary receipt. An invalid candidate must not even touch a
# pre-existing final path while the verifier is still pending.
formal_deferred_evidence="$tmpdir/formal-deferred-evidence"
formal_deferred_state="$tmpdir/formal-deferred-state"
formal_deferred_target="$tmpdir/formal-deferred-target.json"
formal_deferred_log="$tmpdir/formal-deferred.log"
mkdir -p "$formal_deferred_evidence" "$formal_deferred_state"
chmod 0700 "$formal_deferred_evidence"
printf '%s\n' 'outside-unchanged' > "$formal_deferred_target"
ln -s "$formal_deferred_target" "$formal_deferred_evidence/receipt.json"
set +e
FAKE_QGA_STATE="$formal_deferred_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$formal_deferred_evidence" \
  --matrix "$success_matrix" \
  --home-migration-baseline-command migration-baseline-probe \
  --verify-formal \
  --artifact "$formal_invalid_artifact" \
  --public-key "$formal_invalid_public_key" \
  --source-repository "$repo_root" \
  --authoritative-remote 'https://invalid.example/jjdguard.git' \
  --receipt "$formal_deferred_evidence/receipt.json" >"$formal_deferred_log" 2>&1
formal_deferred_exit=$?
set -e
[[ "$formal_deferred_exit" -ne 0 ]] || { printf 'runner promoted an invalid deferred candidate\n' >&2; exit 1; }
grep -F 'formal verification failed' "$formal_deferred_log" >/dev/null || {
  cat "$formal_deferred_log" >&2
  printf 'runner touched the final receipt before verifier failure\n' >&2
  exit 1
}
[[ "$(<"$formal_deferred_target")" == outside-unchanged ]] || {
  printf 'runner wrote through the final receipt symlink\n' >&2
  exit 1
}
[[ -L "$formal_deferred_evidence/receipt.json" ]] || {
  printf 'runner changed the final receipt path before verifier success\n' >&2
  exit 1
}
formal_deferred_stage=$(find "$formal_deferred_evidence/.formal-receipts" -type f -print -quit)
[[ -n "$formal_deferred_stage" ]] || {
  printf 'runner did not retain staged receipt after verifier failure\n' >&2
  exit 1
}
grep -F 'manual disposal' "$formal_deferred_log" >/dev/null || {
  cat "$formal_deferred_log" >&2
  printf 'runner did not identify retained staged receipt after verifier failure\n' >&2
  exit 1
}

# A verifier can return success just before an attacker replaces the staged
# path. The runner must publish only the bytes that were presented to the
# verifier, never whatever happens to be at that path afterwards. This
# wrapper is test-only: all non-verifier Python calls use the real interpreter
# and the production verifier file remains untouched.
formal_race_evidence="$tmpdir/formal-race-evidence"
formal_race_state="$tmpdir/formal-race-state"
formal_race_python="$tmpdir/formal-race-python"
formal_race_marker="$tmpdir/formal-race-marker"
formal_race_log="$tmpdir/formal-race.log"
mkdir -p "$formal_race_state" "$formal_race_python"
formal_race_real_python="$(command -v python3)"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'if [[ "${1:-}" == "$FORMAL_RACE_VERIFIER" ]]; then' \
  '  [[ "${2:-}" == "--receipt" ]] || exit 64' \
  '  stage=${3:?missing staged receipt}' \
  '  printf "%s\n" verifier-success > "$FORMAL_RACE_MARKER"' \
  '  replacement="$stage.replacement"' \
  '  printf "%s\n" swapped-after-verifier > "$replacement"' \
  '  chmod 600 "$replacement"' \
  '  mv -f -- "$replacement" "$stage"' \
  '  exit 0' \
  'fi' \
  'exec "$FORMAL_RACE_REAL_PYTHON" "$@"' > "$formal_race_python/python3"
chmod +x "$formal_race_python/python3"
set +e
PATH="$formal_race_python:$PATH" \
FORMAL_RACE_REAL_PYTHON="$formal_race_real_python" \
FORMAL_RACE_VERIFIER="$repo_root/deploy/acceptance/verify-acceptance-receipt.py" \
FORMAL_RACE_MARKER="$formal_race_marker" \
FAKE_QGA_STATE="$formal_race_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$formal_race_evidence" \
  --matrix "$success_matrix" \
  --home-migration-baseline-command migration-baseline-probe \
  --verify-formal \
  --artifact "$formal_invalid_artifact" \
  --public-key "$formal_invalid_public_key" \
  --source-repository "$repo_root" \
  --authoritative-remote 'https://invalid.example/jjdguard.git' \
  --receipt "$formal_race_evidence/receipt.json" >"$formal_race_log" 2>&1
formal_race_exit=$?
set -e
[[ -f "$formal_race_marker" ]] || { printf 'formal race did not reach simulated verifier success\n' >&2; exit 1; }
[[ "$formal_race_exit" -ne 0 ]] || { printf 'runner published a receipt replaced after verifier success\n' >&2; exit 1; }
grep -F 'cannot publish verified formal receipt' "$formal_race_log" >/dev/null || {
  cat "$formal_race_log" >&2
  printf 'runner did not reject staged receipt drift after verifier success\n' >&2
  exit 1
}
[[ ! -e "$formal_race_evidence/receipt.json" ]] || {
  printf 'runner retained a final receipt after staged receipt drift\n' >&2
  exit 1
}
formal_race_stage=$(find "$formal_race_evidence/.formal-receipts" -type f -print -quit)
[[ -n "$formal_race_stage" && "$(<"$formal_race_stage")" == swapped-after-verifier ]] || {
  printf 'runner did not retain the replaced staged receipt for manual disposal\n' >&2
  exit 1
}
grep -F 'manual disposal' "$formal_race_log" >/dev/null || {
  cat "$formal_race_log" >&2
  printf 'runner did not identify the retained formal race receipt\n' >&2
  exit 1
}

# A TERM can arrive after the publisher creates its no-overwrite hard link but
# before it can return. Pause the real publisher at that exact link with a
# test-only sitecustomize module, then interrupt both child and runner. No
# production code path is gated by this fixture.
formal_signal_evidence="$tmpdir/formal-signal-evidence"
formal_signal_state="$tmpdir/formal-signal-state"
formal_signal_python="$tmpdir/formal-signal-python"
formal_signal_marker="$tmpdir/formal-signal-marker"
formal_signal_log="$tmpdir/formal-signal.log"
mkdir -p "$formal_signal_evidence" "$formal_signal_state" "$formal_signal_python"
chmod 0700 "$formal_signal_evidence"
formal_signal_real_python="$(command -v python3)"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'if [[ "${1:-}" == "$FORMAL_SIGNAL_VERIFIER" ]]; then' \
  '  exit 0' \
  'fi' \
  'exec "$FORMAL_SIGNAL_REAL_PYTHON" "$@"' > "$formal_signal_python/python3"
printf '%s\n' \
  'import os' \
  'import pathlib' \
  'import signal' \
  '' \
  'marker = os.environ.get("FORMAL_SIGNAL_AFTER_LINK_MARKER")' \
  'if marker:' \
  '    original_link = os.link' \
  '' \
  '    def pause_after_link(*args, **kwargs):' \
  '        result = original_link(*args, **kwargs)' \
  '        if os.fspath(args[0]).startswith("/proc/self/fd/"):' \
  '            return result' \
  '        pathlib.Path(marker).write_text(str(os.getpid()), encoding="ascii")' \
  '        os.kill(os.getpid(), signal.SIGSTOP)' \
  '        return result' \
  '' \
  '    os.link = pause_after_link' > "$formal_signal_python/sitecustomize.py"
chmod +x "$formal_signal_python/python3"
PATH="$formal_signal_python:$PATH" \
PYTHONPATH="$formal_signal_python${PYTHONPATH:+:$PYTHONPATH}" \
FORMAL_SIGNAL_REAL_PYTHON="$formal_signal_real_python" \
FORMAL_SIGNAL_VERIFIER="$repo_root/deploy/acceptance/verify-acceptance-receipt.py" \
FORMAL_SIGNAL_AFTER_LINK_MARKER="$formal_signal_marker" \
FAKE_QGA_STATE="$formal_signal_state" bash "$runner" \
  --virsh "$fixture_virsh" \
  --allow-live-vm \
  --domain fixture-vm \
  --evidence-root "$formal_signal_evidence" \
  --matrix "$success_matrix" \
  --home-migration-baseline-command migration-baseline-probe \
  --verify-formal \
  --artifact "$formal_invalid_artifact" \
  --public-key "$formal_invalid_public_key" \
  --source-repository "$repo_root" \
  --authoritative-remote 'https://invalid.example/jjdguard.git' \
  --receipt "$formal_signal_evidence/receipt.json" >"$formal_signal_log" 2>&1 &
formal_signal_runner=$!
formal_signal_publisher=
for _ in $(seq 1 1800); do
  if [[ -s "$formal_signal_marker" ]]; then
    formal_signal_publisher="$(<"$formal_signal_marker")"
    break
  fi
  if ! kill -0 "$formal_signal_runner" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if [[ ! "$formal_signal_publisher" =~ ^[1-9][0-9]*$ ]]; then
  kill -TERM "$formal_signal_runner" >/dev/null 2>&1 || true
  wait "$formal_signal_runner" >/dev/null 2>&1 || true
  cat "$formal_signal_log" >&2
  printf 'signal fixture did not pause after the formal receipt link\n' >&2
  exit 1
fi
kill -TERM "$formal_signal_publisher" >/dev/null 2>&1 || true
kill -TERM "$formal_signal_runner" >/dev/null 2>&1 || true
kill -CONT "$formal_signal_publisher" >/dev/null 2>&1 || true
set +e
wait "$formal_signal_runner"
formal_signal_exit=$?
set -e
[[ "$formal_signal_exit" -ne 0 ]] || { printf 'runner ignored TERM during formal publication\n' >&2; exit 1; }
[[ -f "$formal_signal_evidence/receipt.json" ]] || {
  printf 'runner did not retain a final receipt after interrupted formal publication\n' >&2
  exit 1
}
formal_signal_stage=$(find "$formal_signal_evidence/.formal-receipts" -type f -print -quit)
[[ -n "$formal_signal_stage" ]] || {
  printf 'runner did not retain staged evidence after interrupted formal publication\n' >&2
  exit 1
}
python3 - "$formal_signal_stage" "$formal_signal_evidence/receipt.json" <<'PY'
import pathlib
import sys

staged, published = map(pathlib.Path, sys.argv[1:])
staged_metadata = staged.stat()
published_metadata = published.stat()
assert (staged_metadata.st_dev, staged_metadata.st_ino) == (published_metadata.st_dev, published_metadata.st_ino)
PY
grep -F 'manual disposal' "$formal_signal_log" >/dev/null || {
  cat "$formal_signal_log" >&2
  printf 'runner did not identify retained interrupted formal receipt paths\n' >&2
  exit 1
}

# Loopback-only OpenAI fixture. This test deliberately uses a distinct prompt
# sentinel and checks both HTTP bodies and the fixture audit log never retain
# it. The server file is absent for this red run.
upstream="$repo_root/deploy/acceptance/local-openai-upstream.py"
upstream_port=$(python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)
upstream_audit="$tmpdir/upstream-audit.jsonl"
upstream_log="$tmpdir/upstream.log"
python3 "$upstream" \
  --host 127.0.0.1 \
  --port "$upstream_port" \
  --audit-log "$upstream_audit" >"$upstream_log" 2>&1 &
upstream_pid=$!
upstream_ready=false
for _ in $(seq 1 20); do
  if python3 - "$upstream_port" <<'PY'
import sys
import urllib.request

try:
    urllib.request.urlopen("http://127.0.0.1:" + sys.argv[1] + "/v1/models", timeout=0.2)
except Exception:
    raise SystemExit(1)
PY
  then
    upstream_ready=true
    break
  fi
  sleep 0.1
done
[[ "$upstream_ready" == true ]] || { cat "$upstream_log" >&2; printf 'loopback fixture did not start\n' >&2; exit 1; }

python3 - "$upstream_port" "$upstream_audit" "$upstream_log" <<'PY'
import http.client
import json
import pathlib
import sys
import urllib.error
import urllib.request

port, audit_path, log_path = sys.argv[1:]
base = "http://127.0.0.1:" + port
sentinel = "prompt-never-store-6d3c"

def request(path, payload=None, method=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    return urllib.request.urlopen(req, timeout=2)

with request("/v1/models") as response:
    models = json.load(response)
assert models["object"] == "list"
assert models["data"][0]["id"] == "offline-fixture"

payload = {"model": "offline-fixture", "messages": [{"role": "user", "content": sentinel}]}
with request("/v1/chat/completions", payload) as response:
    body = response.read().decode("utf-8")
    completion = json.loads(body)
assert completion["object"] == "chat.completion"
assert completion["choices"][0]["message"]["content"] == "offline fixture response"
assert sentinel not in body

stream_payload = {**payload, "stream": True}
with request("/v1/chat/completions", stream_payload) as response:
    stream = response.read().decode("utf-8")
    assert response.headers["Content-Type"].startswith("text/event-stream")
assert "chat.completion.chunk" in stream
assert "data: [DONE]" in stream
assert sentinel not in stream

for path, payload, method, expected in (
    ("/not-allowed", None, "GET", 404),
    ("/v1/models", {}, "POST", 405),
    ("/v1/chat/completions", {"model": "offline-fixture", "messages": [{"role": "user", "content": "x" * 70000}]}, "POST", 413),
):
    try:
        request(path, payload, method)
    except urllib.error.HTTPError as error:
        assert error.code == expected, (path, error.code)
    else:
        raise AssertionError("expected HTTP error for " + path)

query_sentinels = ("query-token-never-store", "query-cookie-never-store")
for path in (
    "/v1/models?token=" + query_sentinels[0],
    "/not-allowed?cookie=" + query_sentinels[1],
):
    try:
        request(path, None, "GET")
    except urllib.error.HTTPError as error:
        assert error.code == 404, (path, error.code)
    else:
        raise AssertionError("query path was accepted")

audit = pathlib.Path(audit_path).read_text(encoding="utf-8")
log = pathlib.Path(log_path).read_text(encoding="utf-8")
assert sentinel not in audit
assert sentinel not in log
assert "content" not in audit
for value in query_sentinels:
    assert value not in audit
    assert value not in log

# Replacing an active audit sink must make a successful request fail before
# headers, never write through the replacement, and never return 2xx.
outside = pathlib.Path(audit_path).with_name("outside-audit.jsonl")
outside.write_text("outside-unchanged\n", encoding="utf-8")
pathlib.Path(audit_path).unlink()
pathlib.Path(audit_path).symlink_to(outside)
try:
    request("/v1/models")
except (urllib.error.HTTPError, urllib.error.URLError, http.client.RemoteDisconnected):
    pass
else:
    raise AssertionError("audit replacement still received a 2xx response")
assert outside.read_text(encoding="utf-8") == "outside-unchanged\n"
PY

kill "$upstream_pid" >/dev/null 2>&1 || true
wait "$upstream_pid" >/dev/null 2>&1 || true
upstream_pid=

# The audit parent must be opened component-by-component. A symlink in the
# middle of the configured parent hierarchy is not an acceptable audit sink.
audit_base="$tmpdir/audit-base"
audit_external="$tmpdir/audit-external"
mkdir -p "$audit_base" "$audit_external/nested"
ln -s "$audit_external" "$audit_base/middle"
bad_upstream_port=$(python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)
bad_upstream_log="$tmpdir/bad-upstream.log"
python3 "$upstream" \
  --host 127.0.0.1 \
  --port "$bad_upstream_port" \
  --audit-log "$audit_base/middle/nested/audit.jsonl" >"$bad_upstream_log" 2>&1 &
bad_upstream_pid=$!
sleep 0.3
if kill -0 "$bad_upstream_pid" >/dev/null 2>&1; then
  printf 'upstream accepted an audit path with an intermediate symlink\n' >&2
  exit 1
fi
wait "$bad_upstream_pid" >/dev/null 2>&1 || true
bad_upstream_pid=
[[ ! -e "$audit_external/nested/audit.jsonl" ]] || { printf 'upstream wrote through an intermediate audit symlink\n' >&2; exit 1; }
