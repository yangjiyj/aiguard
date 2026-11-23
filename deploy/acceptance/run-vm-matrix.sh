#!/usr/bin/env bash
set -euo pipefail

# This runner intentionally accepts a virsh binary path so its VM/QGA boundary
# can be exercised with a local fake. It never shells out to a scenario on the
# host: scenario commands are sent only through QEMU Guest Agent.

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
record_step="$script_dir/record-step.py"
evidence_indexer="$script_dir/evidence-index.py"
receipt_verifier="$script_dir/verify-acceptance-receipt.py"
baseline_capture="$script_dir/capture-home-migration-baseline.py"
virsh_bin=virsh
domain=
evidence_root=
matrix=
qga_attempts=30
allow_live_vm=false
verify_formal=false
formal_artifact=
formal_public_key=
formal_source_repository=
formal_authoritative_remote=
formal_receipt=
home_migration_baseline_command=
formal_stage=
formal_stage_active=false
formal_publish_active=false
formal_stage_sha256=

readonly MAX_QGA_OUTPUT_BYTES=$((1024 * 1024))
readonly MAX_QGA_ARCHITECTURE_BYTES=128
readonly MAX_QGA_CONTROL_RESPONSE_BYTES=$((16 * 1024))
readonly MAX_QGA_STATUS_OVERHEAD_BYTES=$((8 * 1024))
readonly MAX_QGA_COMMAND_SECONDS=5

declare -A record_logs=()
qga_exit_code=255
qga_output=
qga_output_base64=
qga_limit_exceeded=false

usage() {
  printf '%s\n' 'usage: run-vm-matrix.sh --domain NAME --evidence-root DIR --matrix FILE [--virsh PATH] [--qga-attempts N] [--allow-live-vm] [--home-migration-baseline-command COMMAND] [--verify-formal --artifact RUN --public-key PUB --source-repository DIR --authoritative-remote URL --receipt PATH (requires --home-migration-baseline-command)]' >&2
}

fail() {
  printf '[error] VM matrix rejected: %s\n' "$1" >&2
  exit 2
}

cleanup_formal_stage() {
  local exit_status=$?
  local cleanup_status=0
  if [[ "$formal_stage_active" == true && -n "$formal_stage" && -n "$evidence_root" ]]; then
    formal_stage_active=false
    if [[ "$formal_publish_active" == true && -n "$formal_stage_sha256" && -n "$formal_receipt" ]]; then
      if python3 "$evidence_indexer" \
        --evidence-root "$evidence_root" \
        --discard-interrupted-formal-receipt "$formal_stage" \
        --expected-staged-sha256 "$formal_stage_sha256" \
        --receipt "$formal_receipt" >/dev/null; then
        :
      else
        cleanup_status=$?
        printf '[error] VM matrix retained formal receipt paths for manual disposal: staged=%q final=%q\n' \
          "$evidence_root/$formal_stage" "$formal_receipt" >&2
      fi
    else
      if python3 "$evidence_indexer" \
        --evidence-root "$evidence_root" \
        --discard-formal-receipt "$formal_stage" >/dev/null; then
        :
      else
        cleanup_status=$?
        printf '[error] VM matrix retained staged formal receipt for manual disposal: staged=%q\n' \
          "$evidence_root/$formal_stage" >&2
      fi
    fi
  fi
  if [[ "$exit_status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    return "$cleanup_status"
  fi
  return "$exit_status"
}

trap cleanup_formal_stage EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --virsh)
      [[ $# -ge 2 ]] || fail '--virsh requires a value'
      virsh_bin=$2
      shift 2
      ;;
    --domain)
      [[ $# -ge 2 ]] || fail '--domain requires a value'
      domain=$2
      shift 2
      ;;
    --evidence-root)
      [[ $# -ge 2 ]] || fail '--evidence-root requires a value'
      evidence_root=$2
      shift 2
      ;;
    --matrix)
      [[ $# -ge 2 ]] || fail '--matrix requires a value'
      matrix=$2
      shift 2
      ;;
    --qga-attempts)
      [[ $# -ge 2 ]] || fail '--qga-attempts requires a value'
      qga_attempts=$2
      shift 2
      ;;
    --allow-live-vm)
      allow_live_vm=true
      shift
      ;;
    --verify-formal)
      verify_formal=true
      shift
      ;;
    --artifact)
      [[ $# -ge 2 ]] || fail '--artifact requires a value'
      formal_artifact=$2
      shift 2
      ;;
    --public-key)
      [[ $# -ge 2 ]] || fail '--public-key requires a value'
      formal_public_key=$2
      shift 2
      ;;
    --source-repository)
      [[ $# -ge 2 ]] || fail '--source-repository requires a value'
      formal_source_repository=$2
      shift 2
      ;;
    --authoritative-remote)
      [[ $# -ge 2 ]] || fail '--authoritative-remote requires a value'
      formal_authoritative_remote=$2
      shift 2
      ;;
    --receipt)
      [[ $# -ge 2 ]] || fail '--receipt requires a value'
      formal_receipt=$2
      shift 2
      ;;
    --home-migration-baseline-command)
      [[ $# -ge 2 ]] || fail '--home-migration-baseline-command requires a value'
      home_migration_baseline_command=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$domain" && -n "$evidence_root" && -n "$matrix" ]] || { usage; exit 2; }
[[ "$qga_attempts" =~ ^[1-9][0-9]*$ ]] || fail '--qga-attempts must be a positive integer'
[[ -x "$virsh_bin" || "$virsh_bin" != */* ]] || fail 'virsh binary is unavailable'
[[ -f "$record_step" ]] || fail 'record-step.py is unavailable'
[[ -f "$evidence_indexer" ]] || fail 'evidence-index.py is unavailable'
[[ -f "$receipt_verifier" ]] || fail 'verify-acceptance-receipt.py is unavailable'
[[ -f "$baseline_capture" ]] || fail 'capture-home-migration-baseline.py is unavailable'
if [[ -n "$home_migration_baseline_command" ]]; then
  [[ ${#home_migration_baseline_command} -le 1024 ]] || fail 'home migration baseline command is too long'
  # Bash variables cannot retain NUL bytes. Reject the control characters that
  # can actually reach QGA instead of treating every non-empty command as NUL.
  [[ "$home_migration_baseline_command" != *$'\n'* && "$home_migration_baseline_command" != *$'\r'* ]] || fail 'home migration baseline command is unsafe'
fi
if [[ "$verify_formal" != true ]] && [[ -n "$formal_artifact$formal_public_key$formal_source_repository$formal_authoritative_remote$formal_receipt" ]]; then
  fail 'formal verification arguments require --verify-formal'
fi
if [[ "$verify_formal" == true && -z "$home_migration_baseline_command" ]]; then
  fail 'formal verification requires --home-migration-baseline-command'
fi
[[ "$allow_live_vm" == true ]] || fail 'live VM execution requires --allow-live-vm'

evidence_root=$(python3 - "$evidence_root" <<'PY'
import os
import pathlib
import stat
import sys

if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    raise SystemExit(2)
root = pathlib.Path(sys.argv[1])
if not root.is_absolute():
    root = pathlib.Path.cwd() / root
parts = root.parts
if not parts or parts[0] != os.sep:
    raise SystemExit(2)
components = parts[1:]
if any(part in {"", ".", ".."} for part in components):
    raise SystemExit(2)
directory_fd = None
try:
    directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    for component in components:
        try:
            os.mkdir(component, 0o700, dir_fd=directory_fd)
        except FileExistsError:
            pass
        next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
        os.close(directory_fd)
        directory_fd = next_fd
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            raise SystemExit(2)
except OSError:
    raise SystemExit(2)
finally:
    if directory_fd is not None:
        os.close(directory_fd)
print(os.path.join(os.sep, *components))
PY
) || fail 'cannot canonicalize evidence root'

create_log() {
  local name=$1
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || return 1
  local path="logs/$name.log"
  python3 "$record_step" --evidence-root "$evidence_root" --create-log "$path" >/dev/null || return 1
  printf '%s' "$path"
}

append_log() {
  local path=$1
  local event=$2
  python3 "$record_step" --evidence-root "$evidence_root" --append-log "$path" --event "$event" >/dev/null
}

formal_inputs_ready() {
  [[ "$verify_formal" == true ]] || return 1
  [[ -n "$formal_artifact" && -f "$formal_artifact" && ! -L "$formal_artifact" ]] || return 1
  [[ -n "$formal_public_key" && -f "$formal_public_key" && ! -L "$formal_public_key" ]] || return 1
  [[ -n "$formal_source_repository" && -d "$formal_source_repository" && ! -L "$formal_source_repository" ]] || return 1
  [[ -n "$formal_authoritative_remote" && ${#formal_authoritative_remote} -le 1024 && "$formal_authoritative_remote" != *$'\n'* && "$formal_authoritative_remote" != *$'\r'* ]] || return 1
  [[ -n "$formal_receipt" ]] || return 1
}

new_formal_stage() {
  python3 - <<'PY'
import secrets

print(".formal-receipts/receipt-" + secrets.token_hex(16) + ".json")
PY
}

details_json() {
  python3 - "$@" <<'PY'
import json
import re
import sys

items = sys.argv[1:]
if len(items) % 2:
    raise SystemExit(2)
result = {}
for key, value in zip(items[::2], items[1::2]):
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", key) is None:
        raise SystemExit(2)
    if len(value) > 1024 or any(ord(character) < 32 and character not in "\t" for character in value):
        raise SystemExit(2)
    result[key] = value
print(json.dumps(result, separators=(",", ":")))
PY
}

write_record_as() {
  local record_id=$1
  local scenario=$2
  local step=$3
  local status=$4
  local exit_code=$5
  local log_path=$6
  local details=$7
  local started_at=$8
  local finished_at=$9
  if [[ "$status" == PASS && "$exit_code" -ne 0 ]]; then
    return 1
  fi
  if [[ "$status" == FAIL && "$exit_code" -eq 0 ]]; then
    return 1
  fi
  python3 "$record_step" \
    --evidence-root "$evidence_root" \
    --output "records/$record_id.json" \
    --scenario "$scenario" \
    --step "$step" \
    --status "$status" \
    --exit-code "$exit_code" \
    --started-at "$started_at" \
    --finished-at "$finished_at" \
    --log "$log_path" \
    --details-json "$details" >/dev/null || return 1
  record_logs["$record_id"]=$log_path
}

write_record() {
  local scenario=$1
  shift
  write_record_as "$scenario" "$scenario" "$@"
}

write_failure_as() {
  local record_id=$1
  local scenario=$2
  local step=$3
  local exit_code=$4
  local log_path=$5
  local started_at=$6
  local finished_at=$7
  shift 7
  local details
  details=$(details_json reason "$1" "${@:2}") || return 1
  write_record_as "$record_id" "$scenario" "$step" FAIL "$exit_code" "$log_path" "$details" "$started_at" "$finished_at"
}

write_failure() {
  local scenario=$1
  shift
  write_failure_as "$scenario" "$scenario" "$@"
}

write_qga_limit_failure() {
  local scenario=$1
  local step=$2
  local log_path=$3
  local started_at=$4
  local finished_at=$5
  [[ "$qga_limit_exceeded" == true ]] || return 1
  write_failure "$scenario" "$step" 76 "$log_path" "$started_at" "$finished_at" qga_limit_exceeded ||
    fail 'cannot record QGA limit failure'
}

write_qga_limit_failure_as() {
  local record_id=$1
  local scenario=$2
  local step=$3
  local log_path=$4
  local started_at=$5
  local finished_at=$6
  [[ "$qga_limit_exceeded" == true ]] || return 1
  write_failure_as "$record_id" "$scenario" "$step" 76 "$log_path" "$started_at" "$finished_at" qga_limit_exceeded ||
    fail 'cannot record QGA limit failure'
}

trim_line_endings() {
  local value=$1
  value=${value//$'\r'/}
  value=${value//$'\n'/}
  printf '%s' "$value"
}

normalize_qga_architecture() {
  python3 - "$1" <<'PY'
import base64
import re
import sys

try:
    raw = base64.b64decode(sys.argv[1], validate=True)
except (ValueError, TypeError):
    raise SystemExit(2)
if b"\x00" in raw:
    raise SystemExit(2)
if raw.endswith(b"\n"):
    raw = raw[:-1]
if raw.endswith(b"\r"):
    raw = raw[:-1]
if b"\r" in raw or b"\n" in raw:
    raise SystemExit(2)
try:
    value = raw.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(2)
if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value) is None:
    raise SystemExit(2)
print(value)
PY
}

qga_transport_response() {
  local request=$1
  local response_limit=$2
  python3 - "$virsh_bin" "$domain" "$request" "$response_limit" "$MAX_QGA_COMMAND_SECONDS" <<'PY'
import os
import select
import signal
import subprocess
import sys
import time

virsh, domain, request, limit_raw, timeout_raw = sys.argv[1:]
limit = int(limit_raw)
timeout_seconds = float(timeout_raw)

try:
    process = subprocess.Popen(
        [virsh, "qemu-agent-command", domain, request],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
except OSError:
    raise SystemExit(2)

def process_group_exists():
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

def wait_for_process_group(deadline):
    while process_group_exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    return not process_group_exists()

def stop_process():
    # A forked virsh worker can outlive its Popen parent while retaining stdout.
    if process_group_exists():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if not wait_for_process_group(time.monotonic() + 1) and process_group_exists():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            wait_for_process_group(time.monotonic() + 1)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass

deadline = time.monotonic() + timeout_seconds
chunks = []
total = 0
try:
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        readable, _, _ = select.select([descriptor], [], [], remaining)
        if not readable:
            raise TimeoutError
        chunk = os.read(descriptor, min(65536, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            stop_process()
            sys.stdout.write("OVERSIZE")
            raise SystemExit(3)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    process.wait(timeout=remaining)
    if process.returncode != 0:
        raise SystemExit(2)
    sys.stdout.buffer.write(b"".join(chunks))
except (OSError, TimeoutError, subprocess.TimeoutExpired):
    stop_process()
    raise SystemExit(2)
finally:
    stop_process()
PY
}

qga_exec() {
  local command=$1
  local log_path=$2
  local output_mode=${3:-text}
  local request pid pid_response status_request status_line status_response transport_status encoded attempt output_limit status_response_limit
  qga_exit_code=255
  qga_output=
  qga_output_base64=
  qga_limit_exceeded=false
  case "$output_mode" in
    text|base64)
      output_limit=$MAX_QGA_OUTPUT_BYTES
      ;;
    architecture)
      output_limit=$MAX_QGA_ARCHITECTURE_BYTES
      ;;
    *) append_log "$log_path" qga_output_mode_invalid; return 255 ;;
  esac
  status_response_limit=$(( ((output_limit + 2) / 3) * 4 + MAX_QGA_STATUS_OVERHEAD_BYTES ))
  request=$(python3 - "$command" <<'PY'
import json
import sys

print(json.dumps({
    "execute": "guest-exec",
    "arguments": {
        "path": "/bin/sh",
        "arg": ["-lc", sys.argv[1]],
        "capture-output": True,
    },
}, separators=(",", ":")))
PY
) || { append_log "$log_path" qga_request_invalid; return 255; }
  if pid_response=$(qga_transport_response "$request" "$MAX_QGA_CONTROL_RESPONSE_BYTES"); then
    if ! pid=$(printf '%s' "$pid_response" | python3 -c '
import json
import sys

try:
    value = json.loads(sys.stdin.buffer.read())["return"]["pid"]
except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit(2)
if not isinstance(value, int) or isinstance(value, bool) or value < 1:
    raise SystemExit(2)
print(value)
 '); then
      append_log "$log_path" qga_pid_invalid
      return 255
    fi
  else
    transport_status=$?
    if [[ "$transport_status" -eq 3 && "$pid_response" == OVERSIZE ]]; then
      append_log "$log_path" qga_limit_exceeded
      qga_limit_exceeded=true
      return 255
    fi
    append_log "$log_path" qga_pid_invalid
    return 255
  fi
  status_request=$(python3 - "$pid" <<'PY'
import json
import sys
print(json.dumps({"execute": "guest-exec-status", "arguments": {"pid": int(sys.argv[1])}}, separators=(",", ":")))
PY
) || { append_log "$log_path" qga_status_request_invalid; return 255; }
  for ((attempt = 1; attempt <= qga_attempts; attempt++)); do
    if status_response=$(qga_transport_response "$status_request" "$status_response_limit"); then
      if ! status_line=$(printf '%s' "$status_response" | python3 -c '
import base64
import json
import sys

output_limit = int(sys.argv[1])
try:
    result = json.loads(sys.stdin.buffer.read())["return"]
    if result.get("exited") is False:
        print("PENDING")
        raise SystemExit(0)
    if result.get("exited") is not True:
        raise RuntimeError("invalid exited state")
    exit_code = result.get("exitcode")
    raw = result.get("out-data", "")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or not 0 <= exit_code <= 255:
        raise RuntimeError("invalid exit code")
    if not isinstance(raw, str):
        raise RuntimeError("invalid output")
    if len(raw) > ((output_limit + 2) // 3) * 4:
        print("OVERSIZE")
        raise SystemExit(0)
    decoded = base64.b64decode(raw, validate=True)
    if len(decoded) > output_limit:
        print("OVERSIZE")
        raise SystemExit(0)
    print("EXIT:%d:%s" % (exit_code, raw))
except (KeyError, TypeError, ValueError, RuntimeError, json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit(2)
 ' "$output_limit"); then
        append_log "$log_path" qga_status_invalid
        return 255
      fi
    else
      transport_status=$?
      if [[ "$transport_status" -eq 3 && "$status_response" == OVERSIZE ]]; then
        append_log "$log_path" qga_limit_exceeded
        qga_limit_exceeded=true
        return 255
      fi
      append_log "$log_path" qga_status_invalid
      return 255
    fi
    if [[ "$status_line" == PENDING ]]; then
      sleep 1
      continue
    fi
    if [[ "$status_line" == OVERSIZE ]]; then
      append_log "$log_path" qga_limit_exceeded
      qga_limit_exceeded=true
      return 255
    fi
    if [[ ! "$status_line" =~ ^EXIT:([0-9]{1,3}):(.*)$ ]]; then
      append_log "$log_path" qga_status_invalid
      return 255
    fi
    qga_exit_code=${BASH_REMATCH[1]}
    encoded=${BASH_REMATCH[2]}
    # Bash strings cannot retain NUL. Keep the validated QGA bytes encoded so
    # architecture validation can inspect the original byte sequence.
    qga_output_base64=$encoded
    if [[ "$output_mode" == base64 || "$output_mode" == architecture ]]; then
      return "$qga_exit_code"
    fi
    if ! qga_output=$(python3 - "$encoded" <<'PY'
import base64
import sys
try:
    sys.stdout.buffer.write(base64.b64decode(sys.argv[1], validate=True))
except (ValueError, TypeError):
    raise SystemExit(2)
PY
); then
      append_log "$log_path" qga_output_invalid
      return 255
    fi
    return "$qga_exit_code"
  done
  append_log "$log_path" qga_status_timeout
  return 255
}

matrix_json=$(python3 - "$matrix" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

MAX_MATRIX_BYTES = 1024 * 1024

if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    raise SystemExit(2)
path = pathlib.Path(sys.argv[1])
if not path.is_absolute():
    path = pathlib.Path.cwd() / path
parts = path.parts
if not parts or parts[0] != os.sep:
    raise SystemExit(2)
components = parts[1:]
if not components or any(part in {"", ".", ".."} for part in components):
    raise SystemExit(2)
directory_fd = None
matrix_fd = None
try:
    directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    for component in components[:-1]:
        next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
        os.close(directory_fd)
        directory_fd = next_fd
    matrix_fd = os.open(components[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory_fd)
    metadata = os.fstat(matrix_fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 0 or metadata.st_size > MAX_MATRIX_BYTES:
        raise SystemExit(2)
    raw = os.read(matrix_fd, MAX_MATRIX_BYTES + 1)
    finished = os.fstat(matrix_fd)
    if len(raw) != metadata.st_size or (finished.st_dev, finished.st_ino) != (metadata.st_dev, metadata.st_ino) or finished.st_size != metadata.st_size:
        raise SystemExit(2)
except OSError:
    raise SystemExit(2)
finally:
    if matrix_fd is not None:
        os.close(matrix_fd)
    if directory_fd is not None:
        os.close(directory_fd)
try:
    value = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(2)
if not isinstance(value, dict):
    raise SystemExit(2)
allowed = {"expected_arch", "network_probe", "scenarios", "version_sequence", "image_ids", "artifact", "release"}
if not set(value).issubset(allowed):
    raise SystemExit(2)
arch = value.get("expected_arch")
if not isinstance(arch, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,64}", arch) is None:
    raise SystemExit(2)
network = value.get("network_probe", "curl -fsS --connect-timeout 5 https://example.com/")
if not isinstance(network, str) or not network or len(network) > 1024 or "\x00" in network or "\n" in network or "\r" in network:
    raise SystemExit(2)
scenarios = value.get("scenarios", [])
if not isinstance(scenarios, list) or len(scenarios) > 128:
    raise SystemExit(2)
names = set()
for item in scenarios:
    if not isinstance(item, dict) or not {"name", "command"}.issubset(item) or not set(item).issubset({"name", "command", "migration_probe", "business_probe"}):
        raise SystemExit(2)
    name, command = item["name"], item["command"]
    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is None or name in names:
        raise SystemExit(2)
    if not isinstance(command, str) or not command or len(command) > 1024 or "\x00" in command or "\n" in command or "\r" in command:
        raise SystemExit(2)
    for probe in ("migration_probe", "business_probe"):
        if probe in item and (not isinstance(item[probe], str) or not item[probe] or len(item[probe]) > 1024 or "\x00" in item[probe] or "\n" in item[probe] or "\r" in item[probe]):
            raise SystemExit(2)
    names.add(name)
versions = value.get("version_sequence", [])
if not isinstance(versions, list) or len(versions) > 32 or any(not isinstance(item, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,64}", item) is None for item in versions):
    raise SystemExit(2)
image_ids = value.get("image_ids", [])
if not isinstance(image_ids, list) or len(image_ids) > 128 or any(not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in image_ids):
    raise SystemExit(2)
artifact = value.get("artifact")
if artifact is not None:
    if not isinstance(artifact, dict) or set(artifact) != {"run_sha256", "run_size", "inner_tar_sha256"}:
        raise SystemExit(2)
    if not isinstance(artifact["run_size"], int) or isinstance(artifact["run_size"], bool) or artifact["run_size"] < 1:
        raise SystemExit(2)
    if any(not isinstance(artifact[key], str) or re.fullmatch(r"[0-9a-f]{64}", artifact[key]) is None for key in ("run_sha256", "inner_tar_sha256")):
        raise SystemExit(2)
release = value.get("release")
if release is not None:
    if not isinstance(release, dict) or set(release) != {"source_revision", "source_tree", "image_provenance_sha256", "sbom_index_sha256"}:
        raise SystemExit(2)
    if any(not isinstance(release[key], str) or re.fullmatch(r"[0-9a-f]{40}", release[key]) is None for key in ("source_revision", "source_tree")):
        raise SystemExit(2)
    if any(not isinstance(release[key], str) or re.fullmatch(r"[0-9a-f]{64}", release[key]) is None for key in ("image_provenance_sha256", "sbom_index_sha256")):
        raise SystemExit(2)
print(json.dumps({"expected_arch": arch, "network_probe": network, "scenarios": scenarios, "version_sequence": versions, "image_ids": image_ids, "artifact": artifact, "release": release}, separators=(",", ":")))
PY
) || fail 'matrix is invalid'

expected_arch=$(printf '%s' "$matrix_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["expected_arch"])') || fail 'matrix architecture is invalid'
network_probe=$(printf '%s' "$matrix_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["network_probe"])') || fail 'matrix network probe is invalid'
version_sequence=$(printf '%s' "$matrix_json" | python3 -c 'import json,sys; print("->".join(json.load(sys.stdin)["version_sequence"]))') || fail 'matrix versions are invalid'
image_ids=$(printf '%s' "$matrix_json" | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)["image_ids"]))') || fail 'matrix image IDs are invalid'
artifact_json=$(printf '%s' "$matrix_json" | python3 -c 'import json,sys; value=json.load(sys.stdin)["artifact"]; print(json.dumps(value,separators=(",",":")) if value is not None else "")') || fail 'matrix artifact is invalid'
release_json=$(printf '%s' "$matrix_json" | python3 -c 'import json,sys; value=json.load(sys.stdin)["release"]; print(json.dumps(value,separators=(",",":")) if value is not None else "")') || fail 'matrix release is invalid'
mapfile -t scenario_lines < <(printf '%s' "$matrix_json" | python3 -c '
import base64
import json
import sys
for item in json.load(sys.stdin)["scenarios"]:
    print("\t".join((
        item["name"],
        base64.b64encode(item["command"].encode("utf-8")).decode("ascii"),
        base64.b64encode(item.get("migration_probe", "").encode("utf-8")).decode("ascii"),
        base64.b64encode(item.get("business_probe", "").encode("utf-8")).decode("ascii"),
    )))
')

lifecycle_log=$(create_log vm-lifecycle) || fail 'cannot create VM lifecycle log'
lifecycle_started=$(now_utc)
if ! qga_exec 'cat /proc/sys/kernel/random/boot_id' "$lifecycle_log"; then
  lifecycle_finished=$(now_utc)
  if write_qga_limit_failure vm-lifecycle read-boot-id "$lifecycle_log" "$lifecycle_started" "$lifecycle_finished"; then
    exit 76
  fi
  write_failure vm-lifecycle read-boot-id 70 "$lifecycle_log" "$lifecycle_started" "$lifecycle_finished" qga_boot_id_unavailable || fail 'cannot record QGA boot-ID failure'
  exit 70
fi
boot_before=$(trim_line_endings "$qga_output")
if [[ -z "$boot_before" ]]; then
  lifecycle_finished=$(now_utc)
  write_failure vm-lifecycle read-boot-id 70 "$lifecycle_log" "$lifecycle_started" "$lifecycle_finished" qga_boot_id_empty || fail 'cannot record empty boot-ID failure'
  exit 70
fi
if ! "$virsh_bin" reboot "$domain" >/dev/null 2>&1; then
  append_log "$lifecycle_log" reboot_failed
  lifecycle_finished=$(now_utc)
  write_failure vm-lifecycle reboot 71 "$lifecycle_log" "$lifecycle_started" "$lifecycle_finished" reboot_command_failed || fail 'cannot record reboot failure'
  exit 71
fi
if ! qga_exec 'cat /proc/sys/kernel/random/boot_id' "$lifecycle_log"; then
  lifecycle_finished=$(now_utc)
  if write_qga_limit_failure vm-lifecycle read-boot-id-after-reboot "$lifecycle_log" "$lifecycle_started" "$lifecycle_finished"; then
    exit 76
  fi
  write_failure vm-lifecycle read-boot-id-after-reboot 72 "$lifecycle_log" "$lifecycle_started" "$lifecycle_finished" qga_boot_id_unavailable || fail 'cannot record post-reboot QGA failure'
  exit 72
fi
boot_after=$(trim_line_endings "$qga_output")
lifecycle_finished=$(now_utc)
if [[ "$boot_before" == "$boot_after" ]]; then
  write_failure vm-lifecycle verify-boot-id 73 "$lifecycle_log" "$lifecycle_started" "$lifecycle_finished" boot_id_unchanged || fail 'cannot record unchanged boot-ID failure'
  exit 73
fi
lifecycle_details=$(details_json boot_id_before "$boot_before" boot_id_after "$boot_after") || fail 'boot IDs are unsafe'
write_record vm-lifecycle verify-boot-id PASS 0 "$lifecycle_log" "$lifecycle_details" "$lifecycle_started" "$lifecycle_finished" || fail 'cannot record VM lifecycle evidence'

metadata_log=$(create_log vm-metadata) || fail 'cannot create VM metadata log'
metadata_started=$(now_utc)
if ! qga_exec 'uname -m' "$metadata_log" architecture; then
  metadata_finished=$(now_utc)
  if write_qga_limit_failure vm-metadata verify-architecture "$metadata_log" "$metadata_started" "$metadata_finished"; then
    exit 76
  fi
  write_failure vm-metadata collect-architecture 75 "$metadata_log" "$metadata_started" "$metadata_finished" qga_architecture_unavailable || fail 'cannot record QGA architecture failure'
  exit 75
fi
if ! actual_arch=$(normalize_qga_architecture "$qga_output_base64"); then
  metadata_finished=$(now_utc)
  write_failure vm-metadata verify-architecture 76 "$metadata_log" "$metadata_started" "$metadata_finished" qga_architecture_invalid || fail 'cannot record unsafe QGA architecture'
  exit 76
fi
if [[ "$actual_arch" != "$expected_arch" ]]; then
  metadata_finished=$(now_utc)
  write_failure vm-metadata verify-architecture 76 "$metadata_log" "$metadata_started" "$metadata_finished" architecture_mismatch expected_arch "$expected_arch" actual_arch "$actual_arch" || fail 'cannot record architecture mismatch'
  exit 76
fi
if ! qga_exec 'cat /etc/os-release' "$metadata_log"; then
  metadata_finished=$(now_utc)
  if write_qga_limit_failure vm-metadata collect-os "$metadata_log" "$metadata_started" "$metadata_finished"; then
    exit 76
  fi
  write_failure vm-metadata collect-os 77 "$metadata_log" "$metadata_started" "$metadata_finished" qga_os_unavailable || fail 'cannot record OS failure'
  exit 77
fi
os_release=$(trim_line_endings "$qga_output")
if ! qga_exec 'uname -r' "$metadata_log"; then
  metadata_finished=$(now_utc)
  if write_qga_limit_failure vm-metadata collect-kernel "$metadata_log" "$metadata_started" "$metadata_finished"; then
    exit 76
  fi
  write_failure vm-metadata collect-kernel 78 "$metadata_log" "$metadata_started" "$metadata_finished" qga_kernel_unavailable || fail 'cannot record kernel failure'
  exit 78
fi
kernel=$(trim_line_endings "$qga_output")
if ! qga_exec 'nproc' "$metadata_log"; then
  metadata_finished=$(now_utc)
  if write_qga_limit_failure vm-metadata collect-vcpu "$metadata_log" "$metadata_started" "$metadata_finished"; then
    exit 76
  fi
  write_failure vm-metadata collect-vcpu 79 "$metadata_log" "$metadata_started" "$metadata_finished" qga_vcpu_unavailable || fail 'cannot record vCPU failure'
  exit 79
fi
vcpu=$(trim_line_endings "$qga_output")
if ! qga_exec 'awk "/MemTotal/ {print \$2}" /proc/meminfo' "$metadata_log"; then
  metadata_finished=$(now_utc)
  if write_qga_limit_failure vm-metadata collect-ram "$metadata_log" "$metadata_started" "$metadata_finished"; then
    exit 76
  fi
  write_failure vm-metadata collect-ram 80 "$metadata_log" "$metadata_started" "$metadata_finished" qga_ram_unavailable || fail 'cannot record RAM failure'
  exit 80
fi
ram_kib=$(trim_line_endings "$qga_output")
if ! qga_exec 'docker version --format "{{.Client.Version}}|{{.Server.Version}}"' "$metadata_log"; then
  metadata_finished=$(now_utc)
  if write_qga_limit_failure vm-metadata docker-before "$metadata_log" "$metadata_started" "$metadata_finished"; then
    exit 76
  fi
  write_failure vm-metadata docker-before 81 "$metadata_log" "$metadata_started" "$metadata_finished" docker_before_unavailable || fail 'cannot record Docker-before failure'
  exit 81
fi
docker_before=$(trim_line_endings "$qga_output")
metadata_finished=$(now_utc)
metadata_details=$(details_json os "$os_release" kernel "$kernel" arch "$actual_arch" vcpu "$vcpu" ram_kib "$ram_kib" docker_before "$docker_before") || fail 'VM metadata is unsafe'
write_record vm-metadata collect-runtime PASS 0 "$metadata_log" "$metadata_details" "$metadata_started" "$metadata_finished" || fail 'cannot record VM metadata'

network_log=$(create_log network) || fail 'cannot create network log'
network_started=$(now_utc)
if qga_exec "$network_probe" "$network_log"; then
  network_finished=$(now_utc)
  write_failure network verify-offline 82 "$network_log" "$network_started" "$network_finished" public_network_reachable || fail 'cannot record public-network failure'
  exit 82
else
  network_exit=$?
fi
network_finished=$(now_utc)
if write_qga_limit_failure network verify-offline "$network_log" "$network_started" "$network_finished"; then
  exit 76
fi
if [[ "$network_exit" -eq 255 ]]; then
  write_failure network verify-offline 83 "$network_log" "$network_started" "$network_finished" qga_network_probe_unavailable || fail 'cannot record network probe failure'
  exit 83
fi
network_details=$(details_json public_network blocked probe_exit "$network_exit") || fail 'network evidence is unsafe'
write_record network verify-offline PASS 0 "$network_log" "$network_details" "$network_started" "$network_finished" || fail 'cannot record offline network evidence'

for scenario_line in "${scenario_lines[@]}"; do
  scenario_name=${scenario_line%%$'\t'*}
  scenario_fields=${scenario_line#*$'\t'}
  scenario_encoded=${scenario_fields%%$'\t'*}
  scenario_fields=${scenario_fields#*$'\t'}
  migration_encoded=${scenario_fields%%$'\t'*}
  business_encoded=${scenario_fields#*$'\t'}
  decode_value() {
    python3 - "$1" <<'PY'
import base64
import sys
try:
    sys.stdout.buffer.write(base64.b64decode(sys.argv[1], validate=True))
except (ValueError, TypeError):
    raise SystemExit(2)
PY
  }
  scenario_command=$(decode_value "$scenario_encoded") || fail 'scenario command is invalid'
  migration_probe=$(decode_value "$migration_encoded") || fail 'scenario migration probe is invalid'
  business_probe=$(decode_value "$business_encoded") || fail 'scenario business probe is invalid'
  scenario_log=$(create_log "$scenario_name") || fail 'cannot create scenario log'
  scenario_started=$(now_utc)
  if qga_exec "$scenario_command" "$scenario_log"; then
    scenario_finished=$(now_utc)
    if [[ -n "$migration_probe" ]]; then
      migration_record_id="${scenario_name}.migration-probe"
      migration_log=$(create_log "$migration_record_id") || fail 'cannot create migration probe log'
      migration_started=$(now_utc)
      if qga_exec "$migration_probe" "$migration_log"; then
        migration_finished=$(now_utc)
        migration_details=$(details_json probe migration) || fail 'migration probe details are unsafe'
        write_record_as "$migration_record_id" "$scenario_name" migration-probe PASS 0 "$migration_log" "$migration_details" "$migration_started" "$migration_finished" || fail 'cannot record migration probe evidence'
        migration_status=PASS
      else
        probe_exit=$?
        migration_finished=$(now_utc)
        if write_qga_limit_failure_as "$migration_record_id" "$scenario_name" migration-probe "$migration_log" "$migration_started" "$migration_finished"; then
          exit 76
        fi
        [[ "$probe_exit" -ne 255 ]] || probe_exit=84
        write_failure_as "$migration_record_id" "$scenario_name" migration-probe "$probe_exit" "$migration_log" "$migration_started" "$migration_finished" migration_probe_nonzero || fail 'cannot record migration probe failure'
        exit "$probe_exit"
      fi
    else
      migration_status=not_configured
    fi
    if [[ -n "$business_probe" ]]; then
      business_record_id="${scenario_name}.business-probe"
      business_log=$(create_log "$business_record_id") || fail 'cannot create business probe log'
      business_started=$(now_utc)
      if qga_exec "$business_probe" "$business_log"; then
        business_finished=$(now_utc)
        business_details=$(details_json probe business) || fail 'business probe details are unsafe'
        write_record_as "$business_record_id" "$scenario_name" business-probe PASS 0 "$business_log" "$business_details" "$business_started" "$business_finished" || fail 'cannot record business probe evidence'
        business_status=PASS
      else
        probe_exit=$?
        business_finished=$(now_utc)
        if write_qga_limit_failure_as "$business_record_id" "$scenario_name" business-probe "$business_log" "$business_started" "$business_finished"; then
          exit 76
        fi
        [[ "$probe_exit" -ne 255 ]] || probe_exit=84
        write_failure_as "$business_record_id" "$scenario_name" business-probe "$probe_exit" "$business_log" "$business_started" "$business_finished" business_probe_nonzero || fail 'cannot record business probe failure'
        exit "$probe_exit"
      fi
    else
      business_status=not_configured
    fi
    scenario_details=$(details_json migration_probe "$migration_status" business_probe "$business_status") || fail 'scenario details are unsafe'
    write_record "$scenario_name" execute PASS 0 "$scenario_log" "$scenario_details" "$scenario_started" "$scenario_finished" || fail 'cannot record scenario evidence'
    continue
  else
    scenario_exit=$?
  fi
  scenario_finished=$(now_utc)
  if write_qga_limit_failure "$scenario_name" execute "$scenario_log" "$scenario_started" "$scenario_finished"; then
    exit 76
  fi
  if [[ "$scenario_exit" -eq 255 ]]; then
    write_failure "$scenario_name" execute 84 "$scenario_log" "$scenario_started" "$scenario_finished" qga_scenario_unavailable || fail 'cannot record scenario transport failure'
    exit 84
  fi
  write_failure "$scenario_name" execute "$scenario_exit" "$scenario_log" "$scenario_started" "$scenario_finished" scenario_exit_nonzero || fail 'cannot record scenario failure'
  exit "$scenario_exit"
done

if [[ -n "$home_migration_baseline_command" ]]; then
  baseline_log=$(create_log vm-migration-baseline) || fail 'cannot create migration baseline log'
  if ! qga_exec "$home_migration_baseline_command" "$baseline_log"; then
    append_log "$baseline_log" migration_baseline_command_failed
    fail 'home migration baseline command failed'
  fi
  python3 "$baseline_capture" \
    --evidence-root "$evidence_root" \
    --artifact-json "$artifact_json" \
    --release-json "$release_json" \
    --payload-base64 "$qga_output_base64" >/dev/null || fail 'cannot capture VM migration baseline'
fi

verify_record_log() {
  local record_path=$1
  local log_path=$2
  python3 "$record_step" \
    --evidence-root "$evidence_root" \
    --verify-record-log "$record_path" \
    --log "$log_path" >/dev/null
}

for scenario_name in "${!record_logs[@]}"; do
  if ! verify_record_log "records/$scenario_name.json" "${record_logs[$scenario_name]}"; then
    integrity_log=$(create_log evidence-integrity) || fail 'cannot create integrity log'
    integrity_started=$(now_utc)
    append_log "$integrity_log" record_log_hash_mismatch
    integrity_finished=$(now_utc)
    write_failure evidence-integrity verify-log-hashes 85 "$integrity_log" "$integrity_started" "$integrity_finished" log_hash_mismatch || fail 'cannot record log hash mismatch'
    exit 85
  fi
done

required_scenarios=(
  n1-install clean-install offline-reboot upgrade-n1-r7 rollback-r7-n1 reupgrade-n1-r7
  tamper-run tamper-manifest tamper-sbom tamper-provenance tamper-receipt browser-login
  model-api model-stream security-benign security-block security-audit portal-proxy-idp-chat
)
declare -A observed_scenarios=()
for scenario_line in "${scenario_lines[@]}"; do
  observed_scenarios["${scenario_line%%$'\t'*}"]=1
done
coverage_ok=true
for scenario_name in "${required_scenarios[@]}"; do
  [[ -n ${observed_scenarios[$scenario_name]:-} ]] || coverage_ok=false
done
[[ ${#observed_scenarios[@]} -eq ${#required_scenarios[@]} ]] || coverage_ok=false
if [[ "$coverage_ok" != true ]]; then
  matrix_log=$(create_log vm-matrix) || fail 'cannot create matrix log'
  matrix_started=$(now_utc)
  append_log "$matrix_log" scenario_coverage_incomplete
  matrix_finished=$(now_utc)
  write_failure vm-matrix verify-scenario-coverage 86 "$matrix_log" "$matrix_started" "$matrix_finished" scenario_coverage_incomplete || fail 'cannot record incomplete matrix failure'
  exit 86
fi

postcheck_log=$(create_log vm-postcheck) || fail 'cannot create postcheck log'
postcheck_started=$(now_utc)
if ! qga_exec 'docker version --format "{{.Client.Version}}|{{.Server.Version}}"' "$postcheck_log"; then
  postcheck_finished=$(now_utc)
  if write_qga_limit_failure vm-postcheck docker-after "$postcheck_log" "$postcheck_started" "$postcheck_finished"; then
    exit 76
  fi
  write_failure vm-postcheck docker-after 87 "$postcheck_log" "$postcheck_started" "$postcheck_finished" docker_after_unavailable || fail 'cannot record Docker-after failure'
  exit 87
fi
docker_after=$(trim_line_endings "$qga_output")
postcheck_finished=$(now_utc)
postcheck_details=$(details_json docker_after "$docker_after" version_sequence "$version_sequence" image_ids "$image_ids") || fail 'postcheck evidence is unsafe'
write_record vm-postcheck collect-runtime PASS 0 "$postcheck_log" "$postcheck_details" "$postcheck_started" "$postcheck_finished" || fail 'cannot record postcheck evidence'

formal_ready=false
if formal_inputs_ready; then
  formal_ready=true
fi

if [[ -z "$artifact_json" || -z "$release_json" ]]; then
  promotion_log=$(create_log promotion) || fail 'cannot create promotion log'
  promotion_started=$(now_utc)
  append_log "$promotion_log" artifact_or_release_identity_missing
  promotion_finished=$(now_utc)
  write_failure promotion verify-formal-inputs 88 "$promotion_log" "$promotion_started" "$promotion_finished" formal_receipt_inputs_missing || fail 'cannot record promotion failure'
elif [[ "$verify_formal" != true || "$formal_ready" != true ]]; then
  promotion_log=$(create_log promotion) || fail 'cannot create promotion log'
  promotion_started=$(now_utc)
  if [[ "$verify_formal" == true ]]; then
    append_log "$promotion_log" formal_verification_inputs_incomplete
  else
    append_log "$promotion_log" verifier_inputs_missing
  fi
  promotion_finished=$(now_utc)
  write_failure promotion verify-formal-inputs 89 "$promotion_log" "$promotion_started" "$promotion_finished" formal_receipt_inputs_missing || fail 'cannot record promotion boundary'
fi

for scenario_name in "${!record_logs[@]}"; do
  if ! verify_record_log "records/$scenario_name.json" "${record_logs[$scenario_name]}"; then
    integrity_log=$(create_log evidence-integrity) || fail 'cannot create integrity log'
    integrity_started=$(now_utc)
    append_log "$integrity_log" record_log_hash_mismatch
    integrity_finished=$(now_utc)
    write_failure evidence-integrity verify-log-hashes 90 "$integrity_log" "$integrity_started" "$integrity_finished" log_hash_mismatch || fail 'cannot record log hash mismatch'
    exit 90
  fi
done

index_args=(--evidence-root "$evidence_root" --output evidence-index.json --artifact-json "$artifact_json" --release-json "$release_json")
for scenario_name in "${!record_logs[@]}"; do
  index_args+=(--entry "records/$scenario_name.json" --entry "${record_logs[$scenario_name]}")
done
if [[ -n "$home_migration_baseline_command" ]]; then
  index_args+=(--entry home-migration-baseline.json)
fi
if [[ -z "$artifact_json" || -z "$release_json" ]]; then
  fail 'cannot build evidence index without artifact and release identity'
fi
python3 "$evidence_indexer" "${index_args[@]}" >/dev/null || fail 'cannot build evidence index'

if [[ "$verify_formal" != true ]]; then
  exit 89
fi
if [[ "$formal_ready" != true ]]; then
  fail 'formal verification inputs are incomplete'
fi

formal_completed=$(now_utc)
formal_stage=$(new_formal_stage) || fail 'cannot allocate formal receipt staging path'
formal_stage_active=true
formal_stage_path="$evidence_root/$formal_stage"
if ! formal_stage_result=$(python3 "$evidence_indexer" \
  --evidence-root "$evidence_root" \
  --output evidence-index.json \
  --artifact-json "$artifact_json" \
  --release-json "$release_json" \
  --write-formal-receipt "$formal_stage" \
  --completed-at "$formal_completed"); then
  fail 'cannot write staged formal receipt'
fi
formal_stage_sha256=$(printf '%s' "$formal_stage_result" | python3 -c '
import json
import re
import sys

expected_path = sys.argv[1]
try:
    result = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit(2)
if (
    not isinstance(result, dict)
    or set(result) != {"action", "path", "sha256"}
    or result["action"] != "write-formal-receipt"
    or result["path"] != expected_path
    or not isinstance(result["sha256"], str)
    or re.fullmatch(r"[0-9a-f]{64}", result["sha256"]) is None
):
    raise SystemExit(2)
print(result["sha256"])
' "$formal_stage_path") || fail 'cannot bind staged formal receipt identity'

if ! python3 "$receipt_verifier" \
  --receipt "$formal_stage_path" \
  --artifact "$formal_artifact" \
  --evidence-index "$evidence_root/evidence-index.json" \
  --evidence-root "$evidence_root" \
  --public-key "$formal_public_key" \
  --source-repository "$formal_source_repository" \
  --authoritative-remote "$formal_authoritative_remote" >/dev/null; then
  fail 'formal verification failed'
fi

formal_publish_active=true
if ! python3 "$evidence_indexer" \
  --evidence-root "$evidence_root" \
  --publish-formal-receipt "$formal_stage" \
  --expected-staged-sha256 "$formal_stage_sha256" \
  --receipt "$formal_receipt" >/dev/null; then
  fail 'cannot publish verified formal receipt'
fi
formal_publish_active=false
formal_stage_active=false
formal_stage=
formal_stage_sha256=

exit 0
