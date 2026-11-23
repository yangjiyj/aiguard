#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

MAX_RECORD_BYTES=$((256 * 1024 * 1024))
MAX_TOTAL_BYTES=$((2 * 1024 * 1024 * 1024))
MAX_LOG_INPUT_BYTES=$((8 * 1024 * 1024))
MAX_LOG_OUTPUT_BYTES=$((1024 * 1024))
MAX_RECORDS=10
MAX_AGE_DAYS=7
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

die() { echo "[failure-evidence] $*" >&2; exit 1; }
usage() { echo "usage: $0 --output-dir ABS_DIR --work-dir ABS_DIR --exit-code CODE" >&2; }

output_dir=''
work_dir=''
exit_code=''
while (($#)); do
  case "$1" in
    --output-dir|--work-dir|--exit-code)
      (($# >= 2)) || { usage; die "missing value for $1"; }
      case "$1" in
        --output-dir) output_dir="$2" ;;
        --work-dir) work_dir="$2" ;;
        --exit-code) exit_code="$2" ;;
      esac
      shift 2
      ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done
[[ "$output_dir" == /* && "$work_dir" == /* && "$exit_code" =~ ^[0-9]+$ ]] || die 'arguments must be absolute paths and a numeric exit code'
[[ -d "$output_dir" && ! -L "$output_dir" && -d "$work_dir" && ! -L "$work_dir" ]] || die 'output and work directories must be real directories'
output_real="$(realpath -e "$output_dir")"
work_real="$(realpath -e "$work_dir")"
[[ "$output_real" != / && "$output_real" != /tmp && "$output_real" != "$PROJECT_ROOT" && "$output_real" != "$work_real" ]] || die 'unsafe output or work root'

for path in "$output_real/evidence" "$output_real/evidence/failures"; do
  [[ ! -L "$path" ]] || die 'evidence path must not contain a symbolic link'
done
install -d -m 0700 "$output_real/evidence/failures"
failure_root="$(realpath -e "$output_real/evidence/failures")"
[[ "$failure_root" == "$output_real/evidence/failures" && "$failure_root" != /tmp ]] || die 'failure root escapes output directory'

safe_remove_record() {
  local record="$1" resolved
  [[ -d "$record" && ! -L "$record" ]] || return 0
  resolved="$(realpath -e "$record")"
  [[ "$resolved" != "$failure_root" && "$(dirname "$resolved")" == "$failure_root" ]] || die 'refusing to remove a path outside the failure root'
  rm -rf -- "$resolved"
}

prune_retention() {
  local record total line path
  while IFS= read -r -d '' record; do
    safe_remove_record "$record"
  done < <(find "$failure_root" -mindepth 1 -maxdepth 1 -type d -mtime "+$MAX_AGE_DAYS" -print0)
  mapfile -t records < <(find "$failure_root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr)
  for ((index=MAX_RECORDS; index<${#records[@]}; index++)); do
    path="${records[$index]#* }"
    safe_remove_record "$path"
  done
  total="$(du -sb "$failure_root" | awk '{print $1}')"
  while (( total > MAX_TOTAL_BYTES )); do
    mapfile -t records < <(find "$failure_root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -n)
    ((${#records[@]})) || die 'failure evidence capacity cannot be recovered'
    path="${records[0]#* }"
    safe_remove_record "$path"
    total="$(du -sb "$failure_root" | awk '{print $1}')"
  done
}

is_sensitive_name() {
  case "$1" in
    .env|*/.env|*.env|*.pem|*.key|*cookie*|*token*|*secret*|*password*) return 0 ;;
    *) return 1 ;;
  esac
}
is_allowed() {
  case "$1" in
    run-manifest.json|failure-summary.tsv|*.log|*.txt|logs/*.log|logs/*.txt) return 0 ;;
    *) return 1 ;;
  esac
}
redact_copy() {
  python3 - "$1" "$2" "$MAX_LOG_OUTPUT_BYTES" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
limit = int(sys.argv[3])
raw = source.read_bytes()
text = raw.decode("utf-8", errors="replace")
patterns = (
    r"(?im)(authorization\s*:\s*bearer\s+)[^\s]+",
    r"(?im)((?:api[_-]?key|password|secret|token|cookie)\s*(?:=|:)\s*)[^\s]+",
)
for pattern in patterns:
    text = re.sub(pattern, r"\1[REDACTED]", text)
encoded = text.encode("utf-8")[:limit]
destination.write_bytes(encoded)
PY
}

prune_retention
record="$failure_root/failure-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 0700 "$record"
index_file="$record/evidence-index.tsv"
printf '%s\t%s\n' schema jjdguard-failure-evidence/v1 >"$index_file"
printf '%s\t%s\n' exit_code "$exit_code" >>"$index_file"
record_bytes=0
while IFS= read -r -d '' file; do
  rel="${file#"$work_real"/}"
  [[ "$file" == "$work_real/"* && -n "$rel" && "$rel" != *$'\t'* && "$rel" != *$'\n'* && "$rel" != *$'\r'* ]] || {
    printf '%s\t%s\t%s\n' dropped invalid-path unsafe-path >>"$index_file"; continue;
  }
  if is_sensitive_name "$rel"; then
    printf '%s\t%s\t%s\n' dropped "$rel" sensitive-name >>"$index_file"
    continue
  fi
  if ! is_allowed "$rel"; then
    printf '%s\t%s\t%s\n' dropped "$rel" not-allowlisted >>"$index_file"
    continue
  fi
  size="$(stat -c '%s' "$file")"
  if (( size > MAX_LOG_INPUT_BYTES )); then
    printf '%s\t%s\t%s\n' dropped "$rel" too-large >>"$index_file"
    continue
  fi
  destination="$record/$rel"
  install -d -m 0700 "$(dirname "$destination")"
  redact_copy "$file" "$destination"
  copied_size="$(stat -c '%s' "$destination")"
  if (( record_bytes + copied_size > MAX_RECORD_BYTES )); then
    rm -f -- "$destination"
    printf '%s\t%s\t%s\n' dropped "$rel" record-cap >>"$index_file"
    continue
  fi
  record_bytes=$((record_bytes + copied_size))
  chmod 0400 "$destination"
  printf '%s\t%s\t%s\t%s\n' kept "$rel" "$copied_size" "$(sha256sum "$destination" | awk '{print $1}')" >>"$index_file"
done < <(find "$work_real" -type f -print0)
chmod 0400 "$index_file"
prune_retention
echo "[ok] failure evidence retained: $record"
