#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK_FILE="$SCRIPT_DIR/release-toolchain.lock"
SOURCES_FILE="$SCRIPT_DIR/release-toolchain.sources.json"
CACHE_DIR=
WORK_DIR=
CACHE_LOCK_DIR=
CACHE_LOCK_HELD=0

fail() {
  printf '[error] release toolchain preparation failed: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" && ! -L "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
  if [[ "$CACHE_LOCK_HELD" == 1 && -d "$CACHE_LOCK_DIR" && ! -L "$CACHE_LOCK_DIR" ]]; then
    rmdir -- "$CACHE_LOCK_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

require_regular_file() {
  local path="$1" label="$2"
  [[ -f "$path" && ! -L "$path" ]] || fail "$label is missing, non-regular, or a symbolic link: $path"
}

MODE="${1:-}"
shift || true
case "$MODE" in
  prepare|verify) ;;
  *) fail 'expected prepare or verify mode' ;;
esac

while (($#)); do
  case "$1" in
    --sources)
      [[ "${JJDGUARD_RELEASE_TOOLCHAIN_TESTING:-0}" == 1 ]] ||
        fail 'custom source manifests are test-only'
      SOURCES_FILE="${2:-}"
      shift 2
      ;;
    --lock)
      [[ "${JJDGUARD_RELEASE_TOOLCHAIN_TESTING:-0}" == 1 ]] ||
        fail 'custom toolchain locks are test-only'
      LOCK_FILE="${2:-}"
      shift 2
      ;;
    --cache-dir)
      [[ "${JJDGUARD_RELEASE_TOOLCHAIN_TESTING:-0}" == 1 ]] ||
        fail 'custom cache directories are test-only'
      CACHE_DIR="${2:-}"
      shift 2
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

require_regular_file "$LOCK_FILE" 'toolchain lock'
require_regular_file "$SOURCES_FILE" 'toolchain source manifest'
command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'

TARGET_ARCH="${OFFLINE_TARGET_ARCH:-amd64}"
case "$TARGET_ARCH" in amd64|arm64) ;; *) fail "unsupported toolchain architecture: $TARGET_ARCH" ;; esac
if [[ -z "$CACHE_DIR" ]]; then
  CACHE_DIR="$("$SCRIPT_DIR/release-toolchain-cache-dir.sh" "$TARGET_ARCH")" ||
    fail 'unable to resolve the locked toolchain cache directory'
fi
[[ "$CACHE_DIR" == /* ]] || fail 'cache directory must be absolute'

mapfile -t ASSETS < <(python3 - "$SOURCES_FILE" "$LOCK_FILE" "${JJDGUARD_RELEASE_TOOLCHAIN_TESTING:-0}" "$TARGET_ARCH" <<'PY'
import json, pathlib, re, sys
sources_path, lock_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
testing, target_arch = sys.argv[3] == "1", sys.argv[4]
try:
    sources = json.loads(sources_path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"cannot read source manifest: {exc}")
if set(sources) != {"schema", "assets"} or sources["schema"] != "jjdguard-release-toolchain-sources/v1":
    raise SystemExit("source manifest schema is invalid")
if not isinstance(sources["assets"], list) or len(sources["assets"]) != 4:
    raise SystemExit("source manifest must contain exactly four architecture assets")
lock = {}
for raw in lock_path.read_text(encoding="utf-8").splitlines():
    if raw.count("=") != 1: raise SystemExit("toolchain lock is malformed")
    key, value = raw.split("=", 1)
    if not key or not value or key in lock: raise SystemExit("toolchain lock is malformed")
    lock[key] = value
lock_keys = {
    "docker-static-amd64":"docker_static_amd64_sha256",
    "docker-compose-amd64":"docker_compose_amd64_sha256",
    "docker-static-arm64":"docker_static_arm64_sha256",
    "docker-compose-arm64":"docker_compose_arm64_sha256",
}
production = {
    "docker-static-amd64": {"arch":"amd64","file":"docker-static.tgz","version":"29.5.2","url":"https://download.docker.com/linux/static/stable/x86_64/docker-29.5.2.tgz"},
    "docker-compose-amd64": {"arch":"amd64","file":"docker-compose","version":"5.3.0","url":"https://github.com/docker/compose/releases/download/v5.3.0/docker-compose-linux-x86_64"},
    "docker-static-arm64": {"arch":"arm64","file":"docker-static.tgz","version":"29.5.2","url":"https://download.docker.com/linux/static/stable/aarch64/docker-29.5.2.tgz"},
    "docker-compose-arm64": {"arch":"arm64","file":"docker-compose","version":"5.3.0","url":"https://github.com/docker/compose/releases/download/v5.3.0/docker-compose-linux-aarch64"},
}
seen=set()
for asset in sources["assets"]:
    if not isinstance(asset,dict) or set(asset)!={"name","arch","file","version","url","sha256"}:
        raise SystemExit("source manifest asset fields do not match the schema")
    name=asset["name"]
    if name not in lock_keys or name in seen: raise SystemExit("source manifest asset names are invalid")
    seen.add(name); expected=production[name]
    if asset["arch"]!=expected["arch"]: raise SystemExit("source manifest architecture is invalid")
    if not isinstance(asset["file"],str) or not re.fullmatch(r"[A-Za-z0-9._-]+",asset["file"]): raise SystemExit("source manifest file name is invalid")
    if not isinstance(asset["version"],str) or not re.fullmatch(r"[0-9A-Za-z._-]+",asset["version"]): raise SystemExit("source manifest version is invalid")
    if not isinstance(asset["url"],str) or not re.fullmatch(r"https://[^\s]+",asset["url"]): raise SystemExit("source manifest URL is invalid")
    if not isinstance(asset["sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",asset["sha256"]): raise SystemExit("source manifest SHA-256 is invalid")
    if lock.get(lock_keys[name])!=asset["sha256"]: raise SystemExit("source manifest SHA-256 does not match the toolchain lock")
    if not testing and any(asset[key]!=value for key,value in expected.items()):
        raise SystemExit("production toolchain source manifest does not match the reviewed source")
    if asset["arch"]==target_arch: print("\t".join((name,asset["file"],asset["url"],asset["sha256"],asset["version"])))
if seen!=set(lock_keys): raise SystemExit("source manifest asset coverage is incomplete")
PY
) || fail 'toolchain source manifest or lock is invalid'

[[ "${#ASSETS[@]}" -eq 2 ]] || fail 'toolchain source manifest returned an unexpected asset count'
LOCK_SHA256="$(sha256_file "$LOCK_FILE")"
[[ "$LOCK_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'cannot hash the toolchain lock'

verify_receipt() {
  local receipt="$CACHE_DIR/receipt.json"
  require_regular_file "$receipt" 'toolchain cache receipt'
  python3 - "$receipt" "$CACHE_DIR" "$LOCK_SHA256" "${ASSETS[@]}" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys

receipt_path = pathlib.Path(sys.argv[1])
cache_dir = pathlib.Path(sys.argv[2])
lock_sha256 = sys.argv[3]
assets = [item.split("\t") for item in sys.argv[4:]]

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"receipt is unreadable: {exc}")

expected_assets = []
for name, filename, url, digest, version in assets:
    path = cache_dir / filename
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit("cache payload is not a regular non-symlink file")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    expected_assets.append(
        {
            "name": name,
            "file": filename,
            "version": version,
            "url": url,
            "sha256": hasher.hexdigest(),
            "size": info.st_size,
        }
    )

expected = {
    "schema": "jjdguard-release-toolchain-cache/v1",
    "lock_sha256": lock_sha256,
    "assets": expected_assets,
}
if receipt != expected:
    raise SystemExit("receipt does not match the locked cache payload")
PY
}

verify_cache() {
  [[ -d "$CACHE_DIR" && ! -L "$CACHE_DIR" ]] ||
    fail "toolchain cache is missing or unsafe: $CACHE_DIR"
  local item name filename url expected_sha256 version actual
  for item in "${ASSETS[@]}"; do
    IFS=$'\t' read -r name filename url expected_sha256 version <<<"$item"
    require_regular_file "$CACHE_DIR/$filename" "toolchain cache asset"
    actual="$(sha256_file "$CACHE_DIR/$filename")"
    [[ "$actual" == "$expected_sha256" ]] ||
      fail "toolchain cache asset hash does not match the lock: $filename"
    if [[ "$filename" == docker-compose ]]; then
      [[ -x "$CACHE_DIR/$filename" ]] || fail 'locked Docker Compose binary is not executable'
    fi
  done
  verify_receipt || fail 'toolchain cache receipt does not match the locked assets'
}

if [[ "$MODE" == verify ]]; then
  verify_cache
  printf '[ok] fixed Docker and Compose cache verified without network\n'
  exit 0
fi

if [[ -e "$CACHE_DIR" || -L "$CACHE_DIR" ]]; then
  verify_cache
  printf '[ok] existing fixed Docker and Compose cache is valid\n'
  exit 0
fi

CACHE_PARENT="$(dirname "$CACHE_DIR")"
mkdir -p -m 0700 "$CACHE_PARENT"
[[ -d "$CACHE_PARENT" && ! -L "$CACHE_PARENT" ]] || fail 'toolchain cache parent is unsafe'
CACHE_LOCK_DIR="${CACHE_DIR}.lock"
if ! mkdir -m 0700 "$CACHE_LOCK_DIR"; then
  if [[ -e "$CACHE_DIR" || -L "$CACHE_DIR" ]]; then
    verify_cache
    printf '[ok] existing fixed Docker and Compose cache is valid\n'
    exit 0
  fi
  fail 'another release toolchain preparation is in progress'
fi
CACHE_LOCK_HELD=1
if [[ -e "$CACHE_DIR" || -L "$CACHE_DIR" ]]; then
  verify_cache
  printf '[ok] existing fixed Docker and Compose cache is valid\n'
  exit 0
fi
WORK_DIR="$(mktemp -d "$CACHE_PARENT/.release-toolchain.XXXXXX")"

CURL_BIN=curl
if [[ "${JJDGUARD_RELEASE_TOOLCHAIN_TESTING:-0}" == 1 && -n "${JJDGUARD_RELEASE_TOOLCHAIN_CURL:-}" ]]; then
  CURL_BIN="$JJDGUARD_RELEASE_TOOLCHAIN_CURL"
fi
command -v "$CURL_BIN" >/dev/null 2>&1 || fail 'curl is unavailable'

for item in "${ASSETS[@]}"; do
  IFS=$'\t' read -r name filename url expected_sha256 version <<<"$item"
  temporary="$WORK_DIR/.$filename.download"
  destination="$WORK_DIR/$filename"
  "$CURL_BIN" --fail --location --proto '=https' --tlsv1.2 --output "$temporary" "$url" ||
    fail "unable to download locked toolchain asset: $name"
  [[ -f "$temporary" && ! -L "$temporary" ]] || fail "download did not produce a regular file: $name"
  [[ "$(sha256_file "$temporary")" == "$expected_sha256" ]] ||
    fail "downloaded toolchain asset hash does not match the lock: $name"
  if [[ "$filename" == docker-compose ]]; then
    install -m 0755 "$temporary" "$destination"
  else
    install -m 0644 "$temporary" "$destination"
  fi
  rm -f -- "$temporary"
done

python3 - "$WORK_DIR/receipt.json" "$LOCK_SHA256" "$WORK_DIR" "${ASSETS[@]}" <<'PY'
import hashlib
import json
import pathlib
import sys

receipt_path = pathlib.Path(sys.argv[1])
cache_dir = pathlib.Path(sys.argv[3])
assets = []
for item in sys.argv[4:]:
    name, filename, url, _, version = item.split("\t")
    payload = cache_dir / filename
    digest = hashlib.sha256()
    with payload.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    assets.append(
        {
            "name": name,
            "file": filename,
            "version": version,
            "url": url,
            "sha256": digest.hexdigest(),
            "size": payload.stat().st_size,
        }
    )
receipt = {
    "schema": "jjdguard-release-toolchain-cache/v1",
    "lock_sha256": sys.argv[2],
    "assets": assets,
}
receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
chmod 0644 "$WORK_DIR/receipt.json"

CACHE_DIR_TO_VERIFY="$CACHE_DIR"
CACHE_DIR="$WORK_DIR"
verify_cache
CACHE_DIR="$CACHE_DIR_TO_VERIFY"
mv -T -- "$WORK_DIR" "$CACHE_DIR" || fail 'unable to publish the verified toolchain cache without overwriting an existing cache'
WORK_DIR=
verify_cache
printf '[ok] fixed Docker and Compose cache prepared with locked hashes\n'
