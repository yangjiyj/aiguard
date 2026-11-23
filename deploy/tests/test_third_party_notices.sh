#!/usr/bin/env bash
# 离线包必须随附第三方组件与模型声明，供客户做软件成分审计。
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGER="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"

fail() {
  printf '[third-party-notices] %s\n' "$*" >&2
  exit 1
}

[[ -f "$ROOT_DIR/THIRD-PARTY-NOTICES.md" ]] || fail 'THIRD-PARTY-NOTICES.md is missing from the source tree'
grep -Fq 'Qwen3-4B-Instruct-2507' "$ROOT_DIR/THIRD-PARTY-NOTICES.md" ||
  fail 'notices do not name the bundled Judge model'
grep -Fq 'Apache-2.0' "$ROOT_DIR/THIRD-PARTY-NOTICES.md" ||
  fail 'notices do not state the bundled Judge license'

tmp=$(mktemp -d)
chmod 0700 "$tmp"
trap 'rm -rf -- "$tmp"' EXIT

src="$tmp/src"
bundle="$tmp/bundle"
mkdir -p "$src" "$bundle/deploy/docker-compose"
cp "$ROOT_DIR/THIRD-PARTY-NOTICES.md" "$src/"
printf '# Changelog\n\n## [9.9.9] - 2026-09-27\n\n- test\n' >"$src/CHANGELOG.md"

# 只取出 write_release_notes 函数本身运行，避免触发完整打包流程。
awk '/^write_release_notes\(\) \{/{f=1} f{print} f && /^\}/{exit}' "$PACKAGER" >"$tmp/fn.sh"
[[ -s "$tmp/fn.sh" ]] || fail 'write_release_notes() not found in packager'

(
  PAYLOAD_SOURCE_ROOT="$src" BUNDLE_DIR="$bundle" JJD_VERSION=9.9.9
  # shellcheck disable=SC1090
  . "$tmp/fn.sh"
  write_release_notes
)

[[ -f "$bundle/THIRD-PARTY-NOTICES.md" ]] || fail 'bundle root does not ship THIRD-PARTY-NOTICES.md'
cmp -s "$src/THIRD-PARTY-NOTICES.md" "$bundle/THIRD-PARTY-NOTICES.md" ||
  fail 'bundled notices differ from the source tree'

printf '[third-party-notices] PASS\n'
