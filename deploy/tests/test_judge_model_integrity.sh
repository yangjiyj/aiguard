#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_SCRIPT="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"

die() {
  printf '[judge-model-integrity] %s\n' "$*" >&2
  exit 1
}

tmp=$(mktemp -d)
chmod 0700 "$tmp"
trap 'rm -rf -- "$tmp"' EXIT

mode_marker="$tmp/mode-secured"
dc="$tmp/deploy/docker-compose"
bin="$tmp/bin"
copy_marker="$tmp/copied"
install -d -m 0700 "$dc/models" "$bin"
# The installer is a top-level shell program, so source only the helper
# definitions through load_judge_model rather than invoking the deployment flow.
# 灌卷逻辑在安装与升级共用的 deploy/lib/judge-model-load.sh 里。
cp "$ROOT_DIR/deploy/lib/judge-model-load.sh" "$dc/deploy-offline-lib.sh"
chmod 0500 "$dc/deploy-offline-lib.sh"

# 文件名取自安装脚本本身，换模型时不必改测试夹具。
gguf_name=$(sed -n 's/^GGUF_NAME="\(.*\)"$/\1/p' "$ROOT_DIR/deploy/lib/judge-model-load.sh")
[ -n "$gguf_name" ] || die 'installer GGUF_NAME not found'
gguf="$dc/models/$gguf_name"
printf 'good' >"$gguf"
expected_sha=$(sha256sum "$gguf" | awk '{print $1}')
printf 'judge_gguf_sha256=%s\njudge_gguf_size=4\n' "$expected_sha" >"$dc/release-toolchain.lock"

cat >"$bin/docker" <<'EOF'
#!/usr/bin/env sh
set -eu

case "$1" in
  volume)
    [ "${2:-}" = create ] || exit 92
    exit 0
    ;;
  run)
    if [ "$2" = --help ]; then
      printf '%s\n' '      --pull string   Pull image before running ("always", "missing", "never")'
      exit 0
    fi
    case "$*" in *'--pull=never'*) ;; *) exit 93 ;; esac
    case "$*" in *'--network=none'*) ;; *) exit 94 ;; esac
    case "$*" in
      *'df -Pk /m'*) printf '%s\n' "${FAKE_FREE_KB-104857600}" ;;
      *'dd if="$src"'*)
        : >"${FAKE_COPY_MARKER:?}"
        [ "${FAKE_VOLUME_POST_SHA-}" = "${FAKE_EXPECTED_SHA:?}" ] || exit 14
        : >"${FAKE_MODE_MARKER:?}"
        ;;
      *sha256sum*)
        case "$*" in *'chmod 0444'*) : >"${FAKE_MODE_MARKER:?}" ;; esac
        # 与真实助手一致：卷内已有文件时输出"大小|哈希"，没有文件时输出空。
        if [ -e "${FAKE_COPY_MARKER:?}" ]; then
          value="${FAKE_VOLUME_POST_SHA-}"
        else
          value="${FAKE_VOLUME_PRE_SHA-}"
        fi
        case "$*" in
          *'%s|'*)
            if [ -n "$value" ]; then printf '%s|%s\n' "${FAKE_VOLUME_SIZE:-4}" "$value"; fi
            ;;
          *) printf '%s\n' "$value" ;;
        esac
        ;;
      *'cp "$src"'* ) : >"${FAKE_COPY_MARKER:?}" ;;
      *'.interrupted'*) : >"${FAKE_RENAME_MARKER:-/dev/null}" ;;
      *) printf 'unexpected docker run: %s\n' "$*" >&2; exit 91 ;;
    esac
    ;;
  *) printf 'unexpected docker call: %s\n' "$*" >&2; exit 92 ;;
esac
EOF
chmod 0500 "$bin/docker"

run_load_judge_model() {
  PATH="$bin:$PATH" \
  COMPOSE_PROJECT_NAME=fixture \
  FAKE_COPY_MARKER="$copy_marker" \
  FAKE_MODE_MARKER="$mode_marker" \
  FAKE_EXPECTED_SHA="$expected_sha" \
  FAKE_VOLUME_PRE_SHA="$1" \
  FAKE_VOLUME_POST_SHA="$2" \
  FAKE_VOLUME_SIZE="${FAKE_VOLUME_SIZE:-4}" \
  FAKE_FREE_KB="${FAKE_FREE_KB-104857600}" \
  SCRIPT_DIR="$dc" sh -c '. "$1"; load_judge_model' "$dc/deploy-offline.sh" "$dc/deploy-offline-lib.sh"
}

wrong_sha=0000000000000000000000000000000000000000000000000000000000000000
printf 'tampered' >"$gguf"
if output=$(run_load_judge_model '' "$expected_sha" 2>&1); then
  die "tampered bundled GGUF must be rejected before Docker, got: $output"
fi
[[ ! -e "$copy_marker" ]] || die 'tampered bundled GGUF must not be copied into the volume'
printf 'good' >"$gguf"

if output=$(run_load_judge_model "$wrong_sha" "$wrong_sha" 2>&1); then
  die "same-size mismatched GGUF must be rejected, got: $output"
fi
[[ ! -e "$copy_marker" ]] || die 'mismatched GGUF must not be copied into the volume'

if ! output=$(run_load_judge_model "$expected_sha" "$expected_sha" 2>&1); then
  die "matching GGUF should be reused, got: $output"
fi
[[ "$output" == *'[skip] GGUF'* ]] || die 'matching GGUF must be reported as reused'
[[ ! -e "$copy_marker" ]] || die 'matching GGUF must not be copied again'
[[ -e "$mode_marker" ]] || die 'matching GGUF must be made readable by the non-root judge'
rm -f "$mode_marker"

if ! output=$(run_load_judge_model '' "$expected_sha" 2>&1); then
  die "empty volume must copy then verify matching GGUF, got: $output"
fi
[[ -e "$copy_marker" ]] || die 'empty volume must copy the verified GGUF'
[[ -e "$mode_marker" ]] || die 'copied GGUF must be made readable by the non-root judge'
[[ "$output" == *'[ok] GGUF 灌卷完成'* ]] || die 'copied GGUF must be reported as verified'

rm -f "$copy_marker"
rm -f "$mode_marker"
if output=$(run_load_judge_model '' "$wrong_sha" 2>&1); then
  die "copy with a mismatched post-copy SHA must be rejected, got: $output"
fi
[[ -e "$copy_marker" ]] || die 'post-copy hash fixture must reach the copy branch'

# 上次中断留下的半文件（体积小于源文件、哈希不同）：保留为 .interrupted 后重新原子写入。
rm -f "$copy_marker" "$mode_marker"
if ! output=$(FAKE_VOLUME_SIZE=1 run_load_judge_model "$wrong_sha" "$expected_sha" 2>&1); then
  die "a half-written GGUF must be set aside and rewritten, got: $output"
fi
[[ "$output" == *'.interrupted'* ]] || die 'half-written GGUF must be preserved as .interrupted'
[[ -e "$copy_marker" ]] || die 'half-written GGUF must be rewritten from the verified bundle'

# 磁盘余量不足：必须在写入前失败，不能留下半文件，也不能报告成功。
rm -f "$copy_marker" "$mode_marker"
if output=$(FAKE_FREE_KB=1024 run_load_judge_model '' "$expected_sha" 2>&1); then
  die "insufficient disk must abort before copying, got: $output"
fi
[[ ! -e "$copy_marker" ]] || die 'insufficient disk must not start the copy'
[[ "$output" == *'磁盘空间不足'* ]] || die "insufficient disk must be reported explicitly, got: $output"
# 无法测量空间同样拒绝继续（不按“未知即足够”处理）。
if output=$(FAKE_FREE_KB='' run_load_judge_model '' "$expected_sha" 2>&1); then
  die "unmeasurable free space must abort, got: $output"
fi
[[ ! -e "$copy_marker" ]] || die 'unmeasurable free space must not start the copy'

# 半文件 + 空间不足：卷必须原样保留，半文件不能被改名。
rename_marker="$(dirname "$copy_marker")/rename-marker"
rm -f "$copy_marker" "$mode_marker" "$rename_marker"
if output=$(FAKE_RENAME_MARKER="$rename_marker" FAKE_FREE_KB=1024 FAKE_VOLUME_SIZE=1 run_load_judge_model "$wrong_sha" "$expected_sha" 2>&1); then
  die "half-written GGUF with insufficient disk must abort, got: $output"
fi
[[ ! -e "$rename_marker" ]] || die 'insufficient disk must not rename the half-written GGUF'
[[ ! -e "$copy_marker" ]] || die 'insufficient disk must not start the copy'
[[ "$output" == *'磁盘空间不足'* ]] || die "insufficient disk must be reported explicitly, got: $output"
# 对照：空间足够时同一场景会改名（证明标记确实接到了改名分支）。
rm -f "$copy_marker" "$mode_marker" "$rename_marker"
FAKE_RENAME_MARKER="$rename_marker" FAKE_VOLUME_SIZE=1 run_load_judge_model "$wrong_sha" "$expected_sha" >/dev/null 2>&1 \
  || die 'half-written GGUF with enough disk must be rewritten'
[[ -e "$rename_marker" ]] || die 'rename marker fixture must observe the .interrupted rename'

printf '[judge-model-integrity] PASS\n'
