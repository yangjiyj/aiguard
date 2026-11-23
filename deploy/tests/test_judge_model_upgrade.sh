#!/usr/bin/env bash
# 升级也必须把锁定的 judge 模型灌进卷：已装 full 客户的卷里只有旧模型文件，
# 新 compose 指向新文件，升级若不灌卷，llm-judge 会因"GGUF 未找到"反复重启。
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT_DIR/deploy/lib/judge-model-load.sh"
INSTALLER="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
UPGRADE="$ROOT_DIR/deploy/docker-compose/upgrade-bundle.sh"
PACKAGER="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"

fail() {
  printf '[judge-model-upgrade] %s\n' "$*" >&2
  exit 1
}

[[ -f "$LIB" ]] || fail 'shared judge model loader deploy/lib/judge-model-load.sh is missing'
grep -Eq '^load_judge_model\(\) \{' "$LIB" || fail 'shared loader does not define load_judge_model'
sh -n "$LIB" || fail 'shared loader must be POSIX sh (installer runs under sh)'

grep -Eq '^load_judge_model\(\) \{' "$INSTALLER" &&
  fail 'installer keeps a private copy of load_judge_model; it must use the shared loader'
grep -Fq 'lib/judge-model-load.sh' "$INSTALLER" || fail 'installer does not source the shared loader'

grep -Fq 'lib/judge-model-load.sh' "$UPGRADE" || fail 'upgrade does not source the shared loader'
main_body=$(awk '/^main\(\) \{/{f=1} f{print} f && /^\}/{exit}' "$UPGRADE")
[[ -n "$main_body" ]] || fail 'upgrade main() not found'
# 只认作为独立命令的调用（避免注释掉或改名后仍被字符串匹配到）。
load_line=$(printf '%s\n' "$main_body" | grep -n -E '^[[:space:]]*upgrade_load_judge_model[[:space:]]*$' | head -1 | cut -d: -f1)
switch_line=$(printf '%s\n' "$main_body" | grep -n 'run_in_place_upgrade' | head -1 | cut -d: -f1)
images_line=$(printf '%s\n' "$main_body" | grep -n 'load_offline_images' | head -1 | cut -d: -f1)
[[ -n "$load_line" ]] || fail 'upgrade main() never loads the judge model into the volume'
[[ -n "$switch_line" && -n "$images_line" ]] || fail 'upgrade main() structure changed unexpectedly'
(( images_line < load_line )) || fail 'judge model must be loaded after offline images (the copy helper image)'
(( load_line < switch_line )) || fail 'judge model must be loaded before services switch to the new compose'

grep -Fq 'deploy/lib/judge-model-load.sh' "$PACKAGER" || fail 'packager does not ship the shared loader'
grep -Fq 'cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/upgrade.sh' "$PACKAGER" ||
  fail 'packager no longer ships deploy/docker-compose/upgrade.sh; re-check which upgrade entry points exist'

# 第二个有效入口：installer.sh 对已停止的旧实例走 upgrade_install -> deploy/docker-compose/upgrade.sh。
LEGACY="$ROOT_DIR/deploy/docker-compose/upgrade.sh"
grep -Fq 'bash ./upgrade.sh' "$ROOT_DIR/deploy/offline-installer/installer.sh" ||
  fail 'installer no longer calls upgrade.sh; update this test to the real entry points'
grep -Fq 'lib/judge-model-load.sh' "$LEGACY" || fail 'upgrade.sh does not source the shared loader'
legacy_load=$(grep -n -E '^timed_step "load_judge_model" upgrade_load_judge_model$' "$LEGACY" | head -1 | cut -d: -f1)
legacy_images=$(grep -n -E '^timed_step "load_offline_images" load_offline_images$' "$LEGACY" | head -1 | cut -d: -f1)
legacy_mutation=$(grep -n -E '^SERVICE_RUNTIME_MUTATION_STARTED=1$' "$LEGACY" | head -1 | cut -d: -f1)
legacy_switch=$(grep -n -E '^timed_step "switch_images" switch_images$' "$LEGACY" | head -1 | cut -d: -f1)
[[ -n "$legacy_load" ]] || fail 'upgrade.sh never loads the judge model into the volume'
[[ -n "$legacy_images" && -n "$legacy_mutation" && -n "$legacy_switch" ]] || fail 'upgrade.sh structure changed unexpectedly'
(( legacy_images < legacy_load )) || fail 'upgrade.sh must load the model after offline images (copy helper image)'
(( legacy_load < legacy_mutation && legacy_load < legacy_switch )) ||
  fail 'upgrade.sh must load the model before any service mutation'



# 行为：只取出升级器里的 upgrade_load_judge_model 与共享库一起运行，
# 卷内只有旧模型时必须把新模型写入以升级前的项目名命名的卷。
tmp=$(mktemp -d)
chmod 0700 "$tmp"
trap 'rm -rf -- "$tmp"' EXIT
dc="$tmp/deploy/docker-compose"; bin="$tmp/bin"
mkdir -p "$dc/models" "$tmp/deploy/lib" "$bin"
cp "$LIB" "$tmp/deploy/lib/judge-model-load.sh"
gguf_name=$(sed -n 's/^GGUF_NAME="\(.*\)"$/\1/p' "$LIB")
printf 'new-judge' >"$dc/models/$gguf_name"
sha=$(sha256sum "$dc/models/$gguf_name" | awk '{print $1}')
printf 'judge_gguf_sha256=%s\njudge_gguf_size=9\n' "$sha" >"$dc/release-toolchain.lock"
awk '/^upgrade_load_judge_model\(\) \{/{f=1} f{print} f && /^\}/{exit}' "$UPGRADE" >"$tmp/fn.sh"
[[ -s "$tmp/fn.sh" ]] || fail 'upgrade_load_judge_model() not found'
cat >"$bin/docker" <<'EOS'
#!/usr/bin/env sh
printf '%s\n' "$*" >>"$FAKE_LOG"
case "$1" in
  volume) exit 0 ;;
  run)
    [ "$2" = --help ] && { echo '--pull string'; exit 0; }
    case "$*" in
      *'df -Pk /m'*) printf '%s\n' "${FAKE_FREE_KB-104857600}" ;;
      *'%s|'*) [ -e "$FAKE_COPIED" ] && printf '9|%s\n' "$FAKE_SHA" ;;   # 旧卷里没有新文件名
      *'dd if='*) : >"$FAKE_COPIED" ;;
      *sha256sum*) printf '%s\n' "$FAKE_SHA" ;;
    esac ;;
esac
exit 0
EOS
chmod 0755 "$bin/docker"
out=$(cd "$tmp" && PATH="$bin:$PATH" FAKE_LOG="$tmp/log" FAKE_COPIED="$tmp/copied" FAKE_SHA="$sha" \
  SCRIPT_DIR="$dc" EXISTING_PROJECT_NAME=customerproj \
  bash -c 'set -Eeuo pipefail; . "$1"; . "$2"; upgrade_load_judge_model' _ "$tmp/deploy/lib/judge-model-load.sh" "$tmp/fn.sh" 2>&1) ||
  fail "upgrade must load the locked judge model, got: $out"
[[ -e "$tmp/copied" ]] || fail 'upgrade did not copy the new judge model into the volume'
grep -q 'customerproj_judge-models' "$tmp/log" || fail 'upgrade must write the volume of the existing project'
[[ "$out" == *'GGUF 灌卷完成'* ]] || fail "upgrade must report a verified copy, got: $out"

# upgrade.sh 的同名函数：同样灌到当前项目卷；磁盘不足时在复制前失败。
rm -f "$tmp/copied" "$tmp/log"
awk '/^upgrade_load_judge_model\(\) \{/{f=1} f{print} f && /^\}/{exit}' "$LEGACY" >"$tmp/legacy_fn.sh"
[[ -s "$tmp/legacy_fn.sh" ]] || fail 'upgrade.sh upgrade_load_judge_model() not found'
run_legacy() {
  (cd "$tmp" && PATH="$bin:$PATH" FAKE_LOG="$tmp/log" FAKE_COPIED="$tmp/copied" FAKE_SHA="$sha" \
    FAKE_FREE_KB="${1}" SCRIPT_DIR="$dc" COMPOSE_PROJECT_NAME=legacyproj JUDGE_MODEL_LIB="$tmp/deploy/lib/judge-model-load.sh" \
    bash -c 'set -Eeuo pipefail; fail(){ echo "[error] $*"; return 1; }; . "$1"; . "$2"; upgrade_load_judge_model' _ \
      "$tmp/deploy/lib/judge-model-load.sh" "$tmp/legacy_fn.sh" 2>&1)
}
out=$(run_legacy 104857600) || fail "upgrade.sh must load the locked judge model, got: $out"
[[ -e "$tmp/copied" ]] || fail 'upgrade.sh did not copy the new judge model into the volume'
grep -q 'legacyproj_judge-models' "$tmp/log" || fail 'upgrade.sh must write the volume of the pinned project'
rm -f "$tmp/copied"
if out=$(run_legacy 1); then fail "upgrade.sh must abort on insufficient disk, got: $out"; fi
[[ ! -e "$tmp/copied" ]] || fail 'upgrade.sh must not copy when disk headroom is insufficient'
# 共享库缺失（坏包）时 full 升级必须失败，而不是静默跳过灌卷。
if out=$(cd "$tmp" && SCRIPT_DIR="$dc" JUDGE_MODEL_LIB=/nonexistent \
    bash -c 'set -Eeuo pipefail; fail(){ echo "[error] $*"; return 1; }; . "$1"; upgrade_load_judge_model' _ "$tmp/legacy_fn.sh" 2>&1); then
  fail "upgrade.sh must fail when the full bundle lacks the loader, got: $out"
fi

# ---- 写死的 JUDGE_MODEL_PATH 拦截 / 改写 ----
# 结构：upgrade-bundle.sh 在正式镜像 override 之后、提交 Compose 链之前检查；
# 旧模型清理在 run_in_place_upgrade（含 verify_upgrade）之后。
pin_line=$(printf '%s\n' "$main_body" | grep -n -E '^[[:space:]]*pin_judge_model_path[[:space:]]*$' | head -1 | cut -d: -f1)
override_line=$(printf '%s\n' "$main_body" | grep -n -E '^[[:space:]]*write_release_image_override[[:space:]]*$' | head -1 | cut -d: -f1)
persist_line=$(printf '%s\n' "$main_body" | grep -n -E '^[[:space:]]*persist_active_compose_chain[[:space:]]*$' | head -1 | cut -d: -f1)
retire_line=$(printf '%s\n' "$main_body" | grep -n -E '^[[:space:]]*retire_legacy_judge_model_after_upgrade[[:space:]]*$' | head -1 | cut -d: -f1)
[[ -n "$pin_line" && -n "$override_line" && -n "$persist_line" ]] || fail 'upgrade main() must check JUDGE_MODEL_PATH'
(( override_line < pin_line && pin_line < persist_line )) ||
  fail 'JUDGE_MODEL_PATH check must run after the image override and before the chain is committed'
[[ -n "$retire_line" ]] || fail 'upgrade main() never retires the legacy judge model'
(( switch_line < retire_line )) || fail 'legacy judge model must be retired only after the verified switch'
legacy_check=$(grep -n -E '^timed_step "check_judge_model_path" check_judge_model_path$' "$LEGACY" | head -1 | cut -d: -f1)
legacy_retire=$(grep -n -E '^timed_step "retire_legacy_judge_model" retire_legacy_judge_model_after_upgrade$' "$LEGACY" | head -1 | cut -d: -f1)
legacy_history=$(grep -n -E '^timed_step "write_history" write_history$' "$LEGACY" | head -1 | cut -d: -f1)
[[ -n "$legacy_check" && -n "$legacy_retire" && -n "$legacy_history" ]] || fail 'upgrade.sh must check and retire judge models'
(( legacy_check < legacy_mutation )) || fail 'upgrade.sh must check JUDGE_MODEL_PATH before any service mutation'
(( legacy_history < legacy_retire )) || fail 'upgrade.sh must retire the legacy model after the upgrade is recorded'

# 决策函数：当前锁定 / 空 -> ok；历史随包 -> repin；未知 -> block（显式放行 -> custom）。
decide() { (. "$LIB"; JUDGE_MODEL_PATH_ALLOW_CUSTOM="${2:-0}" judge_model_path_decision "$1"); }
[[ "$(decide "/models/$gguf_name")" == ok ]] || fail 'locked model path must be accepted'
[[ "$(decide '')" == ok ]] || fail 'deployments without llm-judge must be accepted'
[[ "$(decide /models/Qwen2.5-3B-Instruct-Q4_K_M.gguf)" == repin ]] || fail 'hardcoded 3B path must be repinned'
[[ "$(decide /models/Qwen3-4B-Instruct-2507-Q4_K_M.gguf)" == repin ]] || fail 'hardcoded base 4B path must be repinned'
[[ "$(decide /models/customer.gguf)" == block ]] || fail 'unknown model path must block the upgrade'
[[ "$(decide /models/customer.gguf 1)" == custom ]] || fail 'explicit opt-in must keep a customer model'
[[ "$(decide /models/Qwen2.5-3B-Instruct-Q4_K_M.gguf 1)" == repin ]] ||
  fail 'the custom opt-in must never keep the non-commercial 3B model'
# 解析：map 形式、带引号；多个取值必须失败。
parse() { (. "$LIB"; judge_model_path_from_rendered); }
[[ "$(printf '  llm-judge:\n    environment:\n      JUDGE_MODEL_PATH: "/models/a.gguf"\n' | parse)" == /models/a.gguf ]] ||
  fail 'rendered JUDGE_MODEL_PATH must be parsed'
if printf '      JUDGE_MODEL_PATH: /models/a.gguf\n      JUDGE_MODEL_PATH: /models/b.gguf\n' | parse >/dev/null 2>&1; then
  fail 'conflicting JUDGE_MODEL_PATH values must be rejected'
fi

# 行为：upgrade-bundle.sh 的 pin_judge_model_path 用假 compose 渲染。
awk '/^pin_judge_model_path\(\) \{/{f=1} f{print} f && /^\}/{exit}' "$UPGRADE" >"$tmp/pin_fn.sh"
[[ -s "$tmp/pin_fn.sh" ]] || fail 'pin_judge_model_path() not found'
cat >"$bin/fake-compose" <<'EOS'
#!/usr/bin/env sh
# 最后一个 -f 是 pin 覆盖层时视为已改回锁定模型。
value="$FAKE_RENDERED_PATH"
for arg in "$@"; do case "$arg" in *judge-model-pin.override.yml) value="/models/$FAKE_LOCKED" ;; esac; done
printf 'services:\n  llm-judge:\n    environment:\n      JUDGE_MODEL_PATH: %s\n' "$value"
EOS
chmod 0755 "$bin/fake-compose"
run_pin() {
  local active="$tmp/active-$RANDOM"
  mkdir -p "$active"
  (cd "$tmp" && FAKE_RENDERED_PATH="$1" FAKE_LOCKED="$gguf_name" SCRIPT_DIR="$dc" ACTIVE_CONFIG_DIR="$active" \
    ACTIVE_CONFIG_FILES="$active/inherited-001.yml" JUDGE_MODEL_PATH_ALLOW_CUSTOM="${2:-0}" FAKE_COMPOSE="$bin/fake-compose" \
    bash -c 'set -Eeuo pipefail
      fail(){ echo "[error] $*"; exit 1; }; log(){ echo "$*"; }
      new_compose_args(){
        local f; local -a e=()
        NEW_COMPOSE_ARGS=("$FAKE_COMPOSE")
        IFS=, read -ra e <<<"$ACTIVE_CONFIG_FILES"
        for f in "${e[@]}"; do NEW_COMPOSE_ARGS+=(-f "$f"); done
      }
      . "$1"; . "$2"
      pin_judge_model_path
      printf "ACTIVE=%s\nPATH_USED=%s\n" "$ACTIVE_CONFIG_FILES" "$JUDGE_MODEL_ACTIVE_PATH"' _ \
      "$tmp/deploy/lib/judge-model-load.sh" "$tmp/pin_fn.sh" 2>&1)
}
out=$(run_pin "/models/$gguf_name") || fail "locked path must pass the pin check, got: $out"
[[ "$out" != *judge-model-pin* ]] || fail 'locked path must not add an override layer'
out=$(run_pin /models/Qwen2.5-3B-Instruct-Q4_K_M.gguf) || fail "3B path must be repinned, got: $out"
[[ "$out" == *'judge-model-pin.override.yml'* && "$out" == *"PATH_USED=/models/$gguf_name"* ]] ||
  fail "3B path must be overridden by a final pin layer, got: $out"
pin_file=$(printf '%s\n' "$out" | sed -n 's/^ACTIVE=.*,\(.*judge-model-pin.override.yml\)$/\1/p')
[[ -f "$pin_file" ]] && grep -Fq "JUDGE_MODEL_PATH: /models/$gguf_name" "$pin_file" ||
  fail 'pin override layer must set the locked model path'
if out=$(run_pin /models/customer.gguf); then fail "unknown model path must block, got: $out"; fi
[[ "$out" == *JUDGE_MODEL_PATH_ALLOW_CUSTOM* ]] || fail "block message must explain the opt-in, got: $out"
out=$(run_pin /models/customer.gguf 1) || fail "explicit opt-in must keep the customer model, got: $out"
[[ "$out" == *'PATH_USED=/models/customer.gguf'* ]] || fail 'customer model path must be kept on opt-in'

# ---- 升级成功后移出 3B ----
cat >"$bin/docker" <<'EOS'
#!/usr/bin/env sh
printf '%s\n' "$*" >>"$FAKE_LOG"
case "$1" in
  volume) [ "$2" = inspect ] && { [ "${FAKE_NO_VOLUME:-0}" = 1 ] && exit 1; exit 0; }; exit 0 ;;
  run)
    [ "$2" = --help ] && { echo '--pull string'; exit 0; }
    case "$*" in
      *'echo link'*) [ -e "$FAKE_VOL/$FAKE_NAME" ] && echo file; exit 0 ;;
      *'rm -f -- "/m/$1"'*) rm -f "$FAKE_VOL/$FAKE_NAME"; exit 0 ;;
      *'cat "$src"'*)
        # 真实执行容器内脚本：把 /m 与 /out 映射到测试目录，验证"先复制校验、后删除"。
        out=''; script=''; name=''
        while [ $# -gt 0 ]; do
          case "$1" in
            -v) case "$2" in *:/out) out="${2%:/out}" ;; esac; shift ;;
            -c) script="$2"; name="$4"; break ;;
          esac
          shift
        done
        script=$(printf '%s' "$script" | sed -e "s#/m/#$FAKE_VOL/#g" -e "s#/out#$out#g")
        [ "${FAKE_COPY_FAIL:-0}" = 1 ] && script=$(printf '%s' "$script" | sed 's#cat "\$src" >"\$tmp"#false#')
        exec sh -c "$script" sh "$name" ;;
    esac ;;
esac
exit 0
EOS
chmod 0755 "$bin/docker"
mkdir -p "$tmp/vol"
retire() {
  (cd "$tmp" && PATH="$bin:$PATH" FAKE_LOG="$tmp/rlog" FAKE_VOL="$tmp/vol" FAKE_NAME=Qwen2.5-3B-Instruct-Q4_K_M.gguf \
    COMPOSE_PROJECT_NAME=customerproj "$@" \
    sh -c '. "$1"; retire_legacy_judge_models "$2" "$3"' _ "$LIB" "$tmp/backup" "/models/$gguf_name" 2>&1)
}
printf 'old-3b' >"$tmp/vol/Qwen2.5-3B-Instruct-Q4_K_M.gguf"
out=$(retire env) || fail "legacy 3B must be retired, got: $out"
[[ ! -e "$tmp/vol/Qwen2.5-3B-Instruct-Q4_K_M.gguf" ]] || fail 'legacy 3B must leave the judge volume'
[[ -f "$tmp/backup/retired-judge-models/Qwen2.5-3B-Instruct-Q4_K_M.gguf" ]] || fail 'legacy 3B must be kept in the backup dir'
grep -q 'customerproj_judge-models' "$tmp/rlog" || fail 'retire must target the existing project volume'
out=$(retire env) || fail "retire must be idempotent, got: $out"
# 复制失败：卷内文件必须保留。
rm -rf "$tmp/backup"; printf 'old-3b' >"$tmp/vol/Qwen2.5-3B-Instruct-Q4_K_M.gguf"
if out=$(retire env FAKE_COPY_FAIL=1); then fail "copy failure must be reported, got: $out"; fi
[[ -e "$tmp/vol/Qwen2.5-3B-Instruct-Q4_K_M.gguf" ]] || fail 'failed copy must not delete the legacy model'
# keep / delete / 非法模式 / 无卷。
out=$(retire env JUDGE_LEGACY_MODEL_RETIRE=keep) || fail "keep mode must succeed, got: $out"
[[ -e "$tmp/vol/Qwen2.5-3B-Instruct-Q4_K_M.gguf" ]] || fail 'keep mode must not touch the volume'
if out=$(retire env JUDGE_LEGACY_MODEL_RETIRE=bogus); then fail "invalid retire mode must fail, got: $out"; fi
out=$(retire env JUDGE_LEGACY_MODEL_RETIRE=delete) || fail "delete mode must succeed, got: $out"
[[ ! -e "$tmp/vol/Qwen2.5-3B-Instruct-Q4_K_M.gguf" ]] || fail 'delete mode must remove the legacy model'
out=$(retire env FAKE_NO_VOLUME=1) || fail "missing volume must be a no-op, got: $out"
# 当前生效路径就是 3B（例如客户显式放行）时绝不删除。
printf 'old-3b' >"$tmp/vol/Qwen2.5-3B-Instruct-Q4_K_M.gguf"
out=$(cd "$tmp" && PATH="$bin:$PATH" FAKE_LOG="$tmp/rlog" FAKE_VOL="$tmp/vol" FAKE_NAME=Qwen2.5-3B-Instruct-Q4_K_M.gguf \
  COMPOSE_PROJECT_NAME=customerproj \
  sh -c '. "$1"; retire_legacy_judge_models "$2" /models/Qwen2.5-3B-Instruct-Q4_K_M.gguf' _ "$LIB" "$tmp/backup" 2>&1) ||
  fail "retire with active 3B must not fail, got: $out"
[[ -e "$tmp/vol/Qwen2.5-3B-Instruct-Q4_K_M.gguf" ]] || fail 'the active model must never be retired'
# 4B 原版 Apache-2.0 保留作回退模型，不在清理名单里。
grep -Eq '^RETIRED_JUDGE_GGUF_NAMES="Qwen2.5-3B-Instruct-Q4_K_M.gguf"$' "$LIB" ||
  fail 'only the non-commercial 3B model may be retired'
# 升级器的清理包装：失败只告警，不让升级失败。
awk '/^retire_legacy_judge_model_after_upgrade\(\) \{/{f=1} f{print} f && /^\}/{exit}' "$UPGRADE" >"$tmp/ret_fn.sh"
out=$(cd "$tmp" && SCRIPT_DIR="$dc" EXISTING_PROJECT_NAME=p BACKUP_DIR="$tmp/b" \
  bash -c 'set -Eeuo pipefail; log(){ echo "$*"; }; retire_legacy_judge_models(){ return 1; }; . "$1"; retire_legacy_judge_model_after_upgrade; echo DONE' _ "$tmp/ret_fn.sh" 2>&1) ||
  fail "retire failure must not fail the upgrade, got: $out"
[[ "$out" == *'[warn]'*DONE* ]] || fail "retire failure must be logged as a warning, got: $out"

printf '[judge-model-upgrade] PASS\n'
