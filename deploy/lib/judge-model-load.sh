#!/bin/sh
# 随包 judge 模型灌卷与哈希工具（POSIX sh）。安装器 deploy-offline.sh 与升级器
# upgrade-bundle.sh 共用同一实现：升级也必须把锁定的模型写进 judge-models 卷，
# 否则新 compose 指向的新文件不存在，llm-judge 会反复重启。
# 依赖调用方提供：SCRIPT_DIR（deploy/docker-compose 目录）、COMPOSE_PROJECT_NAME。

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  echo "[error] missing checksum command: shasum or sha256sum" >&2
  exit 1
}

locked_judge_gguf_sha256() {
  lock_file="$SCRIPT_DIR/release-toolchain.lock"
  if [ ! -f "$lock_file" ] || [ -L "$lock_file" ]; then
    echo "[error] judge model lock file is unavailable: $lock_file" >&2
    exit 1
  fi
  expected="$(sed -n 's/^judge_gguf_sha256=//p' "$lock_file")"
  case "$expected" in
    ''|*[!0-9a-f]*)
      echo "[error] invalid judge_gguf_sha256 in $lock_file" >&2
      exit 1
      ;;
  esac
  if [ "${#expected}" -ne 64 ]; then
    echo "[error] invalid judge_gguf_sha256 length in $lock_file" >&2
    exit 1
  fi
  printf '%s\n' "$expected"
}

OFFLINE_DOCKER_RUN_PULL_MODE=unknown
prepare_offline_docker_run_pull() {
  if docker run --help 2>&1 | grep -Fq -- '--pull'; then
    OFFLINE_DOCKER_RUN_PULL_MODE=supported
    echo '[info] Docker CLI supports --pull=never for local image helpers'
    return 0
  fi

  if ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    echo '[error] Docker CLI does not support --pull, and local image postgres:16-alpine is missing' >&2
    exit 1
  fi
  OFFLINE_DOCKER_RUN_PULL_MODE=legacy
  echo '[warn] Docker CLI does not support --pull; verified local postgres:16-alpine and continuing offline'
}

docker_run_offline() {
  case "$OFFLINE_DOCKER_RUN_PULL_MODE" in
    supported) docker run --pull=never "$@" ;;
    legacy) docker run "$@" ;;
    *) echo '[error] offline Docker run compatibility was not initialized' >&2; exit 1 ;;
  esac
}

# full 包：只允许锁定 SHA-256 的 GGUF 进入命名卷 judge-models。
# 用已 load 的 postgres:16-alpine 做 cp 助手（自带 sh/cp，免额外镜像）。
GGUF_NAME="jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf"
load_judge_model() {
  prepare_offline_docker_run_pull
  gguf_src="$SCRIPT_DIR/models/$GGUF_NAME"
  if [ ! -f "$gguf_src" ]; then
    echo "[error] full 包缺 GGUF: $gguf_src" >&2
    exit 1
  fi
  expected_sha="$(locked_judge_gguf_sha256)"
  source_sha="$(sha256_file "$gguf_src")"
  source_size="$(stat -c '%s' "$gguf_src")"
  if [ "$source_sha" != "$expected_sha" ]; then
    echo "[error] full 包 GGUF 哈希与 release-toolchain.lock 不一致" >&2
    exit 1
  fi
  vol="${COMPOSE_PROJECT_NAME}_judge-models"
  docker volume create "$vol" >/dev/null 2>&1 || true
  have_sha="$(
    docker_run_offline --network=none --rm -v "$vol:/m" postgres:16-alpine \
      sh -c 'name=$1
        path=/m/$name
        if [ -e "$path" ] || [ -L "$path" ]; then
          [ -f "$path" ] && [ ! -L "$path" ] || exit 12
          # GGUF is a bundled, non-secret read-only artifact.  The copy helper
          # may inherit a 0600 package mode, which prevents the non-root judge from reading it.
          chmod 0444 "$path" || exit 13
          printf "%s|" "$(stat -c %s "$path")"
          sha256sum "$path" | awk "{print \$1}"
        fi' sh "$GGUF_NAME"
  )" || {
    echo "[error] unable to inspect Judge 模型卷: $vol" >&2
    exit 1
  }
  half_written=0
  if [ -n "$have_sha" ]; then
    have_size="${have_sha%%|*}"
    have_digest="${have_sha#*|}"
    if [ "$have_digest" = "$expected_sha" ]; then
      echo "[skip] GGUF 已在卷 $vol (SHA-256 已验证)"
      return
    fi
    if [ "$have_size" -lt "$source_size" ]; then
      half_written=1
    else
      echo "[error] Judge 模型卷中的完整 GGUF 哈希不匹配，拒绝覆盖: $vol" >&2
      exit 1
    fi
  fi

  # 磁盘余量：在目标卷所在文件系统上检查（与 Docker data-root 一致），不足即在改动卷内
  # 任何文件之前失败；调用方都在切换服务前调用，失败不会留下指向缺失模型的 judge。
  # 半文件改名为 .interrupted 不释放空间，因此不计为可回收；卷内最多保留一个 .interrupted。
  headroom_kb="${JUDGE_MODEL_MIN_HEADROOM_KB:-524288}"
  case "$headroom_kb" in ''|*[!0-9]*) echo "[error] JUDGE_MODEL_MIN_HEADROOM_KB 必须是非负整数" >&2; exit 1 ;; esac
  free_kb="$(
    docker_run_offline --network=none --rm -v "$vol:/m" postgres:16-alpine \
      sh -c 'df -Pk /m | awk "NR==2 {print \$4}"'
  )" || {
    echo "[error] unable to measure free space for Judge 模型卷: $vol" >&2
    exit 1
  }
  case "$free_kb" in
    ''|*[!0-9]*) echo "[error] Judge 模型卷可用空间无法解析: ${free_kb:-empty}" >&2; exit 1 ;;
  esac
  need_kb=$(( (source_size + 1023) / 1024 + headroom_kb ))
  if [ "$free_kb" -lt "$need_kb" ]; then
    echo "[error] Judge 模型卷磁盘空间不足：可用 ${free_kb}KB，需要 ${need_kb}KB（模型 + ${headroom_kb}KB 余量）；未写入、未切换" >&2
    exit 1
  fi
  echo "[ok] Judge 模型卷可用 ${free_kb}KB，需要 ${need_kb}KB"
  # 余量检查通过后才动卷内文件：空间不足时卷保持原样。
  if [ "$half_written" = 1 ]; then
    echo "[warn] 检测到上次中断留下的半文件，保留为 .interrupted 并重新原子写入" >&2
    docker_run_offline --network=none --rm -v "$vol:/m" postgres:16-alpine \
      sh -c 'name=$1; mv "/m/$name" "/m/.$name.interrupted"' sh "$GGUF_NAME"
  fi

  echo "[step] 灌已校验 GGUF 进卷 $vol…"
  docker_run_offline --network=none --rm -v "$vol:/m" -v "$SCRIPT_DIR/models:/src:ro" postgres:16-alpine \
    sh -c 'name=$1
      src=/src/$name
      dest=/m/$name
      incoming=/m/.$name.incoming
      [ -f "$src" ] && [ ! -L "$src" ] || exit 12
      [ ! -e "$dest" ] && [ ! -L "$dest" ] || exit 12
      [ ! -L "$incoming" ] || exit 13
      rm -f "$incoming"
      # BusyBox-based offline runtimes may reject the GNU progress option.
      # Keep the streamed copy and fall back to portable shell I/O without
      # weakening the atomic temp-file and post-copy hash checks.
      if ! dd if="$src" of="$incoming" bs=16M status=progress 2>/dev/null; then
        cat "$src" >"$incoming"
      fi
      [ "$(sha256sum "$incoming" | awk "{print \$1}")" = "$2" ] || exit 14
      chmod 0444 "$incoming"
      mv "$incoming" "$dest"' sh "$GGUF_NAME" "$expected_sha" || {
    echo "[error] unable to copy Judge 模型 into volume: $vol" >&2
    exit 1
  }
  copied_sha="$(
    docker_run_offline --network=none --rm -v "$vol:/m" postgres:16-alpine \
      sh -c 'name=$1
        path=/m/$name
        [ -f "$path" ] && [ ! -L "$path" ] || exit 12
        sha256sum "$path" | awk "{print \$1}"' sh "$GGUF_NAME"
  )" || {
    echo "[error] unable to verify copied Judge 模型: $vol" >&2
    exit 1
  }
  if [ "$copied_sha" != "$expected_sha" ]; then
    echo "[error] copied Judge 模型哈希不匹配: $vol" >&2
    exit 1
  fi
  echo "[ok] GGUF 灌卷完成 (SHA-256 已验证)"
}

# 历史随包 judge 模型。客户 override 层若把 JUDGE_MODEL_PATH 写死成其中之一，
# 升级会继承该层并盖掉新包默认值，llm-judge 就会继续跑旧模型（3B 不可商用）。
LEGACY_JUDGE_GGUF_NAMES="Qwen2.5-3B-Instruct-Q4_K_M.gguf Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
# 升级成功后要移出卷的旧模型（仅不可商用的 3B；4B 原版为 Apache-2.0，保留作回退模型）。
RETIRED_JUDGE_GGUF_NAMES="Qwen2.5-3B-Instruct-Q4_K_M.gguf"

# 输入：渲染后 llm-judge 的 JUDGE_MODEL_PATH（可为空）。输出一个决定：
#   ok    —— 已指向当前锁定模型，或该部署没有 llm-judge；
#   repin —— 指向历史随包模型，由升级器在最后一层强制改回锁定模型；
#   block —— 指向未知文件（客户自带模型），默认拒绝升级；
#            JUDGE_MODEL_PATH_ALLOW_CUSTOM=1 时保留客户值并返回 custom。
judge_model_path_decision() {
  value="$1"
  if [ -z "$value" ] || [ "$value" = "/models/$GGUF_NAME" ]; then
    echo ok
    return 0
  fi
  for legacy in $LEGACY_JUDGE_GGUF_NAMES; do
    if [ "$value" = "/models/$legacy" ]; then
      echo repin
      return 0
    fi
  done
  if [ "${JUDGE_MODEL_PATH_ALLOW_CUSTOM:-0}" = 1 ]; then
    echo custom
    return 0
  fi
  echo block
}

# 从 `compose config` 的输出里取 JUDGE_MODEL_PATH（渲染结果统一为 map 形式）。
# 出现多个不同取值时返回非零，调用方必须拦截。
judge_model_path_from_rendered() {
  values="$(sed -n 's/^[[:space:]]*JUDGE_MODEL_PATH:[[:space:]]*//p' | tr -d "\"'" | sort -u)"
  count="$(printf '%s' "$values" | grep -c . || true)"
  if [ "$count" -gt 1 ]; then
    echo "[error] 渲染后的 Compose 中 JUDGE_MODEL_PATH 取值不唯一" >&2
    return 1
  fi
  printf '%s\n' "$values"
}

# 升级验证通过之后调用：把不可商用的旧模型移出 judge-models 卷。
# 参数 $1：宿主机上的备份目录；$2：当前生效的 JUDGE_MODEL_PATH（这个文件永远不动）。
# JUDGE_LEGACY_MODEL_RETIRE=move（默认，复制到备份目录并校验哈希后才从卷中删除，可手工回退）
#                          =delete（直接删除）=keep（不处理）。
retire_legacy_judge_models() {
  backup_dir="$1"
  active_path="${2:-}"
  mode="${JUDGE_LEGACY_MODEL_RETIRE:-move}"
  case "$mode" in
    keep) echo "[info] JUDGE_LEGACY_MODEL_RETIRE=keep，保留旧 judge 模型"; return 0 ;;
    move|delete) ;;
    *) echo "[error] JUDGE_LEGACY_MODEL_RETIRE 只能是 move、delete 或 keep" >&2; return 1 ;;
  esac
  vol="${COMPOSE_PROJECT_NAME}_judge-models"
  if ! docker volume inspect "$vol" >/dev/null 2>&1; then
    echo "[info] 未找到 Judge 模型卷 $vol，无需清理旧模型"
    return 0
  fi
  prepare_offline_docker_run_pull
  for name in $RETIRED_JUDGE_GGUF_NAMES; do
    if [ "$name" = "$GGUF_NAME" ] || [ "/models/$name" = "$active_path" ]; then
      echo "[warn] 旧模型 $name 仍被当前配置使用，跳过清理" >&2
      continue
    fi
    present="$(
      docker_run_offline --network=none --rm -v "$vol:/m" postgres:16-alpine \
        sh -c 'p=/m/$1; if [ -L "$p" ]; then echo link; elif [ -f "$p" ]; then echo file; fi' sh "$name"
    )" || { echo "[error] 无法检查 Judge 模型卷: $vol" >&2; return 1; }
    case "$present" in
      '') continue ;;
      file) ;;
      *) echo "[error] 旧模型 $name 不是普通文件，拒绝处理" >&2; return 1 ;;
    esac
    if [ "$mode" = delete ]; then
      docker_run_offline --network=none --rm -v "$vol:/m" postgres:16-alpine \
        sh -c 'rm -f -- "/m/$1"' sh "$name" || { echo "[error] 无法删除旧模型 $name" >&2; return 1; }
      echo "[ok] 已从卷 $vol 删除旧模型 $name"
      continue
    fi
    [ -n "$backup_dir" ] || { echo "[error] move 模式需要备份目录" >&2; return 1; }
    dest="$backup_dir/retired-judge-models"
    mkdir -p "$dest" && chmod 0700 "$dest" || { echo "[error] 无法创建 $dest" >&2; return 1; }
    # 复制 -> 两端哈希一致 -> 才删除卷内文件；任一步失败卷内文件保持原样。
    docker_run_offline --network=none --rm -v "$vol:/m" -v "$dest:/out" postgres:16-alpine \
      sh -c 'name=$1
        src=/m/$name
        tmp=/out/.$name.incoming
        a="$(sha256sum "$src" | awk "{print \$1}")"
        [ -n "$a" ] || exit 16
        if [ -e "/out/$name" ] || [ -L "/out/$name" ]; then
          # 重跑：备份已存在且哈希一致才删卷内文件，否则拒绝覆盖任何一端。
          [ -f "/out/$name" ] && [ ! -L "/out/$name" ] || exit 15
          [ "$(sha256sum "/out/$name" | awk "{print \$1}")" = "$a" ] || exit 15
        else
          rm -f "$tmp"
          cat "$src" >"$tmp" || exit 16
          [ "$(sha256sum "$tmp" | awk "{print \$1}")" = "$a" ] || { rm -f "$tmp"; exit 17; }
          mv "$tmp" "/out/$name" || exit 18
        fi
        rm -f -- "$src"' sh "$name" || {
      echo "[error] 旧模型 $name 移出失败，卷内文件未删除" >&2
      return 1
    }
    echo "[ok] 旧模型 $name 已移出卷 $vol，备份在 $dest/$name（观察期后可删除）"
  done
}
