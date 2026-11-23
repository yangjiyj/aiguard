#!/usr/bin/env bash
set -Eeuo pipefail

# drift-audit 的反向验证：它必须既不误报、也仍抓得住真漂移。
#
# 这个工具的危险在于「假红」和「假绿」两头都致命：
#   - 假红（本次修的）：硬编码 PROJECT/PG 凭据、不认 env_file，让每个客户现场
#     都报 8 个服务没在跑、库读不到。更糟的是它把根因 4 的正确修法
#     （删掉 compose 空覆盖、让 0600 env_file 说话）报成漂移——照着「修齐」
#     就是把 bug 装回包里。狼来了会让人学会无视门禁。
#   - 假绿：为了消红而放宽判定（比如「env 文件不在就跳过」），等于永久免检。
# 所以这里两个方向都锁：真漂移必须仍然红。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AUDIT="$ROOT_DIR/deploy/lib/drift-audit.py"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

has() {
  local pattern="$1" why="$2"
  grep -Eq -- "$pattern" "$AUDIT" || fail "drift-audit.py 缺少合约（$why）：$pattern"
}

[ -f "$AUDIT" ] || fail "缺少文件：$AUDIT"

# --- 合约 1：项目名必须探测，不能写死 ---
# 离线包装出来的部署，compose 项目名是包目录名，永远不是 docker-compose。
has 'def detect_project' '项目名自动探测'
grep -q 'PROJECT = os.environ.get("PROJECT") or detect_project' "$AUDIT" ||
  fail 'PROJECT 必须先探测再回退，不能写死默认值'
# docker ps 的 .Labels 是逗号分隔字符串，index 会报错并静默输出空 →
# 探测静默回退，表现成「修了还是假红」。必须用 .Label。
grep -q '{{index .Labels' "$AUDIT" &&
  fail 'docker ps 不能用 index .Labels（会报 cannot index slice/array），必须用 {{.Label "k"}}'
has '\{\{\.Label "com\.docker\.compose\.project"\}\}' '按 compose 标签识别项目'
has '\{\{\.Label "com\.docker\.compose\.service"\}\}' '按 compose 标签识别服务'

# --- 合约 2：PG 凭据必须探测 ---
# 写死 newapi/newapi 会让 [C] 在任何按离线包装的部署上恒报「库读不到」。
has 'def detect_pg_credentials' 'PG 凭据自动探测'
grep -q 'PG_USER = os.environ.get("PG_USER") or _det_user' "$AUDIT" ||
  fail 'PG_USER 必须先探测容器再回退'
grep -q 'PG_DB = os.environ.get("PG_DB") or _det_db' "$AUDIT" ||
  fail 'PG_DB 必须先探测容器再回退'

# --- 合约 3：env_file 与 environment 同为「包声明过」---
# 这条最要紧：漏掉 env_file 会把根因 4 的修法误报成漂移。
has 'def _env_file_keys' 'env_file 键枚举'
grep -q '_env_file_keys(sdef.get("env_file"))' "$AUDIT" ||
  fail 'env_offline 必须把 env_file 声明的变量算进来'
# env 文件是部署时生成的（0600 含 secret，不入库），源码树里没有。
# 回退去引导脚本静态枚举键名——不能直接跳过（等于永不检查）。
has 'def _bootstrap_declared_keys' '引导脚本键名回退'
grep -q '_bootstrap_declared_keys(os.path.basename(full))' "$AUDIT" ||
  fail 'env_file 文件缺失时必须回退枚举引导脚本，而不是当成「没声明」'
grep -q 'if env_basename not in text' "$AUDIT" ||
  fail '只能把「确实写这个 env 文件」的引导脚本的键算进来，否则等于放宽免检'
grep -q 'return set()' "$AUDIT" ||
  fail '找不到引导脚本时必须返回空集让 [B] 照常报，不能默认免检'

# --- 合约 4：镜像基底 ENV 不算部署漂移，但不能顺手放宽真检查 ---
has 'def env_image' '镜像基底 ENV 识别'
grep -q 'env_container(running\[svc\]) - env_offline(svc) - NOISE - env_image(svc)' "$AUDIT" ||
  fail '[B] 的差集必须同时扣掉 NOISE 与镜像基底 ENV，且保留 env_offline 判定'

# --- 合约 5：仍然会因真漂移退出 2 ---
grep -q 'drift.append(f"{svc}: ENV运行态有但离线包没声明' "$AUDIT" ||
  fail '[B] 必须仍然把真漏配计为结构性漂移'
grep -q 'sys.exit(2)' "$AUDIT" ||
  fail '发现结构性漂移必须退出 2（否则打包门禁形同虚设）'

# --- 合约 6：纯只读 ---
# 这工具在发货路径上跑，不能改任何东西。
grep -Eq 'docker (rm|stop|start|restart|exec [^ ]+ (psql[^"]*(INSERT|UPDATE|DELETE|DROP)))' "$AUDIT" &&
  fail 'drift-audit 必须纯只读，不能出现写操作'

echo '[ok] drift-audit 假红/假绿双向合约通过'
