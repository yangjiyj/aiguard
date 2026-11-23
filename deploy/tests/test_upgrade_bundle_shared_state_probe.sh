#!/usr/bin/env bash
# 离线 .run 包升级器（upgrade-bundle.sh）的“升级前共享状态（valkey）命名空间探测”回归测试。
#
# 背景：security-engine 对共享状态默认 fail-closed（SECURITY_SHARED_STATE_REQUIRED 缺省 true，URL 指向
# redis:6379/3）。valkey 连不上或 DB 3 不可用时引擎启动即拒绝服务，整条检测链停摆。
# upgrade.sh 早有 verify_shared_state_namespace（见 test_upgrade_shared_state_probe.sh），
# 但离线包升级走的 upgrade-bundle.sh 没有——11-08 的 2.9.13 候选包 CHANGELOG 因此没写“升级前探测”。
# 本测试用假 compose 行为化地验证 upgrade-bundle.sh 里补上的探测：
#   - 成功路径、REQUIRED=false 跳过、DB 编号、环境/.env 优先级；
#   - 失败路径必须中止（fail）并给出可操作的报错（含探测输出、修复步骤，且不泄露口令）；
#   - valkey 没在运行时先拉起、刚启动时有界重试；
#   - 探测必须接在 Redis->Valkey 迁移之后、重建应用容器之前，并处在失败回滚区内。
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="$ROOT/deploy/docker-compose/upgrade-bundle.sh"
CHANGELOG="$ROOT/CHANGELOG.md"

fail() { printf 'FAIL test_upgrade_bundle_shared_state_probe: %s\n' "$*" >&2; exit 1; }
ok() { printf '[ok] %s\n' "$*"; }

bash -n "$BUNDLE" || fail 'upgrade-bundle.sh 语法错误'
grep -q '^verify_shared_state_namespace() {' "$BUNDLE" || fail 'upgrade-bundle.sh 缺少 verify_shared_state_namespace'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---------------------------------------------------------------------------
# 取出被测函数，连同它依赖的 dotenv 读取函数，放进一个 harness
# ---------------------------------------------------------------------------
extract() { sed -n "/^$1() {/,/^}/p" "$BUNDLE"; }
{
  extract parse_literal_dotenv_value
  extract read_literal_dotenv_key
  extract shared_state_setting
  extract verify_shared_state_namespace
} >"$tmp/functions.sh"
for fn in parse_literal_dotenv_value read_literal_dotenv_key shared_state_setting verify_shared_state_namespace; do
  grep -q "^$fn() {" "$tmp/functions.sh" || fail "无法从 upgrade-bundle.sh 取出 $fn"
done

# 假 compose：记录每次调用；行为由环境变量控制
cat >"$tmp/compose-stub.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_LOG"
case "$*" in
  "ps -q redis")
if [[ -f "$STUB_LOG.up" ]]; then echo "${STUB_PS_AFTER_UP:-redis-container}"; else echo "${STUB_PS-redis-container}"; fi ;;
  "up -d --no-deps redis") : >"$STUB_LOG.up" ;;
  "exec -T redis redis-cli"*)
    n=0; [[ -f "$STUB_LOG.exec" ]] && n="$(<"$STUB_LOG.exec")"; n=$((n + 1)); printf '%s' "$n" >"$STUB_LOG.exec"
    if (( n <= ${STUB_FAIL_TIMES:-0} )); then printf 'Could not connect to Redis at 127.0.0.1:6379: Connection refused\n'; exit 1; fi
    printf '%s\n' "${STUB_PROBE_OUTPUT:-PONG}" ;;
esac
exit 0
STUB
chmod +x "$tmp/compose-stub.sh"

# 跑一次探测。参数：.env 内容；其余通过环境变量传入。输出 "rc|stdout+stderr"，并留下 $tmp/compose.log。
run_probe() {
  local env_content="$1" out rc
  rm -f "$tmp/compose.log" "$tmp/compose.log.up" "$tmp/compose.log.exec"
  mkdir -p "$tmp/work"
  printf '%s' "$env_content" >"$tmp/work/.env"
  set +e
  out="$(cd "$tmp/work" && STUB_LOG="$tmp/compose.log" timeout 60 bash -c '
    set -Eeuo pipefail
    SCRIPT_DIR="$1"; EXISTING_PROJECT_NAME=customer; NEW_COMPOSE_ARGS=("$2")
    log() { printf "%s\n" "$*"; }
    fail() { echo "[error] $*" >&2; exit 1; }
    source "$3"
    verify_shared_state_namespace
  ' _ "$tmp/work" "$tmp/compose-stub.sh" "$tmp/functions.sh" 2>&1 </dev/null)"
  rc=$?
  set -e
  printf '%s|%s' "$rc" "$out"
}

compose_calls() { [[ -f "$tmp/compose.log" ]] && cat "$tmp/compose.log" || true; }

# 1. 成功路径：用 .env 里的口令，默认 DB 3，探测命令形态与 upgrade.sh 一致
res="$(run_probe $'REDIS_PASSWORD=pw123\n')"
[[ "$res" == 0\|* ]] || fail "成功路径应通过：$res"
[[ "$res" == *"valkey DB 3 应答 PONG"* ]] || fail "成功路径应记录 PONG：$res"
grep -qxF 'exec -T redis redis-cli --no-auth-warning -a pw123 -n 3 ping' "$tmp/compose.log" || fail "探测命令不对：$(compose_calls)"
! grep -q '^up ' "$tmp/compose.log" || fail "valkey 已在运行时不应再 up"
ok "成功路径：exec redis-cli -n 3 ping 得到 PONG 即通过，口令取自 .env"

# 2. REQUIRED=false：跳过，不碰 valkey
res="$(run_probe $'REDIS_PASSWORD=pw123\nSECURITY_SHARED_STATE_REQUIRED=false\n')"
[[ "$res" == 0\|* && "$res" == *"跳过 valkey DB 探测"* ]] || fail "REQUIRED=false 应跳过：$res"
[[ -z "$(compose_calls)" ]] || fail "REQUIRED=false 不应调用 compose：$(compose_calls)"
# 进程环境优先于 .env（与 compose 插值一致）
res="$(SECURITY_SHARED_STATE_REQUIRED=false run_probe $'REDIS_PASSWORD=pw123\nSECURITY_SHARED_STATE_REQUIRED=true\n')"
[[ "$res" == 0\|* && "$res" == *"跳过"* ]] || fail "环境变量应覆盖 .env：$res"
ok "REQUIRED=false 跳过探测；进程环境优先于 .env"

# 3. DB 编号可配置，且必须是数字
run_probe $'REDIS_PASSWORD=pw123\nSECURITY_SHARED_STATE_DB=5\n' >/dev/null
grep -qxF 'exec -T redis redis-cli --no-auth-warning -a pw123 -n 5 ping' "$tmp/compose.log" || fail "没有按 SECURITY_SHARED_STATE_DB=5 探测：$(compose_calls)"
res="$(run_probe $'REDIS_PASSWORD=pw123\nSECURITY_SHARED_STATE_DB=abc\n')"
[[ "$res" == 1\|* && "$res" == *"SECURITY_SHARED_STATE_DB 必须是数字"* ]] || fail "非数字 DB 应失败：$res"
ok "SECURITY_SHARED_STATE_DB 生效，非数字被拒绝"

# 4. 失败路径：valkey 不可用 → 中止，报错可操作，不泄露口令
res="$(SHARED_STATE_PROBE_TIMEOUT=0 STUB_PROBE_OUTPUT='Could not connect to Redis at redis:6379: Connection refused (pw123)' run_probe $'REDIS_PASSWORD=pw123\n')"
[[ "$res" == 1\|* ]] || fail "valkey 不可用时必须中止升级（退出非 0）：$res"
for needle in '共享状态探测' 'valkey DB 3 不可用' 'Connection refused' 'SECURITY_SHARED_STATE_REQUIRED=true' '升级已中止' 'docker logs customer-redis-1' 'REDIS_PASSWORD' 'SECURITY_SHARED_STATE_DB' '重新执行升级'; do
  [[ "$res" == *"$needle"* ]] || fail "报错缺少可操作信息 '$needle'：$res"
done
[[ "$res" != *pw123* ]] || fail "报错泄露了 REDIS_PASSWORD：$res"
ok "valkey 不可用时中止升级；报错含探测输出与三步修复指引，且屏蔽口令"

res="$(SHARED_STATE_PROBE_TIMEOUT=0 STUB_PROBE_OUTPUT='ERR DB index is out of range' run_probe $'REDIS_PASSWORD=pw123\n')"
[[ "$res" == 1\|* && "$res" == *"out of range"* ]] || fail "DB 3 不可用（越界）应中止：$res"
ok "DB 不在 valkey databases 范围内时中止"

# 5. 配置缺失 / 非法：先于任何 compose 调用就失败
res="$(run_probe $'POSTGRES_PASSWORD=x\n')"
[[ "$res" == 1\|* && "$res" == *"REDIS_PASSWORD 为空"* ]] || fail "缺 REDIS_PASSWORD 应失败：$res"
[[ -z "$(compose_calls)" ]] || fail "缺口令时不应调用 compose"
res="$(run_probe $'REDIS_PASSWORD=a\nREDIS_PASSWORD=b\n')"
[[ "$res" == 1\|* && "$res" == *"REDIS_PASSWORD 重复或格式非法"* ]] || fail "重复的 REDIS_PASSWORD 应失败：$res"
ok "REDIS_PASSWORD 缺失或重复时直接失败，不调用 compose"

# 6. 刚启动的 valkey：有界重试直到 PONG
res="$(SHARED_STATE_PROBE_TIMEOUT=30 SHARED_STATE_PROBE_INTERVAL=0 STUB_FAIL_TIMES=2 run_probe $'REDIS_PASSWORD=pw123\n')"
[[ "$res" == 0\|* ]] || fail "前两次失败后应在重试中通过：$res"
[[ "$(<"$tmp/compose.log.exec")" == 3 ]] || fail "应探测 3 次：$(compose_calls)"
ok "valkey 刚启动时有界重试，第 3 次通过"

# 7. valkey 没在运行：先单独拉起再探测
res="$(STUB_PS='' run_probe $'REDIS_PASSWORD=pw123\n')"
[[ "$res" == 0\|* ]] || fail "valkey 未运行时应先拉起再探测：$res"
up_line="$(grep -n '^up -d --no-deps redis$' "$tmp/compose.log" | head -1 | cut -d: -f1)"
exec_line="$(grep -n '^exec -T redis redis-cli' "$tmp/compose.log" | head -1 | cut -d: -f1)"
[[ -n "$up_line" && -n "$exec_line" ]] && (( up_line < exec_line )) || fail "应先 up 再 exec：$(compose_calls)"
ok "valkey 未运行时先 up -d --no-deps redis 再探测"

# ---------------------------------------------------------------------------
# 接线：探测接在 Redis->Valkey 迁移之后、重建应用容器之前，并处在失败回滚区内
# ---------------------------------------------------------------------------
body="$(sed -n '/^run_in_place_upgrade() {/,/^}/p' "$BUNDLE")"
line_of() { printf '%s\n' "$body" | grep -n -- "$1" | head -1 | cut -d: -f1; }
switch_started="$(line_of 'IMAGE_SWITCH_STARTED=1')"
migrate="$(line_of 'migrate_redis_service_to_valkey')"
probe="$(line_of 'verify_shared_state_namespace')"
recreate="$(line_of 'up -d --force-recreate')"
for v in switch_started migrate probe recreate; do [[ -n "${!v}" ]] || fail "run_in_place_upgrade 里找不到 $v"; done
(( switch_started < probe )) || fail '探测必须在 IMAGE_SWITCH_STARTED=1 之后，失败才会触发回滚旧版本'
(( migrate < probe && probe < recreate )) || fail '探测必须在 Redis->Valkey 迁移之后、重建应用容器之前'
ok "接线：IMAGE_SWITCH_STARTED=1 < 迁移 < 探测 < up -d --force-recreate"

# ---------------------------------------------------------------------------
# CHANGELOG 如实：记载这项探测的版本段（“未发布”或某个已发布版本）要写清范围，不夸大。
# 这项探测随 2.9.15 发布。原先只看“未发布 + 最新版本段”，2.9.15 之后再发版时最新段不再是它，
# 每次发版都会失败；改为找出同时提到 upgrade-bundle.sh 和“共享状态”的那一段，再在同一段里核对范围。
# ---------------------------------------------------------------------------
probe_section="$(awk '
  /^## \[/ { if (in_sec && ub && ss) { printf "%s", buf; found = 1; exit }
             in_sec = 1; buf = ""; ub = 0; ss = 0 }
  in_sec { buf = buf $0 "\n"
           if (index($0, "upgrade-bundle.sh")) ub = 1
           if (index($0, "共享状态")) ss = 1 }
  END { if (!found && in_sec && ub && ss) printf "%s", buf }
' "$CHANGELOG")"
[[ -n "$probe_section" ]] ||
  fail 'CHANGELOG.md 没有任何版本段记录离线包升级器 upgrade-bundle.sh 新增的升级前共享状态探测'
# 不能写成“升级前最先做”这类夸大：探测发生在数据库迁移之后，必须如实写出
printf '%s\n' "$probe_section" | grep -q '数据库迁移' ||
  fail 'CHANGELOG.md 应如实写明探测发生在数据库迁移之后、迁移按既有机制保留'
ok "CHANGELOG.md 记载这项探测的版本段如实记录了离线包升级路径的升级前探测及其范围"

printf 'PASS test_upgrade_bundle_shared_state_probe\n'
