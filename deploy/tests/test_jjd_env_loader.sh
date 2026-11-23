#!/usr/bin/env bash
# 运维脚本读 .env 的安全性回归测试（11-08 客户现场事故）。
#
# 事故：.env 里 `REDIS_EXTRA_ARGS=--no-appendfsync-on-rewrite yes`（未加引号、含空格）。
# docker compose 把整行等号后面当值，运维脚本却 `source .env`，bash 把它当成
# “带环境变量 REDIS_EXTRA_ARGS 去执行命令 yes”——起一个无限输出的 yes，jjdctl status / rollback
# 卡死刷屏，输出重定向到文件时写满了现场根分区。
#
# 本测试覆盖四层：
#   A. 复现：对事故行直接 source 会无限输出 y（有界地验证，确认 fixture 真能复现）。
#   B. 共享加载函数 deploy/lib/jjd-env.sh 的语义（在 dash / bash / busybox ash 下各跑一遍）。
#   C. 真实脚本端到端：事故 .env 下 backup-db / ensure-*-tls / smoke-test / diagnose / jjdctl /
#      deploy-offline、deploy-oneclick 的 load_env / 打包器生成的 status.sh 都不卡住、读到值、不执行命令。
#   D. 防回归扫描：deploy/ 与 scripts/ 下不再有任何 `source .env` / `. ./.env` 式的裸读取。
# 所有可能无限输出的命令都带 timeout，并且只经管道 + head -c 限量，绝不把输出重定向到文件。
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/deploy/lib/jjd-env.sh"
DC_SRC="$ROOT/deploy/docker-compose"
CTL_SRC="$ROOT/deploy/offline-installer/jjdctl"
PACKAGER="$ROOT/deploy/docker-compose/package-offline-bundle.sh"

fail() { printf 'FAIL test_jjd_env_loader: %s\n' "$*" >&2; exit 1; }
ok() { printf '[ok] %s\n' "$*"; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mark="$tmp/mark"
mkdir -p "$mark"

[[ -f "$LIB" ]] || fail "缺少共享加载函数 $LIB"

# ---------------------------------------------------------------------------
# 事故 fixture
# ---------------------------------------------------------------------------
incident_env="$tmp/incident.env"
cat >"$incident_env" <<'ENV'
POSTGRES_USER=jjdguard
POSTGRES_DB=incidentdb
REDIS_EXTRA_ARGS=--no-appendfsync-on-rewrite yes
WEB_PORT=4242
ENV

# ---------------------------------------------------------------------------
# A. 复现：裸 source 事故行会无限输出（有界验证）
# ---------------------------------------------------------------------------
flood="$( { timeout 5 bash -c ". '$incident_env'" </dev/null 2>&1 | head -c 400; } || true)"
[[ "$flood" == *y* ]] || fail "fixture 没能复现事故：裸 source 事故 .env 应当跑起 yes 并输出 y"
ok "A 复现：裸 source 事故 .env 会起 yes 刷屏（已用 head -c 限量）"

# ---------------------------------------------------------------------------
# B. 加载函数语义
# ---------------------------------------------------------------------------
sem_env="$tmp/semantics.env"
cat >"$sem_env" <<'ENV'
# 注释行
   # 缩进的注释

REDIS_EXTRA_ARGS=--no-appendfsync-on-rewrite yes
export EXPORTED=1
  SPACED_KEY=indented
CMD_SUB=$(touch "@MARK@/pwn1")
BACKTICK=`touch "@MARK@/pwn2"`
SEMI=value; touch "@MARK@/pwn3"
AND=a && touch "@MARK@/pwn4"
PIPE=a | touch "@MARK@/pwn5"
VARREF=$HOME/x
BRACE=${HOME}
DQ="hello world"
SQ='single $x $(y)'
DQ_WITH_SQ="it's"
SQ_WITH_DQ='say "hi"'
UNBALANCED="oops
EMPTY_DQ=""
EMPTY_SQ=''
EMPTY=
DQ_COMMENT="quoted value" # trailing comment
PLAIN_COMMENT=plain value # trailing comment
HASH_NO_SPACE=a#b
INNER_QUOTE="pa"ss"
EQ=a=b=c
URL=postgres://u:p%40ss@db:5432/x?sslmode=disable&a=b
B64=YWJj==
JSON=["chat","responses"]
TRAIL_WS=value
DUP=first
DUP=second
LAST_NO_NEWLINE=tail
ENV
# 最后一行故意不带换行
printf %s 'NOEOL=last-line-without-newline' >>"$sem_env"
sed -i "s#@MARK@#$mark#g" "$sem_env"

expected_sem="$tmp/semantics.expected"
cat >"$expected_sem" <<EXP
REDIS_EXTRA_ARGS=[--no-appendfsync-on-rewrite yes]
EXPORTED=[1]
SPACED_KEY=[indented]
CMD_SUB=[\$(touch "$mark/pwn1")]
BACKTICK=[\`touch "$mark/pwn2"\`]
SEMI=[value; touch "$mark/pwn3"]
AND=[a && touch "$mark/pwn4"]
PIPE=[a | touch "$mark/pwn5"]
VARREF=[\$HOME/x]
BRACE=[\${HOME}]
DQ=[hello world]
SQ=[single \$x \$(y)]
DQ_WITH_SQ=[it's]
SQ_WITH_DQ=[say "hi"]
UNBALANCED=["oops]
EMPTY_DQ=[]
EMPTY_SQ=[]
EMPTY=[]
DQ_COMMENT=[quoted value]
PLAIN_COMMENT=[plain value]
HASH_NO_SPACE=[a#b]
INNER_QUOTE=[pa"ss]
EQ=[a=b=c]
URL=[postgres://u:p%40ss@db:5432/x?sslmode=disable&a=b]
B64=[YWJj==]
JSON=[["chat","responses"]]
TRAIL_WS=[value]
DUP=[second]
LAST_NO_NEWLINE=[tail]
NOEOL=[last-line-without-newline]
EXP

keys="REDIS_EXTRA_ARGS EXPORTED SPACED_KEY CMD_SUB BACKTICK SEMI AND PIPE VARREF BRACE DQ SQ DQ_WITH_SQ SQ_WITH_DQ UNBALANCED EMPTY_DQ EMPTY_SQ EMPTY DQ_COMMENT PLAIN_COMMENT HASH_NO_SPACE INNER_QUOTE EQ URL B64 JSON TRAIL_WS DUP LAST_NO_NEWLINE NOEOL"

print_values_body='for k in '"$keys"'; do eval "v=\${$k-<unset>}"; printf "%s=[%s]\n" "$k" "$v"; done'

shells=()
for candidate in dash bash; do
  command -v "$candidate" >/dev/null 2>&1 && shells+=("$candidate")
done
if command -v busybox >/dev/null 2>&1 && busybox sh -c ':' >/dev/null 2>&1; then
  shells+=("busybox sh")
fi
[[ ${#shells[@]} -ge 2 ]] || fail "至少需要 dash 与 bash 才能验证 POSIX sh 兼容"

for sh_cmd in "${shells[@]}"; do
  label="$sh_cmd"
  # shellcheck disable=SC2086
  out="$(HOME=/nonexistent-home-for-test timeout 20 $sh_cmd -c "set -eu; . '$LIB'; jjd_load_env_file '$sem_env' && $print_values_body" 2>"$tmp/sem.err" </dev/null)" ||
    fail "[$label] 加载语义用例执行失败: $(head -c 600 "$tmp/sem.err")"
  if [[ "$out" != "$(cat "$expected_sem")" ]]; then
    diff <(printf '%s\n' "$out") "$expected_sem" >&2 || true
    fail "[$label] 解析结果与预期不一致"
  fi
  # 不执行任何命令：标记目录必须保持为空
  if [[ -n "$(ls -A "$mark")" ]]; then
    fail "[$label] 加载 .env 时执行了命令：$(ls "$mark")"
  fi
  [[ ! -s "$tmp/sem.err" ]] || fail "[$label] 合法 .env 不应产生警告：$(head -c 400 "$tmp/sem.err")"
  ok "B [$label] 引号 / 等号 / 注释 / export / 缺换行 / \$() 反引号 分号 都按字面处理，没有执行命令"
done

# B2 事故行本身：timeout 内返回、值正确
for sh_cmd in "${shells[@]}"; do
  # shellcheck disable=SC2086
  out="$( { timeout 5 $sh_cmd -c "set -eu; . '$LIB'; jjd_load_env_file '$incident_env'; printf '%s|%s' \"\$REDIS_EXTRA_ARGS\" \"\$POSTGRES_DB\"" </dev/null 2>&1 | head -c 4096; } || true)"
  [[ "$out" == "--no-appendfsync-on-rewrite yes|incidentdb" ]] || fail "[$sh_cmd] 事故 .env 加载结果不对：$out"
done
ok "B 事故行 REDIS_EXTRA_ARGS=--no-appendfsync-on-rewrite yes 在 timeout 内读完，值完整保留"

# B3 非法行 / 保留名：警告并跳过，其余照常，不泄露值
bad_env="$tmp/bad.env"
cat >"$bad_env" <<'ENV'
GOOD1=ok
1BAD=leak-one
BAD-NAME=leak-two
bad name=leak-three
=leak-four
justtext-leak-five
IFS=,
ENV=hijack-leak-six
PS4=$(touch @MARK@/pwn6)
GOOD2=ok2
ENV
sed -i "s#@MARK@#$mark#g" "$bad_env"
for sh_cmd in "${shells[@]}"; do
  # shellcheck disable=SC2086
  out="$(ENV=original timeout 10 $sh_cmd -c "set -eu; . '$LIB'; jjd_load_env_file '$bad_env'; printf '%s|%s|%s|%s' \"\$GOOD1\" \"\$GOOD2\" \"\${ENV}\" \"\${IFS}\"" 2>"$tmp/bad.err" </dev/null | od -An -c | tr -s ' ' | tr -d '\n')" ||
    fail "[$sh_cmd] 含非法行的 .env 不应让加载失败: $(head -c 400 "$tmp/bad.err")"
  [[ "$out" == *"o k | o k 2 | o r i g i n a l |"* ]] || fail "[$sh_cmd] 合法变量或保留名保护异常：$out"
  for n in 2 3 4 5 6; do
    grep -q "第 $n 行" "$tmp/bad.err" || fail "[$sh_cmd] 缺少第 $n 行的警告：$(cat "$tmp/bad.err")"
  done
  for n in 7 8 9; do
    grep -q "第 $n 行" "$tmp/bad.err" || fail "[$sh_cmd] 缺少第 $n 行（保留名）的警告：$(cat "$tmp/bad.err")"
  done
  if grep -Eq 'leak-|hijack|touch' "$tmp/bad.err"; then
    fail "[$sh_cmd] 警告里泄露了 .env 的值：$(cat "$tmp/bad.err")"
  fi
  [[ -z "$(ls -A "$mark")" ]] || fail "[$sh_cmd] 保留名 PS4 的值被执行了"
done
ok "B 非法变量名 / 缺等号 / 保留名（IFS ENV PS4）给警告并跳过，其余变量照常，警告不含值"

# B4 CRLF
crlf_env="$tmp/crlf.env"
printf 'A=1\r\nB="two words"\r\nC=three words\r\n' >"$crlf_env"
for sh_cmd in "${shells[@]}"; do
  # shellcheck disable=SC2086
  out="$(timeout 10 $sh_cmd -c "set -eu; . '$LIB'; jjd_load_env_file '$crlf_env'; printf '%s|%s|%s' \"\$A\" \"\$B\" \"\$C\"" </dev/null)"
  [[ "$out" == "1|two words|three words" ]] || fail "[$sh_cmd] CRLF 行尾处理不对：$out"
done
ok "B CRLF 行尾被正确处理"

# B5 export / noexport，文件不可读
for sh_cmd in "${shells[@]}"; do
  # shellcheck disable=SC2086
  out="$(timeout 10 $sh_cmd -c "set -eu; . '$LIB'; jjd_load_env_file '$crlf_env'; sh -c 'printf \"%s\" \"\${A-unset}\"'" </dev/null)"
  [[ "$out" == 1 ]] || fail "[$sh_cmd] 默认应 export 给子进程，实际：$out"
  # shellcheck disable=SC2086
  out="$(timeout 10 $sh_cmd -c "set -eu; . '$LIB'; jjd_load_env_file '$crlf_env' noexport; printf '%s/' \"\$A\"; sh -c 'printf \"%s\" \"\${A-unset}\"'" </dev/null)"
  [[ "$out" == "1/unset" ]] || fail "[$sh_cmd] noexport 应只设 shell 变量，实际：$out"
  # noexport 模式下，带 `export ` 前缀的行仍然 export（与 source 一致；jjdctl 回滚夹具靠它把变量传给子进程）
  cat >"$tmp/exportprefix.env" <<'ENV'
export EXPORTED_LINE=yes
PLAIN_LINE=no
ENV
  cat >"$tmp/exportprefix-check.sh" <<'CHECK'
set -eu
. "$1"
jjd_load_env_file "$2" noexport
printf '%s/%s/' "$PLAIN_LINE" "$EXPORTED_LINE"
sh -c 'printf "%s/%s" "${EXPORTED_LINE-unset}" "${PLAIN_LINE-unset}"'
CHECK
  # shellcheck disable=SC2086
  out="$(timeout 10 $sh_cmd "$tmp/exportprefix-check.sh" "$LIB" "$tmp/exportprefix.env" </dev/null)"
  [[ "$out" == "no/yes/yes/unset" ]] || fail "[$sh_cmd] noexport 下 export 前缀应仍然 export、普通行不应 export，实际：$out"
  # shellcheck disable=SC2086
  rc=0
  timeout 10 $sh_cmd -c ". '$LIB'; jjd_load_env_file '$tmp/does-not-exist.env'" </dev/null >/dev/null 2>&1 || rc=$?
  [[ "$rc" == 1 ]] || fail "[$sh_cmd] 文件不存在应返回 1，实际 $rc"
done
ok "B export / noexport 语义正确，文件不可读返回 1"

# B6 升级警告：只列变量名和行号，不含值，不误报
warn_env="$tmp/warn.env"
cat >"$warn_env" <<'ENV'
PLAIN=single
SPACED=two words
QUOTED="quoted words"
SQUOTED='single quoted'
COMMENTED=x # a note
SECRET_PASS=has space secret
ENV
for sh_cmd in "${shells[@]}"; do
  # shellcheck disable=SC2086
  timeout 10 $sh_cmd -c ". '$LIB'; jjd_env_warn_unquoted_whitespace '$warn_env'" </dev/null 2>"$tmp/warn.err" ||
    fail "[$sh_cmd] 升级警告函数不应失败"
  grep -q '第 2 行 SPACED' "$tmp/warn.err" || fail "[$sh_cmd] 没有警告 SPACED：$(cat "$tmp/warn.err")"
  grep -q '第 6 行 SECRET_PASS' "$tmp/warn.err" || fail "[$sh_cmd] 没有警告 SECRET_PASS：$(cat "$tmp/warn.err")"
  [[ "$(grep -c '警告' "$tmp/warn.err")" == 2 ]] || fail "[$sh_cmd] 误报：$(cat "$tmp/warn.err")"
  if grep -Eq 'has space|secret$|two words' "$tmp/warn.err"; then
    fail "[$sh_cmd] 升级警告泄露了值：$(cat "$tmp/warn.err")"
  fi
done
ok "B 升级警告只指出含空格未加引号的变量名和行号，不含值、不误报"

# ---------------------------------------------------------------------------
# C. 真实脚本端到端（事故 .env）
# ---------------------------------------------------------------------------
site="$tmp/site"
dc="$site/deploy/docker-compose"
mkdir -p "$dc" "$site/deploy/lib" "$tmp/stubbin"
cp "$LIB" "$ROOT/deploy/lib/captcha-login.sh" "$site/deploy/lib/"

# 假的 compose-wrapper：只回显参数，永远成功
cat >"$dc/compose-wrapper.sh" <<'STUB'
#!/bin/sh
echo "stub-compose $*"
echo "$*" >>"$(dirname "$0")/calls.log"
STUB
# 假的 curl：记录 URL，永远成功
cat >"$tmp/stubbin/curl" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/curl.log"
STUB
chmod +x "$dc/compose-wrapper.sh" "$tmp/stubbin/curl"

write_site_env() {
  cat >"$dc/.env" <<ENV
POSTGRES_USER=incidentuser
POSTGRES_DB=incidentdb
REDIS_EXTRA_ARGS=--no-appendfsync-on-rewrite yes
BACKUP_DIR=$site/backups
WEB_PORT=4242
WEB_HTTPS_PORT=4343
GATEWAY_PORT=4444
TLS_DIR=$site/web-tls
GATEWAY_TLS_DIR=$site/gw-tls
CMD_SUB=\$(touch "$mark/pwn-site")
ENV
}
write_site_env
mkdir -p "$site/web-tls" "$site/gw-tls/guomi"
: >"$site/web-tls/web-console.crt"; : >"$site/web-tls/web-console.key"
: >"$site/gw-tls/gateway.crt"; : >"$site/gw-tls/gateway.key"
for f in sm2_ca.crt sm2_sign.crt sm2_sign.key sm2_enc.crt sm2_enc.key; do echo x >"$site/gw-tls/guomi/$f"; done

# 在事故 .env 下运行脚本：timeout + 管道限量；返回 "rc|输出"。
run_bounded() {
  local out
  out="$( { cd "${RUN_CWD:-$dc}" && PATH="$tmp/stubbin:$PATH" SMOKE_SKIP_LOGIN=true timeout "${RUN_TIMEOUT:-30}" "$@" </dev/null 2>&1 | head -c 200000; } || true)"
  printf '%s' "$out"
}

assert_no_flood() {
  local name="$1" out="$2" ys
  ys="$(printf '%s\n' "$out" | grep -cx 'y' || true)"
  (( ys < 5 )) || fail "$name：输出里出现 y 刷屏（$ys 行）——脚本又在 source .env 了"
}

check_script() { # name, expected substring, command...
  local name="$1" needle="$2"; shift 2
  local out
  out="$(run_bounded "$@")"
  assert_no_flood "$name" "$out"
  [[ "$out" == *"$needle"* ]] || fail "$name：没有读到 .env 里的值或脚本没正常跑完（期望含 '$needle'），输出：$(printf '%s' "$out" | head -c 600)"
  [[ -z "$(ls -A "$mark")" ]] || fail "$name：执行了 .env 里的命令：$(ls "$mark")"
  ok "C $name：事故 .env 下 30 秒内正常结束，值读对了，没有执行命令"
}

# backup-db.sh：POSTGRES_DB / BACKUP_DIR 来自 .env
cp "$DC_SRC/backup-db.sh" "$dc/"
check_script backup-db.sh "incidentdb" sh "$dc/backup-db.sh"
ls "$site/backups"/jjdguard-incidentdb-*.sql >/dev/null 2>&1 || fail "backup-db.sh：备份文件没有按 .env 的 BACKUP_DIR / POSTGRES_DB 落盘"

# ensure-*-tls.sh：证书目录来自 .env，已存在即退出 0
cp "$DC_SRC/ensure-web-tls.sh" "$DC_SRC/ensure-gateway-tls.sh" "$DC_SRC/ensure-guomi-tls.sh" "$dc/"
check_script ensure-web-tls.sh "already exists" sh "$dc/ensure-web-tls.sh"
check_script ensure-gateway-tls.sh "证书已存在" sh "$dc/ensure-gateway-tls.sh"
check_script ensure-guomi-tls.sh "already exist" sh "$dc/ensure-guomi-tls.sh"

# smoke-test.sh：端口来自 .env，经假 curl 记录
cp "$DC_SRC/smoke-test.sh" "$dc/"
: >"$tmp/curl.log"
check_script smoke-test.sh "all health endpoints returned success" sh "$dc/smoke-test.sh" 127.0.0.1
grep -q 'http://127.0.0.1:4242/health' "$tmp/curl.log" || fail "smoke-test.sh：没有按 .env 的 WEB_PORT=4242 探测：$(cat "$tmp/curl.log")"
grep -q 'https://127.0.0.1:4343/health' "$tmp/curl.log" || fail "smoke-test.sh：没有按 .env 的 WEB_HTTPS_PORT=4343 探测"

# diagnose.sh：只读采集，端口来自 .env（用假工具保证不依赖现场环境）
cp "$DC_SRC/diagnose.sh" "$dc/"
RUN_TIMEOUT=90 check_script diagnose.sh "控制台 HTTP:4242" sh "$dc/diagnose.sh"

# scripts/security/*.sh：运维对账 / 重分类脚本（compose 目录默认 ../../deploy/docker-compose）
mkdir -p "$site/scripts/security"
for s in alert_volume_reconcile reclassify_single_bom_events reclassify_passive_semantic_alerts reclassify_suspicious_semantic_events; do
  cp "$ROOT/scripts/security/$s.sh" "$site/scripts/security/"
  : >"$dc/calls.log"
  case "$s" in
    alert_volume_reconcile) RUN_CWD="$site/scripts/security" check_script "scripts/security/$s.sh" "" sh "./$s.sh" 2026-01-01T00:00:00Z ;;
    *) RUN_CWD="$site/scripts/security" check_script "scripts/security/$s.sh" "" sh "./$s.sh" ;;
  esac
  grep -q 'incidentuser' "$dc/calls.log" || fail "scripts/security/$s.sh：没有按 .env 的 POSTGRES_USER 访问数据库：$(cat "$dc/calls.log")"
done

# jjdctl：载入脚本本体（去掉末尾 main），用假 compose，走 main status 与 start_rollback_release
site_ctl="$site/jjdctl"
sed '/^main "\$@"$/d' "$CTL_SRC" >"$site_ctl"
cp "$dc/.env" "$dc/.env.bak"
touch "$dc/docker-compose.offline.yml"
ctl_out="$( { cd "$site" && timeout 30 bash -c '
  set -Eeuo pipefail
  source "$1"
  need_root() { :; }
  compose() { printf "compose[%s] " "$REDIS_EXTRA_ARGS"; }
  status_cmd() { printf "status:%s:%s" "$REDIS_EXTRA_ARGS" "$POSTGRES_DB"; }
  main status
  echo
  rolled="$2/prev"
  mkdir -p "$rolled/deploy/docker-compose"
  cp "$2/deploy/docker-compose/.env" "$rolled/deploy/docker-compose/.env"
  : >"$rolled/deploy/docker-compose/docker-compose.offline.yml"
  ROLLBACK_START_TIMEOUT=5 ROLLBACK_START_INTERVAL=1 start_rollback_release "$rolled"
' _ "$site_ctl" "$site" </dev/null 2>&1 | head -c 20000; } || true)"
assert_no_flood "jjdctl" "$ctl_out"
[[ "$ctl_out" == *"status:--no-appendfsync-on-rewrite yes:incidentdb"* ]] || fail "jjdctl main status 没有按字面读到 .env：$(printf '%s' "$ctl_out" | head -c 800)"
[[ "$ctl_out" == *"compose[--no-appendfsync-on-rewrite yes]"* ]] || fail "jjdctl start_rollback_release 没有读到回滚目标的 .env：$(printf '%s' "$ctl_out" | head -c 800)"
[[ -z "$(ls -A "$mark")" ]] || fail "jjdctl 执行了 .env 里的命令"
ok "C jjdctl：main status 与 start_rollback_release 在事故 .env 下都不卡住，值读对了"

# deploy-offline.sh / deploy-oneclick.sh 的 load_env
for installer in deploy-offline.sh deploy-oneclick.sh; do
  body="$(sed -n '/^load_env() {/,/^}/p' "$DC_SRC/$installer")"
  [[ -n "$body" ]] || fail "$installer 找不到 load_env"
  out="$( { cd "$dc" && timeout 20 sh -c '
    set -eu
    SCRIPT_DIR="$1"
    ENV_FILE="$2"
    . "$3"
    detect_hosts_csv() { echo 10.9.9.9; }
    default_package_version() { echo 0.0.0-test; }
    default_commit() { echo test-commit; }
    default_built_at() { echo test-built-at; }
    '"$body"'
    load_env
    printf "%s|%s|%s" "$REDIS_EXTRA_ARGS" "$POSTGRES_DB" "$WEB_HTTPS_PORT"
  ' _ "$dc" "$dc/.env" "$site/deploy/lib/jjd-env.sh" </dev/null 2>&1 | head -c 4000; } || true)"
  assert_no_flood "$installer load_env" "$out"
  [[ "$out" == *"--no-appendfsync-on-rewrite yes|incidentdb|4343"* ]] || fail "$installer load_env 没有按字面读 .env：$(printf '%s' "$out" | head -c 600)"
  [[ -z "$(ls -A "$mark")" ]] || fail "$installer load_env 执行了 .env 里的命令"
done
ok "C deploy-offline.sh / deploy-oneclick.sh 的 load_env 读事故 .env 不卡住、不执行命令"

# 打包器生成的 status.sh（随包的现场状态脚本）
status_body="$(sed -n '/^write_status_script() {/,/^}/p' "$PACKAGER")"
[[ -n "$status_body" ]] || fail "打包器找不到 write_status_script"
bundle="$tmp/bundle"
mkdir -p "$bundle/deploy/docker-compose" "$bundle/deploy/lib"
cp "$LIB" "$bundle/deploy/lib/"
cp "$dc/.env" "$bundle/deploy/docker-compose/.env"
cp "$dc/compose-wrapper.sh" "$bundle/deploy/docker-compose/"
printf '#!/bin/sh\necho "stub-smoke web=$WEB_PORT extra=$REDIS_EXTRA_ARGS"\n' >"$bundle/deploy/docker-compose/smoke-test.sh"
bash -c "BUNDLE_DIR='$bundle'; $status_body; write_status_script"
out="$( { cd "$bundle" && timeout 20 sh ./status.sh </dev/null 2>&1 | head -c 4000; } || true)"
assert_no_flood "status.sh" "$out"
[[ "$out" == *"stub-smoke web=4242 extra=--no-appendfsync-on-rewrite yes"* ]] || fail "随包 status.sh 没有按字面读 .env：$(printf '%s' "$out" | head -c 600)"
ok "C 打包器生成的 status.sh 读事故 .env 不卡住，值经 export 传给子进程"

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# D. 防回归扫描：不允许再有裸读取 .env
# ---------------------------------------------------------------------------
# 裸读取的写法：source / `.` 后面跟 .env、$ENV、$ENV_FILE、"$DC_DIR/.env" 之类。
# 不在扫描范围（读的不是产品 .env）：
#   deploy/tests/        测试自己造的 env
#   directory-sim/       home 身份仿真环境自己生成的 env
#   /etc/jjdguard/install.env、last-upgrade.env 这类状态文件（安装器自己写、值是路径，名字不是 ENV/ENV_FILE，不会命中）
scan_raw_env_source() { # 目录...
  grep -rnIE '(^|[;&|({[:space:]])(source|\.)[[:space:]]+["'"'"']?(\./)?(\$\{?[A-Za-z_]*(ENV|ENV_FILE|env_file)\}?|[^[:space:]"'"'"']*\.env)["'"'"']?([[:space:];]|$)' \
    "$@" --include='*.sh' --include='jjdctl' --exclude-dir=node_modules --exclude-dir=tests --exclude-dir=directory-sim 2>/dev/null |
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true
}

# 先证明扫描本身有效：这些写法必须被命中
sample="$tmp/scan-sample"
mkdir -p "$sample"
cat >"$sample/bad.sh" <<'SAMPLE'
set -a
. ./.env
. "$DC_DIR/.env" 2>/dev/null || true
source "$ENV"
. "$ENV_FILE"
if [ -f ./.env ]; then set -a; . ./.env; set +a; fi
SAMPLE
cat >"$sample/fine.sh" <<'SAMPLE'
. "$JJD_ENV_LIB"
. "$SCRIPT_DIR/../lib/jjd-env.sh"
source "$LAST_UPGRADE"
# . ./.env 注释里的不算
SAMPLE
hits="$(cd "$sample" && scan_raw_env_source . | cut -d: -f1,2 | sort -u | tr '\n' ' ')"
[[ "$hits" == "./bad.sh:2 ./bad.sh:3 ./bad.sh:4 ./bad.sh:5 ./bad.sh:6 " ]] || fail "防回归扫描自检失败：$hits"

scan_hits="$(cd "$ROOT" && scan_raw_env_source deploy scripts)"
if [[ -n "$scan_hits" ]]; then
  printf '%s\n' "$scan_hits" >&2
  fail "仍有脚本裸 source .env（应改用 deploy/lib/jjd-env.sh 的 jjd_load_env_file）"
fi
ok "D deploy/ 与 scripts/ 下没有裸 source .env 的写法（扫描自检通过）"

# ---------------------------------------------------------------------------
# E. 升级器：.env 里含空格且未加引号的值只给警告，不改客户 .env，不泄露值
# ---------------------------------------------------------------------------
for upgrader in upgrade.sh upgrade-bundle.sh; do
  body="$(sed -n '/^warn_unquoted_env_whitespace() {/,/^}/p' "$DC_SRC/$upgrader")"
  [[ -n "$body" ]] || fail "$upgrader 缺少 warn_unquoted_env_whitespace"
  grep -qE '^[[:space:]]*warn_unquoted_env_whitespace "' "$DC_SRC/$upgrader" || fail "$upgrader 没有调用 warn_unquoted_env_whitespace"
  before="$(sha256sum "$incident_env")"
  err="$(timeout 10 bash -c 'set -Eeuo pipefail; . "$1"; '"$body"'; warn_unquoted_env_whitespace "$2"' _ "$LIB" "$incident_env" 2>&1 >/dev/null </dev/null)"
  [[ "$err" == *"第 3 行 REDIS_EXTRA_ARGS"* ]] || fail "$upgrader 没有对事故行给出警告：$err"
  [[ "$err" != *appendfsync* ]] || fail "$upgrader 的警告泄露了值：$err"
  [[ "$(sha256sum "$incident_env")" == "$before" ]] || fail "$upgrader 修改了 .env"
  # 共享库缺失（精简包）时静默跳过，不影响升级
  err="$(timeout 10 bash -c 'set -Eeuo pipefail; '"$body"'; warn_unquoted_env_whitespace "$1"; echo rc=$?' _ "$incident_env" 2>&1 </dev/null)"
  [[ "$err" == "rc=0" ]] || fail "$upgrader 在缺少共享库时应静默跳过：$err"
done
ok "E upgrade.sh / upgrade-bundle.sh 对含空格未加引号的值只警告（变量名+行号），不改 .env、不含值、缺库时静默"

printf 'PASS test_jjd_env_loader\n'
