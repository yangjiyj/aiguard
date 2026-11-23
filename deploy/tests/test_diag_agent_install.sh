#!/usr/bin/env bash
# 诊断采集器安装/卸载契约测试：全部在一次性 alpine 容器内完成，仓库只读挂载，
# 不触碰宿主机的 /etc、/opt、/var/lib，也不启动任何真实容器。
set -Eeuo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
IMAGE="${DIAG_TEST_IMAGE:-alpine:3.22}"

command -v docker >/dev/null 2>&1 || { echo "SKIP test_diag_agent_install: 无 docker"; exit 0; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "SKIP test_diag_agent_install: 缺少镜像 $IMAGE"; exit 0; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/diag-install-test.XXXXXX")"
cleanup() {
  docker run --rm -v "$WORK:/work" "$IMAGE" sh -c 'rm -rf /work/* /work/.[!.]*' >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

cat >"$WORK/inner.sh" <<'INNER'
set -eu
SRC=/repo/deploy/diag-agent
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
mode() { stat -c '%a' "$1"; }
owner() { stat -c '%u:%g' "$1"; }

apk add --no-cache util-linux >/dev/null 2>&1 || true   # 提供 flock；失败也不影响（busybox 自带）

# 假二进制 + 假 systemctl + 假 compose-wrapper
mkdir -p /fake /work/bin
printf '#!/bin/sh\nexit 0\n' >/fake/jjdguard-diag-agent; chmod 755 /fake/jjdguard-diag-agent
cat >/work/bin/systemctl <<'EOS'
#!/bin/sh
echo "$*" >>/work/systemctl.log
EOS
chmod 755 /work/bin/systemctl

make_deploy() {   # $1=目录 $2=基础 compose 是否已含诊断挂载(1/0)
  d="$1"; rm -rf "$d"; mkdir -p "$d/.upgrade" "$d/active-config/20261024"
  printf 'POSTGRES_USER=jjd\nCOMPOSE_PROJECT_NAME=jjdprod\nDIAG_AGENT_HMAC_KEY=old\nOTHER=1\n' >"$d/.env"
  chmod 600 "$d/.env"
  if [ "$2" = 1 ]; then
    printf 'services:\n  control-plane:\n    volumes:\n      - /var/lib/jjdguard/diag/inbox:/var/lib/jjdguard/diag/inbox\n' >"$d/docker-compose.offline.yml"
  else
    printf 'services:\n  control-plane:\n    image: x\n' >"$d/docker-compose.offline.yml"
  fi
  printf 'services:\n  gateway-core:\n    image: y\n' >"$d/active-config/20261024/release-images.override.yml"
  chmod 600 "$d/active-config/20261024/release-images.override.yml"
  printf '%s\n' "$d/active-config/20261024/release-images.override.yml" >"$d/.upgrade/compose-files"
  printf '%s\n' "$d" >"$d/.upgrade/project-directory"
  printf 'jjdprod\n' >"$d/.upgrade/project-name"
  chmod 600 "$d/.upgrade/"*
  cat >"$d/compose-wrapper.sh" <<'EOS'
#!/bin/sh
echo "$@" >>/work/compose-wrapper.log
EOS
}

run_install() { PATH="/work/bin:$PATH" sh "$SRC/install-diag-agent.sh" "$@"; }
run_uninstall() { PATH="/work/bin:$PATH" sh "$SRC/uninstall-diag-agent.sh" "$@"; }

check_common() {
  d="$1"
  [ -f /etc/jjdguard/diag-agent.key ] || fail "密钥不存在"
  [ "$(mode /etc/jjdguard/diag-agent.key)" = 600 ] || fail "密钥权限应为 600"
  [ "$(owner /etc/jjdguard/diag-agent.key)" = 0:0 ] || fail "密钥属主应为 root"
  [ "$(wc -c </etc/jjdguard/diag-agent.key | tr -d ' ')" = 64 ] || fail "密钥应为 64 位 hex"
  grep -Eq '^[0-9a-f]{64}$' /etc/jjdguard/diag-agent.key || fail "密钥应为小写 hex"
  [ -x /usr/local/bin/jjdguard-diag-agent ] || fail "二进制未安装"
  for s in snapshot outbox; do
    [ "$(mode /var/lib/jjdguard/diag/$s)" = 755 ] || fail "$s 权限应为 755"
    [ "$(owner /var/lib/jjdguard/diag/$s)" = 0:0 ] || fail "$s 属主应为 root"
  done
  [ "$(mode /var/lib/jjdguard/diag/inbox)" = 770 ] || fail "inbox 权限应为 770"
  [ "$(owner /var/lib/jjdguard/diag/inbox)" = 0:101 ] || fail "inbox 应为 root:101"
  [ "$(mode /var/lib/jjdguard/diag/state)" = 700 ] || fail "state 权限应为 700"
  [ "$(grep -c '^DIAG_AGENT_HMAC_KEY=' "$d/.env")" = 1 ] || fail ".env 中 DIAG_AGENT_HMAC_KEY 应恰好一行"
  [ "$(sed -n 's/^DIAG_AGENT_HMAC_KEY=//p' "$d/.env")" = "$(cat /etc/jjdguard/diag-agent.key)" ] || fail ".env 密钥与密钥文件不一致"
  grep -q '^OTHER=1$' "$d/.env" && grep -q '^COMPOSE_PROJECT_NAME=jjdprod$' "$d/.env" || fail "其它 .env 键被破坏"
  [ "$(mode "$d/.env")" = 600 ] || fail ".env 权限被改变"
}

snap() { find /etc/jjdguard /usr/local/bin/jjdguard-diag-agent /var/lib/jjdguard /etc/cron.d /etc/systemd "$1" -type f 2>/dev/null -exec sh -c 'for f; do printf "%s %s %s\n" "$f" "$(stat -c %a:%u:%g "$f")" "$(cksum <"$f")"; done' sh {} + | sort; }

############ 场景 1：systemd + 基础 compose 不含挂载（需要 override）
D=/work/dc1
make_deploy $D 0
mkdir -p /run/systemd/system
run_install --deploy-dir $D --binary /fake/jjdguard-diag-agent >/tmp/o1 2>&1 || { cat /tmp/o1; fail "首次 install 失败"; }
check_common $D
[ -f /etc/systemd/system/jjdguard-diag-agent.service ] || fail "unit 未安装"
grep -q "^ExecStart=/usr/local/bin/jjdguard-diag-agent --dir /var/lib/jjdguard/diag --key-file /etc/jjdguard/diag-agent.key --deploy-dir $D$" /etc/systemd/system/jjdguard-diag-agent.service || fail "ExecStart 不对"
grep -q '^ReadWritePaths=/var/lib/jjdguard/diag$' /etc/systemd/system/jjdguard-diag-agent.service || fail "ReadWritePaths 不对"
! grep -q '@' /etc/systemd/system/jjdguard-diag-agent.service || fail "unit 仍有未替换占位符"
grep -q 'daemon-reload' /work/systemctl.log && grep -q 'enable --now jjdguard-diag-agent.service' /work/systemctl.log || fail "systemctl 调用不对"
[ ! -e /etc/cron.d/jjdguard-diag-agent ] || fail "systemd 分支不应有 cron"
OV=$D/active-config/diag-agent.override.yml
[ -f $OV ] && [ "$(mode $OV)" = 600 ] || fail "override 缺失或权限不是 600"
grep -q 'DIAG_AGENT_HMAC_KEY' $OV && grep -q 'diag/inbox:/var/lib/jjdguard/diag/inbox' $OV || fail "override 内容不对"
[ "$(tail -n 1 $D/.upgrade/compose-files)" = "$OV" ] || fail "override 未追加到 compose-files 末尾"
[ "$(grep -c . $D/.upgrade/compose-files)" = 2 ] || fail "compose-files 行数应为 2"
[ "$(mode $D/.upgrade/compose-files)" = 600 ] || fail "compose-files 权限被改变"
grep -q '控制面重启后生效' /tmp/o1 || fail "缺少生效提示"
[ ! -e /work/compose-wrapper.log ] || fail "默认不应重建容器"
pass "systemd 首次安装（文件、权限、.env、override）"

S1="$(snap $D)"
run_install --deploy-dir $D --binary /fake/jjdguard-diag-agent >/tmp/o1b 2>&1 || fail "第二次 install 失败"
S2="$(snap $D)"
[ "$S1" = "$S2" ] || { echo "$S1" >/tmp/s1; echo "$S2" >/tmp/s2; diff /tmp/s1 /tmp/s2 || true; fail "重复执行结果不一致"; }
[ "$(grep -c . $D/.upgrade/compose-files)" = 2 ] || fail "重复安装后 compose-files 行数变化"
pass "幂等（两次结果逐文件一致）"

# 密钥保留
K1="$(cat /etc/jjdguard/diag-agent.key)"
run_install --deploy-dir $D --binary /fake/jjdguard-diag-agent >/dev/null 2>&1
[ "$K1" = "$(cat /etc/jjdguard/diag-agent.key)" ] || fail "密钥被重新生成"
pass "已有密钥保留"

# --apply
: >/work/compose-wrapper.log; rm -f /work/compose-wrapper.log
run_install --deploy-dir $D --binary /fake/jjdguard-diag-agent --apply >/tmp/o1c 2>&1 || { cat /tmp/o1c; fail "--apply 失败"; }
L="$(cat /work/compose-wrapper.log)"
EXP="--project-name jjdprod --project-directory $D --env-file .env -f docker-compose.offline.yml -f $D/active-config/20261024/release-images.override.yml -f $OV up -d --no-deps --force-recreate control-plane"
[ "$L" = "$EXP" ] || { echo "实际: $L"; echo "期望: $EXP"; fail "--apply 的 compose 参数不对"; }
pass "--apply 只重建 control-plane，参数与开机链一致"

# 卸载（不 purge）
run_uninstall --deploy-dir $D >/tmp/u1 2>&1 || { cat /tmp/u1; fail "uninstall 失败"; }
[ ! -e /etc/systemd/system/jjdguard-diag-agent.service ] || fail "unit 未删除"
[ ! -e /usr/local/bin/jjdguard-diag-agent ] || fail "二进制未删除"
[ ! -e /var/lib/jjdguard/diag ] || fail "诊断目录未删除"
[ -f /etc/jjdguard/diag-agent.key ] || fail "非 purge 不应删除密钥"
grep -q '^DIAG_AGENT_HMAC_KEY=' $D/.env || fail "非 purge 不应改 .env"
[ -f $OV ] || fail "非 purge 不应删 override"
grep -q 'disable --now' /work/systemctl.log || fail "未停止并禁用服务"
pass "卸载（保留密钥与 .env）"
run_uninstall --deploy-dir $D --purge >/tmp/u2 2>&1 || { cat /tmp/u2; fail "uninstall --purge 失败"; }
[ ! -e /etc/jjdguard/diag-agent.key ] || fail "purge 未删除密钥"
! grep -q 'DIAG_AGENT_HMAC_KEY' $D/.env || fail "purge 未清理 .env"
grep -q '^OTHER=1$' $D/.env || fail "purge 破坏了其它 .env 键"
[ ! -e $OV ] || fail "purge 未删 override"
[ "$(cat $D/.upgrade/compose-files)" = "$D/active-config/20261024/release-images.override.yml" ] || fail "purge 后 compose-files 应只剩原条目"
pass "卸载 --purge（密钥、.env 键、override、compose-files 条目全部清理）"

############ 场景 2：基础 compose 已含挂载 -> 不生成 override
D=/work/dc2
make_deploy $D 1
run_install --deploy-dir $D --binary /fake/jjdguard-diag-agent >/tmp/o2 2>&1 || { cat /tmp/o2; fail "场景2 install 失败"; }
check_common $D
[ ! -e $D/active-config/diag-agent.override.yml ] || fail "基础已含挂载时不应生成 override"
[ "$(grep -c . $D/.upgrade/compose-files)" = 1 ] || fail "compose-files 不应变化"
run_uninstall --deploy-dir $D --purge >/dev/null 2>&1
pass "基础 compose 已含挂载：不生成 override"

############ 场景 3：升级后 override 被收口为 inherited-NNN.yml，purge 仍能按标记清理
D=/work/dc3
make_deploy $D 0
run_install --deploy-dir $D --binary /fake/jjdguard-diag-agent >/dev/null 2>&1
mv $D/active-config/diag-agent.override.yml $D/active-config/20261024/inherited-001.yml
sed -i "s#active-config/diag-agent.override.yml#active-config/20261024/inherited-001.yml#" $D/.upgrade/compose-files
run_uninstall --deploy-dir $D --purge >/dev/null 2>&1
[ ! -e $D/active-config/20261024/inherited-001.yml ] || fail "收口后的 override 未被清理"
[ "$(grep -c . $D/.upgrade/compose-files)" = 1 ] || fail "收口后的 compose-files 条目未清理"
pass "升级收口后的 override 仍可被 --purge 识别"

############ 场景 4：无 systemd -> cron
rm -rf /run/systemd /work/bin/systemctl /etc/jjdguard /var/lib/jjdguard /usr/local/bin/jjdguard-diag-agent /etc/systemd
D=/work/dc4
make_deploy $D 1
run_install --deploy-dir $D --binary /fake/jjdguard-diag-agent >/tmp/o4 2>&1 || { cat /tmp/o4; fail "无 systemd install 失败"; }
check_common $D
[ ! -e /etc/systemd/system/jjdguard-diag-agent.service ] || fail "无 systemd 不应装 unit"
C=/etc/cron.d/jjdguard-diag-agent
[ -f $C ] && [ "$(mode $C)" = 644 ] || fail "cron 文件缺失或权限不是 644"
grep -Eq "^\* \* \* \* \* root .*/usr/local/bin/jjdguard-diag-agent --once --dir /var/lib/jjdguard/diag --key-file /etc/jjdguard/diag-agent.key --deploy-dir $D >/dev/null 2>&1$" $C || { cat $C; fail "cron 行不对"; }
C1="$(cksum <$C)"
run_install --deploy-dir $D --binary /fake/jjdguard-diag-agent >/dev/null 2>&1
[ "$C1" = "$(cksum <$C)" ] || fail "cron 重复安装不一致"
run_uninstall --deploy-dir $D >/dev/null 2>&1
[ ! -e $C ] || fail "cron 未删除"
[ ! -e /var/lib/jjdguard/diag ] || fail "无 systemd 卸载后目录残留"
pass "无 systemd：cron 安装、幂等、卸载"

############ 场景 5：参数错误
if run_install --deploy-dir /work/不存在 --binary /fake/jjdguard-diag-agent >/dev/null 2>&1; then fail "不存在的 deploy 目录应报错"; fi
if run_install --deploy-dir /work/dc4 --binary /fake/none >/dev/null 2>&1; then fail "缺少二进制应报错"; fi
if run_install --deploy-dir /work/dc4 --diag-dir '/var/lib/x y' --binary /fake/jjdguard-diag-agent >/dev/null 2>&1; then fail "非法 diag-dir 应报错"; fi
if run_uninstall --diag-dir /var >/dev/null 2>&1; then fail "过浅的 diag-dir 应拒绝"; fi
pass "参数校验"
############ 场景 6：经 current 软链传入部署目录（现场默认就是 /opt/jjdguard/current/...）
rm -rf /work/rel6 /work/cur6; make_deploy /work/rel6/dc 0; ln -s /work/rel6 /work/cur6
rm -f /etc/jjdguard/diag-agent.key
run_install --deploy-dir /work/cur6/dc --binary /fake/jjdguard-diag-agent >/dev/null
tail -n 1 /work/rel6/dc/.upgrade/compose-files | grep -Fxq /work/rel6/dc/active-config/diag-agent.override.yml \
  || fail "开机链条目应是真实路径，实际：$(tail -n 1 /work/rel6/dc/.upgrade/compose-files)"
if grep -Fq /work/cur6 /work/rel6/dc/.upgrade/compose-files; then fail "开机链不应出现软链路径"; fi
run_uninstall --deploy-dir /work/cur6/dc --purge >/dev/null
if grep -Fq diag-agent.override.yml /work/rel6/dc/.upgrade/compose-files; then fail "经软链 --purge 应清掉条目"; fi
pass "经软链传入部署目录：开机链写真实路径，卸载可清理"
echo "ALL PASS"
INNER

docker run --rm --network none \
  -v "$ROOT:/repo:ro" -v "$WORK:/work" "$IMAGE" sh -c 'sh /work/inner.sh'
