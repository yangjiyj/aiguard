#!/usr/bin/env bash
# set-public-sso-url.sh 行为合约：dry-run 输出、env 改写幂等、启动链解析、不泄露 secret，
# 以及通用性：两种 compose 项目名布局、postgres 用户/库名来自容器 env、老版本缺件跳过、
# 带端口/大小写/默认端口的地址规范化、同址直接退出、多租户 SQL、realm/子路径/端口/客户端 ID 推导、回滚。
# 全部使用桩 docker / compose-wrapper / kcadm，不需要 Docker 或网络。

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT_DIR/deploy/docker-compose/chat/set-public-sso-url.sh"
JJDCTL="$ROOT_DIR/deploy/offline-installer/jjdctl"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

[ -x "$SCRIPT" ] || fail "缺少可执行 set-public-sso-url.sh"
grep -q 'set-public-url' "$JJDCTL" || fail "jjdctl 未挂载 sso set-public-url"
grep -q 'rollback' "$JJDCTL" || fail "jjdctl 未挂载 sso rollback"

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

NEW=https://testapi2.example.cn
OLD=https://192.168.20.246
SECRET_MARK=TOPSECRET_VALUE_9f3a
LEGACY_PROJECT=jjdguard-2-2-offline-full-chat-amd64-20260817-153752

dc="" ; log="" ; bk=""

# ---------- 桩（一次写好，所有场景共用，行为由 FAKE_* 环境变量决定） ----------
cat >"$fixture/wrapper.sh" <<'EOF'
#!/bin/sh
# 假 compose-wrapper：只会被用于 config / up，记录参数。
printf 'WRAPPER %s\n' "$*" >>"$FAKE_LOG"
case " $* " in
  *" config"*) printf 'services:\n  control-plane:\n    image: %s\n' "${FAKE_CONFIG_IMAGE:-cp:2.9.4}" ;;
esac
exit 0
EOF
cat >"$fixture/docker" <<'EOF'
#!/bin/sh
# 假 docker：按 FAKE_PROJECT / FAKE_SERVICES 模拟 compose 容器；所有调用写入 FAKE_LOG。
printf 'DOCKER %s\n' "$*" >>"$FAKE_LOG"
proj="${FAKE_PROJECT:-docker-compose}"
services="${FAKE_SERVICES:-postgres control-plane chat-idp chat-edge chat-portal-proxy chat-portal-ui gateway-core}"
has_service() { for s in $services; do [ "$s" = "$1" ] && return 0; done; return 1; }
cmd="$1"; shift
case "$cmd" in
  ps)
    want_proj=""; want_wd=""; want_svc=""; fmt=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --filter) shift
          case "$1" in
            label=com.docker.compose.project=*) want_proj="${1#label=com.docker.compose.project=}" ;;
            label=com.docker.compose.project.working_dir=*) want_wd="${1#label=com.docker.compose.project.working_dir=}" ;;
            label=com.docker.compose.service=*) want_svc="${1#label=com.docker.compose.service=}" ;;
          esac ;;
        --format) shift; fmt="$1" ;;
      esac
      shift
    done
    [ -z "$want_proj" ] || [ "$want_proj" = "$proj" ] || exit 0
    [ -z "$want_wd" ] || { [ -n "${FAKE_WORKDIR:-}" ] && [ "$want_wd" = "$FAKE_WORKDIR" ]; } || exit 0
    if [ -n "$want_svc" ]; then has_service "$want_svc" || exit 0; svc="$want_svc"; else svc="$(echo $services | cut -d' ' -f1)"; fi
    if [ -n "$fmt" ]; then echo "$proj"; else echo "cid-$proj-$svc"; fi ;;
  inspect)
    fmtv=""; [ "$1" = --format ] && { shift; fmtv="$1"; shift; }
    cid="$1"
    case "$fmtv" in
      *project.config_files*) echo "${FAKE_LABELS:-$proj|/x|/x/a.yml,/x/b.yml|/x/.env}" ;;
      *Config.Env*)
        case "$cid" in
          *-postgres) echo "POSTGRES_USER=${FAKE_PGUSER:-newapi}"; echo "POSTGRES_DB=${FAKE_PGDB:-newapi}"; echo "POSTGRES_PASSWORD=$SECRET_MARK" ;;
          *-chat-idp)
            [ -z "${FAKE_KC_REL:-}" ] || echo "KC_HTTP_RELATIVE_PATH=$FAKE_KC_REL"
            [ -z "${FAKE_KC_ENV_PORT:-}" ] || echo "KC_HTTP_PORT=$FAKE_KC_ENV_PORT"
            echo "KC_BOOTSTRAP_ADMIN_PASSWORD=$SECRET_MARK" ;;
          *-chat-portal-ui) [ -z "${FAKE_UI_CLIENT:-}" ] || echo "OIDC_CLIENT_ID=$FAKE_UI_CLIENT" ;;
          *-chat-portal-proxy) [ -z "${FAKE_ADMIN_CLIENT:-}" ] || echo "PORTAL_OIDC_CLIENT_ID=$FAKE_ADMIN_CLIENT" ;;
        esac ;;
      *Config.Cmd*) case "$cid" in *-chat-idp) echo start; echo "--http-port=${FAKE_KC_PORT:-8180}"; echo --import-realm ;; esac ;;
      *Config.Image*) echo "${FAKE_RUNNING_IMAGE:-cp:2.9.4}" ;;
    esac ;;
  exec)
    [ "$1" = -i ] && shift
    cid="$1"; shift
    case "$cid" in
      *-postgres)
        case "$1" in
          pg_dump) echo "-- dump" ;;
          psql)
            body="$(cat | tr '\n' ' ')"
            printf 'PSQL args=%s\n' "$*" >>"$FAKE_LOG"
            printf 'SQL %s\n' "$body" >>"$FAKE_LOG"
            case "$body" in
              *to_regclass*) if [ -n "${FAKE_NO_TABLE:-}" ]; then echo f; else echo t; fi ;;
              *string_agg*) echo "${FAKE_COLS:-tenant_id,user_id,source_type,source_id,external_subject,local_runtime_managed}" ;;
              *"INSERT INTO"*) for i in ${FAKE_NEW_IDS:-uil_aaa uil_bbb uil_ccc}; do echo "$i"; done ;;
              *"count(DISTINCT"*) echo "3|2" ;;
              *"DELETE FROM"*) echo 3 ;;
            esac ;;
        esac ;;
      *-chat-idp)
        case "$1" in
          sh) printf 'KC_LOGIN_SH %s\n' "$(printf '%s' "$*" | tr '\n' ' ')" >>"$FAKE_LOG" ;;
          /opt/keycloak/bin/kcadm.sh) shift; exec "$FAKE_KCADM" "$@" ;;
        esac ;;
    esac ;;
esac
exit 0
EOF
cat >"$fixture/kcadm" <<'EOF'
#!/bin/sh
printf 'KCADM %s\n' "$*" >>"$FAKE_LOG"
case "$1" in
  get)
    case "$2" in
      clients/*) printf '{ "id" : "uuid-1", "clientId" : "x", "secret" : "SHOULDNOTLEAK", "redirectUris" : [ "https://192.168.20.246/chat/api/auth/callback/account-login" ], "webOrigins" : [ "https://192.168.20.246" ], "attributes" : { "post.logout.redirect.uris" : "https://192.168.20.246/chat##https://192.168.20.246/chat/*" } }\n' ;;
      *) printf '[ { "id" : "uuid-1", "redirectUris" : [ "https://192.168.20.246/chat/api/auth/callback/account-login" ], "webOrigins" : [ "https://192.168.20.246" ], "attributes" : { "post.logout.redirect.uris" : "https://192.168.20.246/chat##https://192.168.20.246/chat/*" } } ]\n' ;;
    esac ;;
esac
EOF
chmod +x "$fixture/wrapper.sh" "$fixture/docker" "$fixture/kcadm"
export SECRET_MARK

# ---------- 场景夹具：每个场景一份干净的假 compose 目录 ----------
fresh() {
  rm -rf "$fixture/s"; mkdir -p "$fixture/s"
  dc="$fixture/s/dc"; log="$fixture/s/calls.log"; bk="$fixture/s/backup"
  mkdir -p "$dc/active-config" "$dc/.upgrade" "$dc/chat" "$bk"
  : >"$log"
  : >"$dc/docker-compose.offline.yml"
  : >"$dc/active-config/dev-release.yml"; : >"$dc/active-config/inherited-001.yml"
  chmod 600 "$dc"/active-config/*.yml
  printf '%s\n' "$dc/active-config/dev-release.yml" "$dc/active-config/inherited-001.yml" >"$dc/.upgrade/compose-files"
  printf 'docker-compose\n' >"$dc/.upgrade/project-name"
  chmod 600 "$dc/.upgrade/compose-files" "$dc/.upgrade/project-name"
  cat >"$dc/.env" <<EOF
JJD_SSO_PUBLIC_URL=$OLD
JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=false
CHAT_OIDC_HOST=192.168.20.246
CHAT_OIDC_ISSUER=$OLD/sso/realms/jjdguard
CHAT_PORTAL_UI_OIDC_CLIENT_ID=enterprise-ai-portal
POSTGRES_PASSWORD=$SECRET_MARK
KEYCLOAK_ADMIN_PASSWORD=$SECRET_MARK
EOF
  cat >"$dc/identity-runtime.env" <<EOF
JJD_SSO_PUBLIC_URL=$OLD
JJD_IDENTITY_RUNTIME_CLIENT_SECRET=$SECRET_MARK
EOF
  cp "$SCRIPT" "$dc/chat/set-public-sso-url.sh"
  unset FAKE_PROJECT FAKE_SERVICES FAKE_WORKDIR FAKE_LABELS FAKE_PGUSER FAKE_PGDB FAKE_KC_REL FAKE_KC_PORT \
    FAKE_KC_ENV_PORT FAKE_UI_CLIENT FAKE_ADMIN_CLIENT FAKE_NO_TABLE FAKE_COLS FAKE_NEW_IDS FAKE_CONFIG_IMAGE \
    FAKE_RUNNING_IMAGE JJD_COMPOSE_PROJECT || true
}

run() {
  FAKE_LOG="$log" FAKE_KCADM="$fixture/kcadm" JJD_ENV_FILE="$dc/.env" IDENTITY_RUNTIME_ENV_FILE="$dc/identity-runtime.env" \
    COMPOSE_WRAPPER="$fixture/wrapper.sh" DOCKER_BIN="$fixture/docker" JJD_BACKUP_ROOT="$bk" \
    bash "$dc/chat/set-public-sso-url.sh" "$@"
}
latest_backup() { ls -d "$bk"/sso-public-url-* 2>/dev/null | tail -n 1; }

# =====================================================================
# 一、基础行为（项目名 docker-compose，postgres 用户 newapi）
# =====================================================================
fresh
env_before="$(cat "$dc/.env")"
out="$(run "$NEW" 2>&1)" || { echo "$out"; fail "dry-run 退出非零"; }
echo "$out" | grep -q 'dry-run' || fail "dry-run 输出缺少模式提示"
echo "$out" | grep -q "JJD_SSO_PUBLIC_URL: $OLD -> $NEW" || fail "dry-run 未展示 JJD_SSO_PUBLIC_URL 改动"
echo "$out" | grep -q "CHAT_OIDC_ISSUER: $OLD/sso/realms/jjdguard -> $NEW/sso/realms/jjdguard" || fail "dry-run 未展示 issuer 改动"
echo "$out" | grep -q 'identity-runtime.env' || fail "dry-run 未覆盖 identity-runtime.env"
echo "$out" | grep -q '预计新增 3 行（涉及 2 个租户）' || fail "dry-run 应展示预计行数与租户数"
[ "$env_before" = "$(cat "$dc/.env")" ] || fail "dry-run 修改了 .env"
grep -q "$OLD" "$dc/identity-runtime.env" || fail "dry-run 修改了 identity-runtime.env"
if grep -E 'force-recreate|KCADM update| up |INSERT INTO|DELETE FROM' "$log" >/dev/null; then fail "dry-run 执行了写操作"; fi
[ -z "$(ls -A "$bk")" ] || fail "dry-run 创建了备份目录"
ok "dry-run 只打印计划、不改文件、不写库"

echo "$out" | grep -q "$SECRET_MARK" && fail "输出泄露 secret"
ok "输出不含 secret"

echo "$out" | grep -q "启动链来源: file:" || fail "未从 compose-files 解析启动链"
echo "$out" | grep -q 'active-config/dev-release.yml' || fail "启动链缺少 dev 覆盖层"
echo "$out" | grep -q 'active-config/inherited-001.yml' || fail "启动链缺少 inherited 层"
ok "启动链解析：compose-files"

run "$NEW" --apply >"$fixture/apply.out" 2>&1 || { cat "$fixture/apply.out"; fail "apply 失败"; }
grep -q "$SECRET_MARK" "$fixture/apply.out" && fail "apply 输出泄露 secret"
grep -qx "JJD_SSO_PUBLIC_URL=$NEW" "$dc/.env" || fail ".env 未更新 JJD_SSO_PUBLIC_URL"
grep -qx "JJD_SSO_PUBLIC_URL=$NEW" "$dc/identity-runtime.env" || fail "identity-runtime.env 未更新"
grep -qx "CHAT_OIDC_HOST=testapi2.example.cn" "$dc/.env" || fail "CHAT_OIDC_HOST 未更新"
grep -qx "CHAT_OIDC_ISSUER=$NEW/sso/realms/jjdguard" "$dc/.env" || fail "CHAT_OIDC_ISSUER 未更新"
grep -qx "POSTGRES_PASSWORD=$SECRET_MARK" "$dc/.env" || fail "无关键被破坏"
grep -qx "JJD_IDENTITY_RUNTIME_CLIENT_SECRET=$SECRET_MARK" "$dc/identity-runtime.env" || fail "runtime secret 被破坏"
b1="$(latest_backup)"
[ -s "$b1/env.bak" ] && [ -s "$b1/identity-runtime.env.bak" ] && [ -s "$b1/user_identity_links.sql" ] || fail "备份不全"
[ -s "$b1/meta.env" ] && [ -s "$b1/added-link-ids.txt" ] && [ -s "$b1/keycloak-clients/enterprise-ai-portal.json" ] || fail "备份缺少 meta/新增行 id/Keycloak 客户端 JSON"
grep -qx "JJD_SSO_PUBLIC_URL=$OLD" "$b1/env.bak" || fail "备份应保存旧值"
[ "$(stat -c %a "$b1")" = 700 ] || fail "备份目录权限应为 700"
[ "$(wc -l <"$b1/added-link-ids.txt" | tr -d ' ')" = 3 ] || fail "应记录 3 个新增行 id"
ok "apply：env 改写 + 备份（含新增行 id、客户端 JSON）"

rec="$(grep 'force-recreate' "$log")"
[ -n "$rec" ] || fail "没有执行重建"
echo "$rec" | grep -q 'active-config/dev-release.yml' || fail "重建命令缺少 dev 覆盖层"
echo "$rec" | grep -q 'active-config/inherited-001.yml' || fail "重建命令缺少 inherited 层"
echo "$rec" | grep -q -- '--no-deps' || fail "重建应带 --no-deps"
for s in control-plane chat-idp chat-edge chat-portal-proxy chat-portal-ui; do
  echo "$rec" | grep -q "$s" || fail "重建缺少服务 $s"
done
ok "重建复用启动链"

grep -q 'KCADM update clients/uuid-1' "$log" || fail "未更新 Keycloak 客户端"
kcu="$(grep 'KCADM update' "$log" | head -n 1)"
echo "$kcu" | grep -q "$OLD/chat/api/auth/callback/account-login" || fail "默认应保留旧 redirect"
echo "$kcu" | grep -q "$NEW/chat/api/auth/callback/enterprise-sso" || fail "未追加新 redirect"
echo "$kcu" | grep -q "post.logout.redirect.uris\"=.*$OLD/chat.*##.*$NEW/chat" || fail "post-logout 应同时含旧新"
ok "Keycloak 追加新地址并保留旧地址"

grep -q "old_issuer=$OLD/sso/realms/jjdguard" "$log" || fail "未按旧 issuer 复制 links"
grep -q "new_issuer=$NEW/sso/realms/jjdguard" "$log" || fail "未设置新 issuer"
ok "links 复制使用旧/新 issuer"

# 多租户：SQL 不带任何租户常量，按行内 tenant_id 复制
sql="$(grep '^SQL .*INSERT INTO' "$log" | head -n 1)"
echo "$sql" | grep -q 'tenant_default' && fail "复制 SQL 不应写死 tenant_default"
echo "$sql" | grep -q 'l.tenant_id' || fail "复制 SQL 应携带 l.tenant_id（覆盖所有租户）"
echo "$sql" | grep -q 'n.tenant_id = l.tenant_id' || fail "去重应按租户内比较"
echo "$sql" | grep -Eq 'WHERE l\.issuer = :.old_issuer.[[:space:]]+AND NOT EXISTS' || fail "复制 SQL 不应带租户过滤"
ok "多租户：issuer 复制覆盖所有 tenant"

# 数据库用户/库名来自容器 env（本场景是 newapi）
grep -q 'PSQL args=.*-U newapi -d newapi' "$log" || fail "应使用容器 env 的 POSTGRES_USER/DB（newapi）"
ok "psql 用户/库来自容器 env（newapi）"

# 幂等
cp "$dc/.env" "$fixture/env.after1"; cp "$dc/identity-runtime.env" "$fixture/rt.after1"
run "$NEW" --apply >"$fixture/apply2.out" 2>&1 || fail "第二次 apply 失败"
cmp -s "$dc/.env" "$fixture/env.after1" || fail "第二次 apply 改变了 .env"
cmp -s "$dc/identity-runtime.env" "$fixture/rt.after1" || fail "第二次 apply 改变了 identity-runtime.env"
[ "$(grep -c '^JJD_SSO_PUBLIC_URL=' "$dc/.env")" = 1 ] || fail "出现重复键"
grep -q '无变化' "$fixture/apply2.out" || fail "第二次应提示无变化"
ok "env 改写幂等；同址再跑直接退出（见下方专项）"

# --drop-old
: >"$log"
run "$NEW" --apply --drop-old --skip-recreate >/dev/null 2>&1 || fail "drop-old 失败"
kcu="$(grep 'KCADM update' "$log" | head -n 1)"
echo "$kcu" | grep -q "$OLD" && fail "--drop-old 仍含旧地址"
ok "--drop-old（地址已一致时仍执行 Keycloak 清理）"

# 非法输入
for bad in "ftp://x.example" "https://x.example/path" "https://x.example/sso/" "https://x.example?a=1" "https://u:p@x.example" "https://0.0.0.0" "https://localhost" "x.example" "https://x.example:99999" "https://300.1.1.1" "https://" ""; do
  if run "$bad" >/dev/null 2>&1; then fail "应拒绝非法地址: '$bad'"; fi
done
msg="$(run "https://x.example/sso" 2>&1 || true)"
echo "$msg" | grep -q '不能带路径' || fail "带路径的报错应说明原因"
echo "$msg" | grep -q '/sso' || fail "报错应指出检测到的路径"
ok "拒绝非法地址，路径报错清楚"

# 镜像漂移
fresh
: >"$log"
if FAKE_RUNNING_IMAGE=cp:2.9.4 FAKE_CONFIG_IMAGE=cp:2.9.3 run "$NEW" --apply >"$fixture/drift.out" 2>&1; then fail "镜像漂移时 apply 不应成功"; fi
grep -q '镜像漂移' "$fixture/drift.out" || fail "未提示镜像漂移"
grep -q 'force-recreate' "$log" && fail "漂移时不应执行重建"
grep -q 'sso rollback' "$fixture/drift.out" || fail "失败提示应带回滚命令"
ok "镜像漂移保护（且提示回滚命令）"

# 无 compose-files 时回退到容器标签
fresh
rm -f "$dc/.upgrade/compose-files" "$dc/.upgrade/project-name"
mkdir -p "$fixture/s/x"; : >"$fixture/s/x/a.yml"; : >"$fixture/s/x/b.yml"; : >"$fixture/s/x/.env"
export FAKE_WORKDIR="$dc" FAKE_LABELS="docker-compose|$fixture/s/x|$fixture/s/x/a.yml,$fixture/s/x/b.yml|$fixture/s/x/.env"
out="$(run "$NEW" 2>&1)"
echo "$out" | grep -q '启动链来源: labels:' || fail "未回退到容器标签"
echo "$out" | grep -q "$fixture/s/x/b.yml" || fail "标签启动链缺少第二个文件"
echo "$out" | grep -q '老版本部署' || fail "回退应给出提示"
ok "启动链解析：无 compose-files 回退容器标签（按工作目录标签定位）"

# =====================================================================
# 二、通用性
# =====================================================================
# 2.1 老安装布局：项目名带时间戳、postgres 用户和库都叫 jjdguard、没有 .upgrade/project-name
fresh
rm -f "$dc/.upgrade/project-name"
printf 'COMPOSE_PROJECT_NAME=%s\n' "$LEGACY_PROJECT" >>"$dc/.env"
export FAKE_PROJECT="$LEGACY_PROJECT" FAKE_PGUSER=jjdguard FAKE_PGDB=jjdguard
run "$NEW" --apply >"$fixture/legacy.out" 2>&1 || { cat "$fixture/legacy.out"; fail "老安装布局 apply 失败"; }
grep -q "label=com.docker.compose.project=$LEGACY_PROJECT" "$log" || fail "应按 .env 的项目名过滤容器"
grep -q 'PSQL args=.*-U jjdguard -d jjdguard' "$log" || fail "老布局应取容器 env（jjdguard）"
grep -q 'PSQL args=.*-U newapi' "$log" && fail "不应出现写死的 newapi"
grep -q "DOCKER exec -i cid-$LEGACY_PROJECT-postgres" "$log" || fail "docker exec 应指向老布局容器"
grep 'force-recreate' "$log" | grep -q -- "--project-name $LEGACY_PROJECT" || fail "重建应沿用老项目名"
ok "老安装布局：长项目名 + jjdguard 用户/库"

# 2.2 工作目录标签定位 + 整机唯一项目定位
fresh
rm -f "$dc/.upgrade/project-name"
export FAKE_PROJECT="$LEGACY_PROJECT" FAKE_WORKDIR="$dc"
out="$(run "$NEW" 2>&1)"
echo "$out" | grep -q '容器范围: 工作目录' || fail "无项目名时应按工作目录标签定位"
fresh
rm -f "$dc/.upgrade/project-name"
export FAKE_PROJECT="$LEGACY_PROJECT"
out="$(run "$NEW" 2>&1)"
echo "$out" | grep -q '整机唯一' || fail "整机仅一个项目时应自动定位"
ok "容器定位：项目名 > 工作目录标签 > 整机唯一项目"

# 2.3 没有 identity-runtime.env
fresh
rm -f "$dc/identity-runtime.env"
out="$(run "$NEW" 2>&1)" || { echo "$out"; fail "无 identity-runtime.env 的 dry-run 失败"; }
echo "$out" | grep -q 'identity-runtime.env 不存在' || fail "缺 identity-runtime.env 应给出提示"
run "$NEW" --apply >/dev/null 2>&1 || fail "无 identity-runtime.env 的 apply 失败"
[ ! -e "$dc/identity-runtime.env" ] || fail "不应凭空创建 identity-runtime.env"
b2="$(latest_backup)"; [ ! -e "$b2/identity-runtime.env.bak" ] || fail "无该文件时不应有备份"
grep -qx "JJD_SSO_PUBLIC_URL=$NEW" "$dc/.env" || fail ".env 仍应更新"
ok "无 identity-runtime.env：跳过并提示"

# 2.4 没有 chat-idp（未启用内置 Keycloak / BYO IdP）
fresh
export FAKE_SERVICES="postgres control-plane gateway-core"
out="$(run "$NEW" --apply 2>&1)" || { echo "$out"; fail "无 chat-idp 的 apply 失败"; }
echo "$out" | grep -q '跳过 Keycloak' || fail "无 chat-idp 应提示跳过 Keycloak"
grep -q 'KCADM' "$log" && fail "无 chat-idp 不应调用 kcadm"
grep -q 'KC_LOGIN_SH' "$log" && fail "无 chat-idp 不应登录 Keycloak"
grep 'force-recreate' "$log" | grep -q 'chat-idp' && fail "不应重建不存在的 chat-idp"
grep 'force-recreate' "$log" | grep -q 'control-plane' || fail "control-plane 仍应重建"
ok "无 chat-idp：跳过 Keycloak，仅重建存在的服务"

fresh
printf 'CHAT_BYO_IDP=true\n' >>"$dc/.env"
out="$(run "$NEW" --apply 2>&1)" || { echo "$out"; fail "BYO IdP 的 apply 失败"; }
echo "$out" | grep -q '外部 IdP' || fail "BYO 应提示外部 IdP 需手工登记"
echo "$out" | grep -q "$NEW/chat/api/auth/callback/account-login" || fail "BYO 应列出需登记的回调地址"
grep -q 'KCADM\|INSERT INTO' "$log" && fail "BYO 不应动 Keycloak 或 identity link"
grep -q '^CHAT_OIDC_ISSUER=.*192.168.20.246' "$dc/.env" || fail "BYO 不应改 CHAT_OIDC_ISSUER"
ok "BYO IdP：不改 Keycloak/issuer/links，并列出需手工登记的地址"

# 2.5 没有 user_identity_links 表
fresh
export FAKE_NO_TABLE=1
out="$(run "$NEW" --apply 2>&1)" || { echo "$out"; fail "无 user_identity_links 的 apply 失败"; }
echo "$out" | grep -q '没有 user_identity_links 表' || fail "无表应提示跳过"
grep -q 'INSERT INTO' "$log" && fail "无表时不应执行复制"
grep -q 'KCADM update' "$log" || fail "无表不影响 Keycloak 步骤"
ok "无 user_identity_links 表：跳过并提示"

# 2.6 realm / 子路径 / 管理端口 / 客户端 ID 从 env 与容器推导
fresh
cat >"$dc/.env" <<EOF
JJD_SSO_PUBLIC_URL=$OLD
CHAT_OIDC_HOST=192.168.20.246
CHAT_OIDC_ISSUER=$OLD/auth/realms/acme
CHAT_REALM=acme
CHAT_PORTAL_UI_OIDC_CLIENT_ID=my-portal
EOF
export FAKE_KC_REL=/auth FAKE_KC_PORT=9000 FAKE_ADMIN_CLIENT=my-admin
run "$NEW" --apply >"$fixture/derive.out" 2>&1 || { cat "$fixture/derive.out"; fail "推导场景 apply 失败"; }
grep -qx "CHAT_OIDC_ISSUER=$NEW/auth/realms/acme" "$dc/.env" || fail "issuer 应按推导出的子路径和 realm 生成"
grep -q "KC_LOGIN_SH .*localhost:9000/auth" "$log" || fail "Keycloak 登录应使用推导出的端口和子路径"
grep -q "KCADM get clients -r acme -q clientId=my-portal" "$log" || fail "应使用 .env 的 UI 客户端 ID 和推导的 realm"
grep -q "KCADM get clients -r acme -q clientId=my-admin" "$log" || fail "应使用容器 env 的 admin 客户端 ID"
grep -q "old_issuer=$OLD/auth/realms/acme" "$log" || fail "旧 issuer 应按子路径/realm 推导"
grep -q 'KCADM get .*jjdguard\|-r jjdguard\|localhost:8180/sso' "$log" && fail "不应出现写死的 jjdguard/8180//sso"
ok "realm/子路径/端口/客户端 ID 推导（无写死）"

# 2.7 默认值：容器和 env 都推导不出时回落产品默认
fresh
run "$NEW" --apply >/dev/null 2>&1 || fail "默认值场景失败"
grep -q "KC_LOGIN_SH .*localhost:8180/sso" "$log" || fail "推导不出时应回落 8180//sso"
grep -q "clientId=enterprise-ai-portal" "$log" && grep -q "clientId=chat-portal-admin" "$log" || fail "客户端 ID 应回落默认值"
ok "推导不出才用默认值"

# =====================================================================
# 三、地址形态
# =====================================================================
# 3.1 带端口、大写、尾斜杠
fresh
run "https://SSO.Example.COM:8443/" --apply >/dev/null 2>&1 || fail "带端口地址 apply 失败"
grep -qx "JJD_SSO_PUBLIC_URL=https://sso.example.com:8443" "$dc/.env" || fail "应规范化为小写 origin"
grep -qx "CHAT_OIDC_HOST=sso.example.com" "$dc/.env" || fail "CHAT_OIDC_HOST 不应带端口"
grep -qx "CHAT_OIDC_ISSUER=https://sso.example.com:8443/sso/realms/jjdguard" "$dc/.env" || fail "issuer 应带端口"
kcu="$(grep 'KCADM update clients/uuid-1' "$log" | head -n 1)"
echo "$kcu" | grep -q 'https://sso.example.com:8443/chat/api/auth/callback/account-login' || fail "redirect 应带端口"
ok "带端口 + 大小写 + 尾斜杠规范化"

# 3.2 IP 与域名互转、域名改域名、http
fresh
run "http://10.1.2.3:8080" --apply >/dev/null 2>&1 || fail "http+IP 失败"
grep -qx "JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=true" "$dc/.env" || fail "http 应置 ALLOW_INSECURE=true"
grep -qx "CHAT_OIDC_HOST=10.1.2.3" "$dc/.env" || fail "IP host"
run "https://a.example.com" --apply >/dev/null 2>&1 || fail "IP -> 域名失败"
grep -qx "JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=false" "$dc/.env" || fail "https 应恢复 ALLOW_INSECURE=false"
run "https://b.example.org" --apply >/dev/null 2>&1 || fail "域名 -> 域名失败"
grep -qx "CHAT_OIDC_ISSUER=https://b.example.org/sso/realms/jjdguard" "$dc/.env" || fail "域名改域名 issuer"
grep -q "old_issuer=https://a.example.com/sso/realms/jjdguard" "$log" || fail "域名改域名应以上一个域名为旧 issuer"
ok "IP/域名互转、域名改域名、http<->https"

# 3.3 新地址等于当前地址：提示后返回 0（含大小写/尾斜杠/默认端口等价写法）
fresh
for same in "$OLD" "$OLD/" "HTTPS://192.168.20.246" "https://192.168.20.246:443" "https://192.168.20.246:443/"; do
  : >"$log"
  out="$(run "$same" --apply 2>&1)" || fail "同址应返回 0: $same"
  echo "$out" | grep -q '无变化' || fail "同址应提示无变化: $same"
  [ -z "$(ls -A "$bk")" ] || fail "同址不应创建备份: $same"
  grep -qE 'force-recreate|KCADM|INSERT' "$log" && fail "同址不应执行任何写操作: $same"
done
ok "新地址等于当前地址（规范化后）直接退出 0"

# 3.4 同址但其他配置不一致：进入修复模式
fresh
sed -i "s#^JJD_SSO_PUBLIC_URL=.*#JJD_SSO_PUBLIC_URL=$NEW#" "$dc/.env"
out="$(run "$NEW" 2>&1)" || fail "修复模式失败"
echo "$out" | grep -q '修复模式' || fail "env 与 runtime 不一致应提示修复模式"
ok "同址但 identity-runtime.env 不一致：按修复模式继续"

# =====================================================================
# 四、回滚
# =====================================================================
fresh
cp -p "$dc/.env" "$fixture/s/env.orig"; cp -p "$dc/identity-runtime.env" "$fixture/s/rt.orig"
run "$NEW" --apply >/dev/null 2>&1 || fail "回滚前置 apply 失败"
b3="$(latest_backup)"
cmp -s "$dc/.env" "$fixture/s/env.orig" && fail "apply 后 env 应已变化"

# dry-run 不改任何东西
: >"$log"
out="$(run --rollback "$b3" 2>&1)" || { echo "$out"; fail "rollback dry-run 失败"; }
echo "$out" | grep -q 'dry-run' || fail "rollback 应默认 dry-run"
echo "$out" | grep -q '将删除 3 行' || fail "rollback dry-run 应展示将删除的行数"
grep -qE 'DELETE FROM|force-recreate|KCADM update' "$log" && fail "rollback dry-run 不应有写操作"
grep -qx "JJD_SSO_PUBLIC_URL=$NEW" "$dc/.env" || fail "rollback dry-run 改了 .env"

# apply
: >"$log"
run --rollback "$b3" --apply >"$fixture/rb.out" 2>&1 || { cat "$fixture/rb.out"; fail "rollback apply 失败"; }
cmp -s "$dc/.env" "$fixture/s/env.orig" || fail "rollback 应还原 .env"
cmp -s "$dc/identity-runtime.env" "$fixture/s/rt.orig" || fail "rollback 应还原 identity-runtime.env"
del="$(grep '^PSQL args=.*-v ids=' "$log" | head -n 1)"
echo "$del" | grep -q 'ids=uil_aaa,uil_bbb,uil_ccc' || fail "应按备份记录的 id 删除新增行"
echo "$del" | grep -q "new_issuer=$NEW/sso/realms/jjdguard" || fail "删除应限定新 issuer"
grep '^SQL .*DELETE FROM' "$log" | grep -q 'issuer = :.new_issuer' || fail "DELETE 必须同时限定 issuer"
kcu="$(grep 'KCADM update clients/uuid-1' "$log" | head -n 1)"
[ -n "$kcu" ] || fail "rollback 应还原 Keycloak 客户端"
echo "$kcu" | grep -q "$NEW" && fail "还原后的 Keycloak 属性不应含新地址"
echo "$kcu" | grep -q "$OLD/chat/api/auth/callback/account-login" || fail "还原后应含旧 redirect"
grep -q 'SHOULDNOTLEAK' "$fixture/rb.out" && fail "rollback 输出泄露客户端 secret"
grep 'force-recreate' "$log" | grep -q 'active-config/dev-release.yml' || fail "rollback 应按启动链重建"
[ -f "$b3/rolled-back-at" ] || fail "rollback 应标记完成"
ok "rollback：还原 env、按 id 删除新增行、还原 Keycloak 属性、按启动链重建"

# 保护：apply 之后又改过
fresh
run "$NEW" --apply >/dev/null 2>&1
b4="$(latest_backup)"
printf 'SOME_LATER_EDIT=1\n' >>"$dc/.env"
if run --rollback "$b4" --apply >/dev/null 2>&1; then fail "env 被改过时 rollback 应拒绝"; fi
run --rollback "$b4" --apply --force >/dev/null 2>&1 || fail "--force 应允许继续"
ok "rollback 保护：配置被后续修改时拒绝，--force 放行"

# 不合法的备份目录
if run --rollback "$fixture/nonexistent" >/dev/null 2>&1; then fail "不存在的备份目录应报错"; fi
mkdir -p "$fixture/s/emptybk"
if run --rollback "$fixture/s/emptybk" >/dev/null 2>&1; then fail "缺少 meta.env 的目录应报错"; fi
ok "rollback 校验备份目录"

# jjdctl 子命令：rollback 与缺脚本提示
grep -q 'sso_cmd' "$JJDCTL" && grep -q -- '--rollback' "$JJDCTL" || fail "jjdctl 应有 sso rollback 分发"
grep -q '不含 chat/SSO 载荷' "$JJDCTL" || fail "jjdctl 缺脚本时应有清楚提示"
ok "jjdctl 子命令分发"

# =====================================================================
# 软链布局：/opt/jjdguard/current -> releases/v1（jjdctl 经 /usr/local/bin 软链调用的真实形态）
# compose-files 记录 releases 下的真实路径；软链路径与真实路径调用都必须成功，
# 且 active-config 经软链逃逸出真实 release 目录树时必须被拒绝。
# =====================================================================
make_symlink_layout() {
  fresh
  local base="$fixture/x/opt/jjdguard" src="$dc"
  rm -rf "$fixture/x"
  mkdir -p "$base/releases/v1/deploy"
  mv "$src" "$base/releases/v1/deploy/docker-compose"
  ln -s releases/v1 "$base/current"
  real_dc="$(cd "$base/releases/v1/deploy/docker-compose" && pwd -P)"
  link_dc="$base/current/deploy/docker-compose"
  printf '%s\n' "$real_dc/active-config/dev-release.yml" "$real_dc/active-config/inherited-001.yml" \
    >"$real_dc/.upgrade/compose-files"
  chmod 600 "$real_dc/.upgrade/compose-files"
  dc="$real_dc"
}

make_symlink_layout
dc="$link_dc"
out="$(run "$NEW" 2>&1)" || { echo "$out"; fail "通过软链路径调用 dry-run 应成功"; }
echo "$out" | grep -q "启动链来源: file:" || fail "软链调用应从 compose-files 解析启动链"
echo "$out" | grep -q "$real_dc/active-config/dev-release.yml" || fail "软链调用的启动链应使用真实路径"
echo "$out" | grep -q '活动 Compose 链包含非法路径' && fail "软链调用不应报非法路径"
ok "软链布局：通过 current 软链调用 dry-run 成功"

dc="$real_dc"
out="$(run "$NEW" 2>&1)" || { echo "$out"; fail "通过真实路径调用 dry-run 应成功"; }
echo "$out" | grep -q "启动链来源: file:" || fail "真实路径调用应从 compose-files 解析启动链"
ok "软链布局：通过真实路径调用 dry-run 成功"

# compose-files 用软链形式的目录前缀书写，同样应被规范化后接受
printf '%s\n' "$link_dc/active-config/dev-release.yml" "$link_dc/active-config/inherited-001.yml" \
  >"$real_dc/.upgrade/compose-files"
dc="$link_dc"
out="$(run "$NEW" 2>&1)" || { echo "$out"; fail "compose-files 使用软链前缀时应被规范化后接受"; }
echo "$out" | grep -q "$real_dc/active-config/dev-release.yml" || fail "启动链应被规范化为真实路径"
ok "软链布局：compose-files 的软链前缀被规范化后接受"

# 负例 1：compose-files 条目本身是软链，指向允许目录树之外
make_symlink_layout
mkdir -p "$fixture/outside"; : >"$fixture/outside/evil.yml"; chmod 600 "$fixture/outside/evil.yml"
ln -s "$fixture/outside/evil.yml" "$real_dc/active-config/evil.yml"
printf '%s\n' "$real_dc/active-config/evil.yml" >"$real_dc/.upgrade/compose-files"
out="$(run "$NEW" 2>&1)" && fail "条目为逃逸软链时必须被拒绝"
echo "$out" | grep -q '活动 Compose 链包含非法路径' || fail "逃逸软链应报非法路径"
ok "软链布局负例：条目为逃逸软链被拒绝"

# 负例 2：条目的父目录是软链，真实路径落在 release 目录树之外
make_symlink_layout
mkdir -p "$fixture/outside2"; : >"$fixture/outside2/evil.yml"; chmod 600 "$fixture/outside2/evil.yml"
ln -s "$fixture/outside2" "$real_dc/active-config/sub"
printf '%s\n' "$real_dc/active-config/sub/evil.yml" >"$real_dc/.upgrade/compose-files"
out="$(run "$NEW" 2>&1)" && fail "条目父目录软链逃逸时必须被拒绝"
echo "$out" | grep -q '活动 Compose 链包含非法路径' || fail "父目录软链逃逸应报非法路径"
ok "软链布局负例：父目录软链逃逸被拒绝"

# 负例 3：active-config 整体是软链，指向 release 目录树之外
make_symlink_layout
mkdir -p "$fixture/outside3"; : >"$fixture/outside3/dev-release.yml"; chmod 600 "$fixture/outside3/dev-release.yml"
rm -rf "$real_dc/active-config"; ln -s "$fixture/outside3" "$real_dc/active-config"
printf '%s\n' "$real_dc/active-config/dev-release.yml" >"$real_dc/.upgrade/compose-files"
out="$(run "$NEW" 2>&1)" && fail "active-config 整体软链逃逸时必须被拒绝"
echo "$out" | grep -q '活动 Compose 链包含非法路径' || fail "active-config 软链逃逸应报非法路径"
ok "软链布局负例：active-config 整体软链逃逸被拒绝"

# jjdctl 定位脚本和 ROOT 时必须先解析软链（回归保护）
grep -q 'readlink -f' "$JJDCTL" || fail "jjdctl 应用 readlink -f 解析自身路径"

echo "全部通过"
