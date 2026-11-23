#!/usr/bin/env bash
# set-public-sso-url.sh 的真实环境验证：apply -> rollback 闭环
# 需要 Docker 和本地 postgres:16-alpine、keycloak 26.3 镜像。
# 只创建带唯一前缀的一次性容器，结束即删；不接触任何现有容器。
# 容器带 compose 标签（project/service），用来验证“按标签找容器”而不是按名字。
# 用法：bash deploy/docker-compose/tests/set-public-sso-url-e2e.sh
#   E2E_PG_IMAGE / E2E_KC_IMAGE 可覆盖镜像；E2E_KEEP=1 保留容器便于排查。

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT_DIR/deploy/docker-compose/chat/set-public-sso-url.sh"
PG_IMAGE="${E2E_PG_IMAGE:-postgres:16-alpine}"
KC_IMAGE="${E2E_KC_IMAGE:-docker.1ms.run/keycloak/keycloak:26.3}"
P="ssoe2e-$$"
PROJ="$P-proj"                  # 故意不是 docker-compose，也不是现场项目名
PG="$P-pg-container"            # 容器名与 service 名毫无关系，只能靠标签找到
KC="$P-kc-container"
OLD=https://192.168.20.246
NEW=https://sso.example.com:8443
REALM=acme                      # 非默认 realm，验证从 CHAT_REALM 推导
ISS_OLD="$OLD/sso/realms/$REALM"
ISS_NEW="$NEW/sso/realms/$REALM"
DBUSER=jjdguard                 # 老安装：用户和库都叫 jjdguard
DBNAME=jjdguard

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

fixture="$(mktemp -d)"
cleanup() {
  [ -z "${E2E_KEEP:-}" ] || { echo "E2E_KEEP: 保留容器 $PG $KC"; return 0; }
  docker rm -f -v "$PG" "$KC" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT

docker run -d --name "$PG" \
  --label "com.docker.compose.project=$PROJ" --label "com.docker.compose.service=postgres" \
  -e POSTGRES_PASSWORD=e2e -e POSTGRES_USER="$DBUSER" -e POSTGRES_DB="$DBNAME" "$PG_IMAGE" >/dev/null
docker run -d --name "$KC" \
  --label "com.docker.compose.project=$PROJ" --label "com.docker.compose.service=chat-idp" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=e2e-admin-pw \
  -e KC_HTTP_RELATIVE_PATH=/sso "$KC_IMAGE" start-dev --http-port=8180 >/dev/null

for _ in $(seq 1 60); do
  docker exec "$PG" pg_isready -U "$DBUSER" >/dev/null 2>&1 && break; sleep 1
done
sleep 2
PSQL() { docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U "$DBUSER" -d "$DBNAME" "$@"; }
PSQL >/dev/null <<SQL
CREATE TABLE user_identity_links (
  id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL, user_id varchar(64) NOT NULL,
  issuer varchar(512) NOT NULL, source_type varchar(32) NOT NULL, source_id varchar(64) NOT NULL DEFAULT '',
  external_subject varchar(512) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(), local_runtime_managed boolean NOT NULL DEFAULT false,
  CHECK (btrim(issuer) <> ''), UNIQUE (tenant_id, issuer, source_type, external_subject));
INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,external_subject,local_runtime_managed) VALUES
 ('uil_1','t1','u1','$ISS_OLD','oidc','sub-a',false),
 ('uil_2','t1','u2','$ISS_OLD','oidc','sub-b',true),
 ('uil_4','t2','u9','$ISS_OLD','oidc','sub-z',false),
 ('uil_5','t3_default','u8','$ISS_OLD','oidc','sub-y',false),
 ('uil_3','t1','u3','urn:jjdguard:local','local','sub-c',false);
SQL

for _ in $(seq 1 120); do
  docker exec "$KC" /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8180/sso \
    --realm master --user admin --password e2e-admin-pw >/dev/null 2>&1 && break; sleep 2
done
KCA() { docker exec -i "$KC" /opt/keycloak/bin/kcadm.sh "$@"; }
KCA create realms -s realm="$REALM" -s enabled=true >/dev/null
KCA create clients -r "$REALM" -s clientId=my-portal -s enabled=true \
  -s "redirectUris=[\"$OLD/chat/api/auth/callback/account-login\",\"$OLD/chat/api/auth/callback/enterprise-sso\"]" \
  -s "webOrigins=[\"$OLD\"]" -s "attributes.\"post.logout.redirect.uris\"=$OLD/chat##$OLD/chat/*" >/dev/null
KCA create clients -r "$REALM" -s clientId=chat-portal-admin -s enabled=true \
  -s "redirectUris=[\"$OLD/portal/auth/callback\"]" -s "webOrigins=[\"$OLD\"]" \
  -s "attributes.\"post.logout.redirect.uris\"=$OLD##$OLD/*" >/dev/null

# 假 compose 目录：只给 wrapper 一个记录用的桩（config/up 不真正执行），其余全部走真实 docker
dc="$fixture/dc"; mkdir -p "$dc/chat" "$dc/active-config" "$dc/.upgrade" "$fixture/backup"
cp "$SCRIPT" "$dc/chat/"; : >"$dc/docker-compose.offline.yml"
cat >"$dc/.env" <<EOF
JJD_SSO_PUBLIC_URL=$OLD
CHAT_OIDC_HOST=192.168.20.246
CHAT_OIDC_ISSUER=$ISS_OLD
CHAT_REALM=$REALM
CHAT_PORTAL_UI_OIDC_CLIENT_ID=my-portal
POSTGRES_PASSWORD=must-not-leak
EOF
printf 'JJD_SSO_PUBLIC_URL=%s\nJJD_IDENTITY_RUNTIME_CLIENT_SECRET=must-not-leak\n' "$OLD" >"$dc/identity-runtime.env"
: >"$dc/active-config/dev.yml"; chmod 600 "$dc/active-config/dev.yml"
echo "$dc/active-config/dev.yml" >"$dc/.upgrade/compose-files"
echo "$PROJ" >"$dc/.upgrade/project-name"
chmod 600 "$dc/.upgrade/compose-files" "$dc/.upgrade/project-name"
cat >"$fixture/wrapper.sh" <<EOF
#!/bin/sh
echo "\$*" >>"$fixture/wrapper.log"
exit 0
EOF
chmod +x "$fixture/wrapper.sh"
cp -p "$dc/.env" "$fixture/env.orig"; cp -p "$dc/identity-runtime.env" "$fixture/rt.orig"

run() {
  JJD_ENV_FILE="$dc/.env" IDENTITY_RUNTIME_ENV_FILE="$dc/identity-runtime.env" COMPOSE_WRAPPER="$fixture/wrapper.sh" \
    JJD_BACKUP_ROOT="$fixture/backup" bash "$dc/chat/set-public-sso-url.sh" "$@"
}
count() { PSQL -At -c "$1"; }
kc_fields() { KCA get clients -r "$REALM" -q "clientId=$1" --fields "redirectUris,webOrigins,attributes(*)"; }

snap_ui="$(kc_fields my-portal)"; snap_admin="$(kc_fields chat-portal-admin)"
total0="$(count "select count(*) from user_identity_links")"

# ---- dry-run ----
out="$(run "$NEW" 2>&1)" || { echo "$out"; fail "dry-run 失败"; }
echo "$out" | grep -q '预计新增 4 行（涉及 3 个租户）' || { echo "$out"; fail "dry-run 预计行数/租户数不对"; }
echo "$out" | grep -q "realm=$REALM" || fail "dry-run 应推导出 realm=$REALM"
echo "$out" | grep -q 'my-portal' || fail "dry-run 应使用 .env 的客户端 ID"
[ "$(count "select count(*) from user_identity_links")" = "$total0" ] || fail "dry-run 改了 DB"
echo "$out" | grep -q 'must-not-leak' && fail "dry-run 泄露 secret"
ok "dry-run：按标签找到容器，推导 realm/客户端 ID，预计 4 行 3 租户，不改库"

# ---- apply（带端口新地址） ----
run "$NEW" --apply >"$fixture/apply.out" 2>&1 || { cat "$fixture/apply.out"; fail "apply 失败"; }
grep -q 'must-not-leak\|e2e-admin-pw' "$fixture/apply.out" && fail "apply 输出泄露 secret"
[ "$(count "select count(*) from user_identity_links where issuer='$ISS_OLD'")" = 4 ] || fail "旧行应保留 4 行"
[ "$(count "select count(*) from user_identity_links where issuer='$ISS_NEW'")" = 4 ] || fail "新 issuer 应有 4 行"
[ "$(count "select count(distinct tenant_id) from user_identity_links where issuer='$ISS_NEW'")" = 3 ] || fail "应覆盖 3 个租户"
[ "$(count "select count(*) from user_identity_links where issuer='urn:jjdguard:local'")" = 1 ] || fail "local 行不应被动"
[ "$(count "select local_runtime_managed from user_identity_links where issuer='$ISS_NEW' and external_subject='sub-b'")" = t ] || fail "local_runtime_managed 未保留"
ok "links 复制：所有租户、旧行保留、local 不动、属性保留"

bk="$(ls -d "$fixture"/backup/sso-public-url-* | tail -n 1)"
grep -q 'user_identity_links' "$bk/user_identity_links.sql" || fail "pg_dump 备份内容异常"
[ "$(wc -l <"$bk/added-link-ids.txt" | tr -d ' ')" = 4 ] || fail "应记录 4 个新增行 id"
[ -s "$bk/keycloak-clients/my-portal.json" ] && [ -s "$bk/keycloak-clients/chat-portal-admin.json" ] || fail "缺少客户端 JSON 备份"
ok "备份：pg_dump、新增行 id、客户端 JSON"

r1="$(kc_fields my-portal)"
for u in "$OLD/chat/api/auth/callback/enterprise-sso" "$NEW/chat/api/auth/callback/enterprise-sso" "$NEW/chat/api/auth/callback/account-login"; do
  echo "$r1" | grep -Fq "$u" || fail "my-portal 缺少 $u"
done
echo "$r1" | grep -Fq "$NEW/chat##$NEW/chat/*" || { echo "$r1"; fail "post-logout 缺少新地址"; }
echo "$r1" | grep -Fq "$OLD/chat" || fail "post-logout 默认应保留旧地址"
r2="$(kc_fields chat-portal-admin)"
echo "$r2" | grep -Fq "$NEW/portal/auth/callback" && echo "$r2" | grep -Fq "$OLD/portal/auth/callback" || fail "chat-portal-admin 新旧 redirect 应并存"
ok "Keycloak 两个客户端：新地址已追加、旧地址保留（带端口 $NEW）"

grep -qx "CHAT_OIDC_ISSUER=$ISS_NEW" "$dc/.env" && grep -qx "CHAT_OIDC_HOST=sso.example.com" "$dc/.env" || fail "env 未按带端口新地址改写"
grep -q 'up -d --no-deps --force-recreate chat-idp' "$fixture/wrapper.log" || fail "应重建存在的 chat-idp（且只重建存在的服务）"
grep -q -- "--project-name $PROJ" "$fixture/wrapper.log" || fail "重建应带项目名"
ok "env 改写 + 重建命令（只含存在的服务）"

# ---- 同址再跑：直接退出 ----
out="$(run "$NEW" --apply 2>&1)" || fail "同址应返回 0"
echo "$out" | grep -q '无变化' || fail "同址应提示无变化"
[ "$(count "select count(*) from user_identity_links")" = $((total0 + 4)) ] || fail "同址不应再增行"
ok "同址再跑：提示后退出 0，不重复写入"

# ---- rollback ----
out="$(run --rollback "$bk" 2>&1)" || { echo "$out"; fail "rollback dry-run 失败"; }
echo "$out" | grep -q '将删除 4 行' || fail "rollback dry-run 应展示 4 行"
[ "$(count "select count(*) from user_identity_links")" = $((total0 + 4)) ] || fail "rollback dry-run 改了 DB"
run --rollback "$bk" --apply >"$fixture/rb.out" 2>&1 || { cat "$fixture/rb.out"; fail "rollback apply 失败"; }
grep -q 'must-not-leak\|e2e-admin-pw' "$fixture/rb.out" && fail "rollback 输出泄露 secret"
cmp -s "$dc/.env" "$fixture/env.orig" || fail "rollback 后 .env 应与原始一致"
cmp -s "$dc/identity-runtime.env" "$fixture/rt.orig" || fail "rollback 后 identity-runtime.env 应与原始一致"
[ "$(count "select count(*) from user_identity_links")" = "$total0" ] || fail "rollback 后行数应回到 $total0"
[ "$(count "select count(*) from user_identity_links where issuer='$ISS_NEW'")" = 0 ] || fail "新 issuer 行应全部删除"
[ "$(count "select count(*) from user_identity_links where issuer='$ISS_OLD'")" = 4 ] || fail "旧 issuer 行应保留"
[ "$(kc_fields my-portal)" = "$snap_ui" ] || { kc_fields my-portal; fail "my-portal 属性应与 apply 前完全一致"; }
[ "$(kc_fields chat-portal-admin)" = "$snap_admin" ] || { echo "--- 期望"; echo "$snap_admin"; echo "--- 实际"; kc_fields chat-portal-admin; fail "chat-portal-admin 属性应与 apply 前完全一致"; }
ok "rollback：env 逐字节还原、新增行删除、旧行保留、Keycloak 属性与 apply 前完全一致"

# ---- 回滚后再次 apply（域名改域名、--drop-old） ----
run "https://b.example.org" --apply --drop-old >/dev/null 2>&1 || fail "回滚后再次 apply 失败"
r3="$(kc_fields my-portal)"
echo "$r3" | grep -Fq "$OLD" && fail "--drop-old 后仍含旧地址"
echo "$r3" | grep -Fq "https://b.example.org/chat/api/auth/callback/enterprise-sso" || fail "缺少新 redirect"
bk2="$(ls -d "$fixture"/backup/sso-public-url-* | tail -n 1)"
run --rollback "$bk2" --apply >/dev/null 2>&1 || fail "--drop-old 的 rollback 失败"
[ "$(kc_fields my-portal)" = "$snap_ui" ] || fail "--drop-old 回滚后客户端应完全还原（旧地址回来）"
ok "--drop-old 后 rollback 可恢复被移除的旧地址"
echo "全部通过"
