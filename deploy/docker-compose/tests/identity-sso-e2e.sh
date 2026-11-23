#!/usr/bin/env bash
# 真实身份引擎、JJDGuard 发布 API 与员工门户浏览器闭环验收。
# 所有服务均位于唯一 Compose project；secret 仅写入 0600 临时文件且不回显。

set -euo pipefail
set +x

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
MAX_WAIT_SECONDS="${IDENTITY_E2E_MAX_WAIT_SECONDS:-120}"
KEEP_ENVIRONMENT="${IDENTITY_E2E_KEEP:-0}"
STAMP="$(date +%s)-$$-${RANDOM}"
PROJECT="jjdguard-identity-e2e-${STAMP}"
TMP_DIR="/tmp/${PROJECT}"
ARTIFACT_DIR="/tmp/${PROJECT}-artifacts"
COMPOSE_FILE="$TMP_DIR/compose.yml"
ENV_FILE="$TMP_DIR/runtime.env"
IDENTITY_RUNTIME_ENV_FILE="$TMP_DIR/identity-runtime.env"
RESPONSE_FILE="$TMP_DIR/response.json"
COMPOSE_STARTED=0
ADMIN_TOKEN=""

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

stage() {
  printf '\n==> %s\n' "$1"
}

pass() {
  printf 'PASS: %s\n' "$1"
}

compose() {
  docker compose --env-file "$ENV_FILE" --project-name "$PROJECT" --file "$COMPOSE_FILE" "$@"
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ] && [ "$COMPOSE_STARTED" -eq 1 ]; then
    compose logs --no-color >"$ARTIFACT_DIR/compose.log" 2>&1 || true
  fi
  ADMIN_TOKEN=""
  if [ "$KEEP_ENVIRONMENT" = "1" ]; then
    printf '隔离环境已保留: project=%s temp=%s\n' "$PROJECT" "$TMP_DIR" >&2
  else
    if [ "$COMPOSE_STARTED" -eq 1 ]; then
      compose down --volumes --remove-orphans --timeout 20 >/dev/null 2>&1 || true
    fi
    rm -rf -- "$TMP_DIR"
  fi
  if [ "$status" -ne 0 ]; then
    printf '失败证据目录: %s\n' "$ARTIFACT_DIR" >&2
  elif [ "$KEEP_ENVIRONMENT" != "1" ]; then
    rm -rf -- "$ARTIFACT_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("0.0.0.0", 0))
    print(sock.getsockname()[1])
PY
}

declare -A USED_PORTS=()
reserve_port() {
  local port
  while :; do
    port="$(free_port)"
    if [ -z "${USED_PORTS[$port]:-}" ]; then
      USED_PORTS[$port]=1
      printf '%s\n' "$port"
      return
    fi
  done
}

random_secret() {
  openssl rand -hex 32
}

wait_http() {
  local name="$1" url="$2" expected="${3:-200}"
  local deadline=$((SECONDS + MAX_WAIT_SECONDS)) code
  while [ "$SECONDS" -lt "$deadline" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" || true)"
    if [ "$code" = "$expected" ]; then
      return 0
    fi
    sleep 2
  done
  fail "$name 在 ${MAX_WAIT_SECONDS}s 内未就绪（最后状态 ${code:-000}）"
}

wait_query_true() {
  local name="$1" sql="$2"
  local deadline=$((SECONDS + MAX_WAIT_SECONDS)) result
  while [ "$SECONDS" -lt "$deadline" ]; do
    result="$(compose exec -T postgres psql -U jjdguard -d jjdguard -tAc "$sql" 2>/dev/null | tr -d '[:space:]' || true)"
    if [ "$result" = "t" ] || [ "$result" = "1" ]; then
      return 0
    fi
    sleep 2
  done
  fail "$name 在 ${MAX_WAIT_SECONDS}s 内未成立"
}

api_request() {
  local method="$1" path="$2" body="${3:-}" expected_codes="${4:-200}"
  local code
  code="$(printf '%s' "$body" | curl -sS --max-time 30 -o "$RESPONSE_FILE" -w '%{http_code}' \
    -X "$method" "http://127.0.0.1:${CONTROL_PORT}${path}" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    --data-binary @-)"
  case ",${expected_codes}," in
    *",${code},"*) ;;
    *) fail "${method} ${path} 状态为 ${code}，期望 ${expected_codes}" ;;
  esac
}

fetch_captcha() {
  local captcha_response captcha_image
  captcha_response="$(curl -sS --max-time 20 "http://127.0.0.1:${CONTROL_PORT}/admin/v1/captcha")" ||
    fail "无法取得本地管理员验证码"
  CAPTCHA_ID="$(printf '%s' "$captcha_response" | jq -er '.captcha_id | select(type == "string" and length > 0)')" ||
    fail "本地管理员验证码缺少 captcha_id"
  captcha_image="$(printf '%s' "$captcha_response" | jq -er '.image | select(type == "string" and startswith("data:image/svg+xml;base64,"))')" ||
    fail "本地管理员验证码不是预期 SVG"
  CAPTCHA_CODE="$(printf '%s' "$captcha_image" | python3 -c '
import base64
import re
import sys

encoded = sys.stdin.read().strip().split(",", 1)[1]
svg = base64.b64decode(encoded).decode("utf-8")
print("".join(re.findall(r"<text[^>]*>([^<])</text>", svg)))
')"
  [ "${#CAPTCHA_CODE}" -eq 5 ] || fail "无法从本地管理员验证码读取 5 位字符"
}

login_local_admin() {
  local password="$1"
  fetch_captcha
  login_payload="$(jq -n \
    --arg username admin \
    --arg login_password "$password" \
    --arg captcha_id "$CAPTCHA_ID" \
    --arg captcha_code "$CAPTCHA_CODE" \
    '{username:$username,password:$login_password,captcha_id:$captcha_id,captcha_code:$captcha_code}')"
  login_code="$(printf '%s' "$login_payload" | curl -sS --max-time 20 \
    -o "$RESPONSE_FILE" -w '%{http_code}' \
    -H 'Content-Type: application/json' --data-binary @- \
    "http://127.0.0.1:${CONTROL_PORT}/admin/v1/login")" ||
    fail "本地管理员登录请求失败"
}

stage "检查真实 E2E 依赖"
for command_name in docker curl jq openssl python3; do
  command -v "$command_name" >/dev/null 2>&1 || fail "缺少依赖: $command_name"
done
docker info >/dev/null 2>&1 || fail "Docker 不可用"
docker compose version >/dev/null 2>&1 || fail "Docker Compose 不可用"
[ -f "$ROOT_DIR/deploy/docker-compose/chat/keycloak-realm/realm-jjdguard.json" ] ||
  fail "缺少 JJDGuard 身份域定义"
[ -f "$ROOT_DIR/deploy/docker-compose/chat/Caddyfile" ] || fail "缺少身份公共边界配置"
[ -x "$ROOT_DIR/deploy/docker-compose/chat/bootstrap-identity-runtime.sh" ] ||
  fail "缺少身份运行态引导脚本"

mkdir -m 700 -p "$TMP_DIR" "$ARTIFACT_DIR"
touch "$IDENTITY_RUNTIME_ENV_FILE"
chmod 600 "$IDENTITY_RUNTIME_ENV_FILE"

HOST_GATEWAY="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
case "$HOST_GATEWAY" in
  ''|*[!0-9.]*) fail "无法取得 Docker IPv4 host gateway" ;;
esac

POSTGRES_PORT="$(reserve_port)"
REDIS_PORT="$(reserve_port)"
CONTROL_PORT="$(reserve_port)"
GATEWAY_PORT="$(reserve_port)"
PORTAL_PORT="$(reserve_port)"
PORTAL_ADMIN_PORT="$(reserve_port)"
SSO_PORT="$(reserve_port)"
UPSTREAM_PORT="$(reserve_port)"

POSTGRES_PASSWORD="$(random_secret)"
REDIS_PASSWORD="$(random_secret)"
CHAT_POSTGRES_PASSWORD="$(random_secret)"
ADMIN_PASSWORD="$(random_secret)"
ADMIN_ROTATED_PASSWORD="$(random_secret)"
KEYCLOAK_ADMIN_PASSWORD="$(random_secret)"
UPSTREAM_ADMIN_PASSWORD="$(random_secret)"
UPSTREAM_CLIENT_SECRET="$(random_secret)"
UPSTREAM_USER_PASSWORD="$(random_secret)"
PORTAL_CLIENT_SECRET="$(random_secret)"
PORTAL_ADMIN_CLIENT_SECRET="$(random_secret)"
PROVIDER_SECRET_KEY="$(random_secret)"
INTERNAL_API_SECRET="$(random_secret)"
PORTAL_API_SECRET="$(random_secret)"
AUDIT_HMAC_KEY="$(random_secret)"
AUTH_SECRET="$(random_secret)"
PORTAL_INTERNAL_TOKEN="$(random_secret)"
PORTAL_KEY_ENC_SECRET="$(random_secret)"

UPSTREAM_PUBLIC_URL="http://${HOST_GATEWAY}:${UPSTREAM_PORT}"
PORTAL_PUBLIC_ORIGIN="http://${HOST_GATEWAY}:${PORTAL_PORT}"
PORTAL_PUBLIC_URL="${PORTAL_PUBLIC_ORIGIN}/chat"
JJD_SSO_PUBLIC_URL="http://${HOST_GATEWAY}:${SSO_PORT}"

umask 077
{
  printf 'ROOT_DIR=%s\n' "$ROOT_DIR"
  printf 'TMP_DIR=%s\n' "$TMP_DIR"
  printf 'IDENTITY_RUNTIME_ENV_FILE=%s\n' "$IDENTITY_RUNTIME_ENV_FILE"
  printf 'HOST_GATEWAY=%s\n' "$HOST_GATEWAY"
  printf 'POSTGRES_PORT=%s\n' "$POSTGRES_PORT"
  printf 'REDIS_PORT=%s\n' "$REDIS_PORT"
  printf 'CONTROL_PORT=%s\n' "$CONTROL_PORT"
  printf 'GATEWAY_PORT=%s\n' "$GATEWAY_PORT"
  printf 'PORTAL_PORT=%s\n' "$PORTAL_PORT"
  printf 'PORTAL_ADMIN_PORT=%s\n' "$PORTAL_ADMIN_PORT"
  printf 'SSO_PORT=%s\n' "$SSO_PORT"
  printf 'UPSTREAM_PORT=%s\n' "$UPSTREAM_PORT"
  printf 'POSTGRES_PASSWORD=%s\n' "$POSTGRES_PASSWORD"
  printf 'REDIS_PASSWORD=%s\n' "$REDIS_PASSWORD"
  printf 'CHAT_POSTGRES_PASSWORD=%s\n' "$CHAT_POSTGRES_PASSWORD"
  printf 'ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD"
  printf 'KEYCLOAK_ADMIN_PASSWORD=%s\n' "$KEYCLOAK_ADMIN_PASSWORD"
  printf 'UPSTREAM_ADMIN_PASSWORD=%s\n' "$UPSTREAM_ADMIN_PASSWORD"
  printf 'UPSTREAM_CLIENT_SECRET=%s\n' "$UPSTREAM_CLIENT_SECRET"
  printf 'UPSTREAM_USER_PASSWORD=%s\n' "$UPSTREAM_USER_PASSWORD"
  printf 'PORTAL_CLIENT_SECRET=%s\n' "$PORTAL_CLIENT_SECRET"
  printf 'PORTAL_ADMIN_CLIENT_SECRET=%s\n' "$PORTAL_ADMIN_CLIENT_SECRET"
  printf 'PROVIDER_SECRET_KEY=%s\n' "$PROVIDER_SECRET_KEY"
  printf 'INTERNAL_API_SECRET=%s\n' "$INTERNAL_API_SECRET"
  printf 'PORTAL_API_SECRET=%s\n' "$PORTAL_API_SECRET"
  printf 'AUDIT_HMAC_KEY=%s\n' "$AUDIT_HMAC_KEY"
  printf 'AUTH_SECRET=%s\n' "$AUTH_SECRET"
  printf 'PORTAL_INTERNAL_TOKEN=%s\n' "$PORTAL_INTERNAL_TOKEN"
  printf 'PORTAL_KEY_ENC_SECRET=%s\n' "$PORTAL_KEY_ENC_SECRET"
  printf 'UPSTREAM_PUBLIC_URL=%s\n' "$UPSTREAM_PUBLIC_URL"
  printf 'PORTAL_PUBLIC_URL=%s\n' "$PORTAL_PUBLIC_URL"
  printf 'PORTAL_PUBLIC_ORIGIN=%s\n' "$PORTAL_PUBLIC_ORIGIN"
  printf 'JJD_SSO_PUBLIC_URL=%s\n' "$JJD_SSO_PUBLIC_URL"
} >"$ENV_FILE"
chmod 600 "$ENV_FILE"

CHAT_OIDC_HOST="$HOST_GATEWAY" \
CHAT_IDP_PORT="$SSO_PORT" \
JJD_ENV_FILE="$ENV_FILE" \
  bash "$ROOT_DIR/deploy/docker-compose/chat/ensure-public-sso-url.sh" >/dev/null
JJD_SSO_PUBLIC_URL="$(sed -n 's/^JJD_SSO_PUBLIC_URL=//p' "$ENV_FILE" | tail -n 1)"
[ -n "$JJD_SSO_PUBLIC_URL" ] || fail "默认公开 SSO 地址未写入隔离环境"
grep -qx 'JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=true' "$ENV_FILE" ||
  fail "自动生成 HTTP 地址未开启兼容模式"
jq -n \
  --arg clientSecret "$UPSTREAM_CLIENT_SECRET" \
  --arg callback "${JJD_SSO_PUBLIC_URL}/sso/realms/jjdguard/broker/enterprise/endpoint" \
  --arg webOrigin "$JJD_SSO_PUBLIC_URL" \
  --arg password "$UPSTREAM_USER_PASSWORD" \
  '{
    realm: "upstream-enterprise",
    displayName: "企业身份源",
    enabled: true,
    sslRequired: "none",
    registrationAllowed: false,
    resetPasswordAllowed: false,
    loginWithEmailAllowed: true,
    clients: [{
      clientId: "jjdguard-e2e-broker",
      name: "JJDGuard SSO",
      enabled: true,
      protocol: "openid-connect",
      publicClient: false,
      clientAuthenticatorType: "client-secret",
      secret: $clientSecret,
      standardFlowEnabled: true,
      implicitFlowEnabled: false,
      directAccessGrantsEnabled: false,
      redirectUris: [$callback],
      webOrigins: [$webOrigin],
      protocolMappers: [{
        name: "department",
        protocol: "openid-connect",
        protocolMapper: "oidc-usermodel-attribute-mapper",
        consentRequired: false,
        config: {
          "user.attribute": "department",
          "claim.name": "department",
          "jsonType.label": "String",
          "id.token.claim": "true",
          "access.token.claim": "true",
          "userinfo.token.claim": "true",
          "multivalued": "false"
        }
      }]
    }],
    users: [{
      username: "e2e.employee",
      email: "e2e.employee@example.test",
      firstName: "E2E",
      lastName: "Employee",
      enabled: true,
      emailVerified: true,
      attributes: { department: ["SEC-E2E"] },
      credentials: [{type: "password", value: $password, temporary: false}]
    }]
  }' >"$TMP_DIR/upstream-enterprise-realm.json"
chmod 600 "$TMP_DIR/upstream-enterprise-realm.json"

cat >"$TMP_DIR/upstream.Caddyfile" <<'CADDY'
{
  admin off
  auto_https off
  persist_config off
}
:8081 {
  header -Server
  @health path /healthz
  handle @health {
    respond "ok" 200
  }
  @private path /admin /admin/* /realms/master /realms/master/*
  handle @private {
    respond "Not Found" 404
  }
  @realm path /realms/upstream-enterprise /realms/upstream-enterprise/*
  handle @realm {
    reverse_proxy upstream-idp:8080 {
      header_down -Server
      header_down -X-Powered-By
    }
  }
  @resources path /resources/*
  handle @resources {
    reverse_proxy upstream-idp:8080 {
      header_down -Server
      header_down -X-Powered-By
    }
  }
  handle {
    respond "Not Found" 404
  }
}
CADDY

cat >"$TMP_DIR/identity-proxy.js" <<'NODE'
const http = require('node:http');

let faultArmed = false;
let providerReadbackFailuresRemaining = 0;
const adminPrefix = '/sso/admin/realms/jjdguard/identity-provider/instances/enterprise';

function isLoopback(address) {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', 'http://identity-proxy');
  if (url.pathname === '/__e2e/fault' && req.method === 'POST') {
    req.resume();
    if (!isLoopback(req.socket.remoteAddress)) {
      res.writeHead(404).end();
      return;
    }
    faultArmed = true;
    providerReadbackFailuresRemaining = 0;
    res.writeHead(204).end();
    return;
  }

  const isAdminTarget = url.pathname.startsWith(adminPrefix);
  const isProviderReadback = url.pathname === adminPrefix && req.method === 'GET';
  if (faultArmed && providerReadbackFailuresRemaining > 0 && isProviderReadback) {
    req.resume();
    providerReadbackFailuresRemaining -= 1;
    console.log(`[e2e] injected provider readback failure; remaining=${providerReadbackFailuresRemaining}`);
    if (providerReadbackFailuresRemaining === 0) faultArmed = false;
    res.writeHead(502, {'content-type': 'application/json'});
    res.end(JSON.stringify({error: 'injected readback failure'}));
    return;
  }

  const headers = {...req.headers, host: 'identity-engine:8180'};
  const upstream = http.request({
    hostname: 'identity-engine',
    port: 8180,
    method: req.method,
    path: req.url,
    headers,
  }, (upstreamResponse) => {
    const mutation = isAdminTarget && ['POST', 'PUT', 'DELETE'].includes(req.method || '');
    const succeeded = (upstreamResponse.statusCode || 500) < 300;
    if (mutation && succeeded && faultArmed) {
      providerReadbackFailuresRemaining = 2;
    }
    res.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
    upstreamResponse.pipe(res);
  });
  upstream.on('error', () => {
    if (!res.headersSent) res.writeHead(502, {'content-type': 'application/json'});
    res.end(JSON.stringify({error: 'identity runtime unavailable'}));
  });
  req.pipe(upstream);
});

server.listen(8180, '0.0.0.0');
NODE

cat >"$TMP_DIR/portal-seed.mjs" <<'NODE'
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
try {
  await prisma.portalSystemConfig.upsert({
    where: {tenantId_key: {tenantId: 'tenant_default', key: 'gateway_user_sync_enabled'}},
    create: {tenantId: 'tenant_default', key: 'gateway_user_sync_enabled', value: 'true'},
    update: {value: 'true'},
  });
  await prisma.groupMappingRule.create({
    data: {
      id: 'e2e-department-rule',
      tenantId: 'tenant_default',
      matchType: 'department',
      matchValue: 'SEC-E2E',
      mappedGroup: 'E2E Security',
      gatewayProjectId: process.env.E2E_PROJECT_ID,
      gatewayTeamId: process.env.E2E_TEAM_ID,
      priority: 1,
      enabled: true,
    },
  });
} finally {
  await prisma.$disconnect();
}
NODE

cat >"$ARTIFACT_DIR/browser.js" <<'NODE'
const fs = require('node:fs');
const { chromium } = require('playwright');

const portalUrl = process.env.PORTAL_URL;
const upstreamPort = process.env.UPSTREAM_PORT;
const ssoPort = process.env.SSO_PORT;
const username = process.env.UPSTREAM_USERNAME;
const password = process.env.UPSTREAM_PASSWORD;
const chatModel = process.env.E2E_CHAT_MODEL || 'e2e-probe-model';
const chromiumExecutablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH?.trim();
const resultPath = '/work/browser-result.json';
const tracePath = '/work/trace.zip';
const screenshotPath = '/work/browser-failure.png';

(async () => {
  const launchOptions = {headless: true};
  if (chromiumExecutablePath) {
    launchOptions.executablePath = chromiumExecutablePath;
    launchOptions.args = ['--no-sandbox'];
  }
  const browser = await chromium.launch(launchOptions);
  const context = await browser.newContext();
  await context.tracing.start({screenshots: true, snapshots: true});
  const page = await context.newPage();
  let succeeded = false;
  try {
    await page.goto(`${portalUrl}/login`, {waitUntil: 'domcontentloaded', timeout: 60000});
    await page.getByRole('button', {name: '企业 SSO 登录'}).click();

    await page.waitForURL(
      (url) => url.port === ssoPort || url.port === upstreamPort,
      {timeout: 60000},
    );
    if (new URL(page.url()).port === ssoPort) {
      const provider = page.getByRole('link', {name: '企业账号', exact: true});
      await provider.click();
    }

    await page.waitForURL((url) => url.port === upstreamPort, {timeout: 60000});
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.locator('#kc-login').click();

    await page.waitForURL((url) => url.origin === portalUrl, {timeout: 60000});
    await page.waitForLoadState('domcontentloaded');
    const me = await page.evaluate(async () => {
      const response = await fetch('/api/me', {cache: 'no-store'});
      return {status: response.status, body: await response.json()};
    });
    if (me.status !== 200 || me.body?.authenticated !== true) {
      throw new Error(`portal session missing: ${JSON.stringify(me)}`);
    }
    if (!me.body.user?.external_subject || me.body.user.external_subject !== me.body.user.id) {
      throw new Error('portal /api/me missing stable external_subject');
    }
    if (me.body.user.department !== 'SEC-E2E') {
      throw new Error(`department mismatch: ${String(me.body.user.department)}`);
    }
    if (me.body.user.role !== 'employee') {
      throw new Error(`role escalation detected: ${String(me.body.user.role)}`);
    }

    const chat = await page.evaluate(async (chatModel) => {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({
          model: chatModel,
          messages: [{role: 'user', content: 'identity mapping probe'}],
        }),
      });
      return {status: response.status};
    }, chatModel);
    fs.writeFileSync(resultPath, JSON.stringify({
      external_subject: me.body.user.external_subject,
      user_id: me.body.user.id,
      email: me.body.user.email,
      department: me.body.user.department,
      role: me.body.user.role,
      chat_status: chat.status,
    }));
    succeeded = true;
  } catch (error) {
    await page.screenshot({path: screenshotPath, fullPage: true}).catch(() => {});
    throw error;
  } finally {
    await context.tracing.stop({path: tracePath}).catch(() => {});
    await browser.close();
    if (succeeded) {
      fs.rmSync(screenshotPath, {force: true});
    }
  }
})().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
NODE

cat >"$COMPOSE_FILE" <<'YAML'
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: jjdguard
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: jjdguard
    ports:
      - "127.0.0.1:${POSTGRES_PORT}:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ${ROOT_DIR}/deploy/migrations:/migrations:ro
      - ${ROOT_DIR}/deploy/docker-compose/initdb:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U jjdguard -d jjdguard"]
      interval: 2s
      timeout: 3s
      retries: 60
    networks: [identity]

  redis:
    image: valkey/valkey:8.1.10-alpine
    environment:
      REDIS_PASSWORD: ${REDIS_PASSWORD}
    command: ["sh", "-c", "exec valkey-server --appendonly no --requirepass \"$${REDIS_PASSWORD}\""]
    ports:
      - "127.0.0.1:${REDIS_PORT}:6379"
    healthcheck:
      test: ["CMD-SHELL", "valkey-cli -a \"$${REDIS_PASSWORD}\" ping | grep PONG"]
      interval: 2s
      timeout: 3s
      retries: 60
    networks: [identity]

  chat-postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${CHAT_POSTGRES_PASSWORD}
      POSTGRES_DB: enterprise_ai_portal
    volumes:
      - chat-postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d enterprise_ai_portal"]
      interval: 2s
      timeout: 3s
      retries: 60
    networks: [identity]

  upstream-idp:
    image: docker.1ms.run/keycloak/keycloak:26.3@sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba
    command: ["start-dev", "--http-port=8080", "--import-realm"]
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${UPSTREAM_ADMIN_PASSWORD}
      KC_HOSTNAME: ${UPSTREAM_PUBLIC_URL}
      KC_PROXY_HEADERS: xforwarded
      KC_HTTP_ENABLED: "true"
      KC_HEALTH_ENABLED: "false"
    volumes:
      - upstream-data:/opt/keycloak/data
      - ${TMP_DIR}/upstream-enterprise-realm.json:/opt/keycloak/data/import/upstream-enterprise-realm.json:ro
    networks: [identity]

  upstream-edge:
    image: docker.1ms.run/library/caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648
    ports:
      - "0.0.0.0:${UPSTREAM_PORT}:8081"
    volumes:
      - ${TMP_DIR}/upstream.Caddyfile:/etc/caddy/Caddyfile:ro
    networks: [identity]

  identity-engine:
    image: docker.1ms.run/keycloak/keycloak:26.3@sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba
    command: ["start", "--http-port=8180", "--import-realm"]
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_HOSTNAME: ${JJD_SSO_PUBLIC_URL}/sso
      KC_PROXY_HEADERS: xforwarded
      KC_HTTP_ENABLED: "true"
      KC_HTTP_RELATIVE_PATH: /sso
      KC_HEALTH_ENABLED: "false"
      CHAT_PORTAL_UI_OIDC_SECRET: ${PORTAL_CLIENT_SECRET}
      PORTAL_OIDC_CLIENT_SECRET: ${PORTAL_ADMIN_CLIENT_SECRET}
      PORTAL_UI_ORIGIN: ${PORTAL_PUBLIC_ORIGIN}
      PORTAL_ADMIN_ORIGIN: http://${HOST_GATEWAY}:${PORTAL_ADMIN_PORT}
      PORTAL_UI_ACCOUNT_REDIRECT: ${PORTAL_PUBLIC_URL}/api/auth/callback/account-login
      PORTAL_UI_SSO_REDIRECT: ${PORTAL_PUBLIC_URL}/api/auth/callback/enterprise-sso
      PORTAL_ADMIN_REDIRECT_8280: http://${HOST_GATEWAY}:${PORTAL_ADMIN_PORT}/portal/auth/callback
      PORTAL_ADMIN_REDIRECT_3100: ${PORTAL_PUBLIC_ORIGIN}/portal/auth/callback
    volumes:
      - identity-data:/opt/keycloak/data
      - ${ROOT_DIR}/deploy/docker-compose/chat/keycloak-realm:/opt/keycloak/data/import:ro
      - ${ROOT_DIR}/deploy/docker-compose/chat/keycloak-themes/jjdguard:/opt/keycloak/themes/jjdguard:ro
    networks: [identity]

  chat-idp:
    image: docker.1ms.run/library/node:22-alpine
    command: ["node", "/e2e/identity-proxy.js"]
    volumes:
      - ${TMP_DIR}/identity-proxy.js:/e2e/identity-proxy.js:ro
    depends_on:
      - identity-engine
    networks: [identity]

  control-plane:
    build:
      context: ${ROOT_DIR}
      args:
        GOPROXY: "https://goproxy.cn|https://mirrors.aliyun.com/goproxy|direct"
      dockerfile: apps/control-plane/Dockerfile
    env_file:
      - ${IDENTITY_RUNTIME_ENV_FILE}
    environment:
      LISTEN_ADDR: :8081
      DATABASE_URL: postgres://jjdguard:${POSTGRES_PASSWORD}@postgres:5432/jjdguard?sslmode=disable
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0
      SECURITY_ENGINE_URL: http://127.0.0.1:9
      SECURITY_AUDIT_ONLY: "true"
      SESSION_COOKIE_SECURE: "false"
      UAG_RBAC_ENFORCE: "false"
      UAG_AUDIT_HMAC_KEY: ${AUDIT_HMAC_KEY}
      JJD_PROVIDER_SECRET_KEY: ${PROVIDER_SECRET_KEY}
      JJD_INTERNAL_API_SECRET: ${INTERNAL_API_SECRET}
      JJD_PORTAL_API_SECRET: ${PORTAL_API_SECRET}
      BOOTSTRAP_ADMIN_USERNAME: admin
      BOOTSTRAP_ADMIN_EMAIL: admin@local
      BOOTSTRAP_ADMIN_PASSWORD: ${ADMIN_PASSWORD}
      JJD_LICENSE_ENFORCE: "false"
      JJD_IDP_ALLOW_CIDRS: ${HOST_GATEWAY}/32
      JJD_SSO_ALLOW_INSECURE_PUBLIC_URL: "true"
      RETENTION_STORE_PATH: /tmp/retention
    ports:
      - "127.0.0.1:${CONTROL_PORT}:8081"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      chat-idp:
        condition: service_started
    networks: [identity]
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8081/health"]
      interval: 2s
      timeout: 3s
      retries: 60

  gateway-core:
    build:
      context: ${ROOT_DIR}
      args:
        GOPROXY: "https://goproxy.cn|https://mirrors.aliyun.com/goproxy|direct"
      dockerfile: apps/gateway-core/Dockerfile
    environment:
      LISTEN_ADDR: :8080
      DATABASE_URL: postgres://jjdguard:${POSTGRES_PASSWORD}@postgres:5432/jjdguard?sslmode=disable
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0
      SECURITY_ENGINE_URL: http://127.0.0.1:9
      SECURITY_AUDIT_ONLY: "true"
      SECURITY_SCAN_FP_ENABLED: "false"
      CONTROL_PLANE_URL: http://control-plane:8081
      JJD_PROVIDER_SECRET_KEY: ${PROVIDER_SECRET_KEY}
      JJD_INTERNAL_API_SECRET: ${INTERNAL_API_SECRET}
      PROXY_ENABLED: "false"
      PROXY_LISTEN_ADDR: :8082
    ports:
      - "127.0.0.1:${GATEWAY_PORT}:8080"
    depends_on:
      control-plane:
        condition: service_healthy
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks: [identity]
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/health"]
      interval: 2s
      timeout: 3s
      retries: 60

  chat-portal-proxy:
    image: chat-portal/portal-proxy:0.1.0
    environment:
      PORT: "8788"
      DATABASE_URL: file:/data/portal.db
      PORTAL_INTERNAL_TOKEN: ${PORTAL_INTERNAL_TOKEN}
      PORTAL_KEY_ENC_SECRET: ${PORTAL_KEY_ENC_SECRET}
      JJD_PORTAL_API_SECRET: ${PORTAL_API_SECRET}
      NEWAPI_PORTAL_API_SECRET: ${PORTAL_API_SECRET}
      LOBE_DATABASE_URL: postgresql://postgres:${CHAT_POSTGRES_PASSWORD}@chat-postgres:5432/enterprise_ai_portal
      GATEWAY_BASE_URL: http://gateway-core:8080
      GATEWAY_CP_URL: http://control-plane:8081
      PORTAL_TENANT_ID: tenant_default
      PORTAL_PROJECT_ID: project_default
      PORTAL_DEFAULT_PROJECT_ID: project_default
      PORTAL_REEVAL_TTL_SEC: "1"
      PORTAL_OIDC_ISSUER: ${JJD_SSO_PUBLIC_URL}/sso/realms/jjdguard
      PORTAL_OIDC_CLIENT_ID: chat-portal-admin
      PORTAL_OIDC_CLIENT_SECRET: ${PORTAL_ADMIN_CLIENT_SECRET}
      PORTAL_OIDC_REDIRECT_URI: http://${HOST_GATEWAY}:${PORTAL_ADMIN_PORT}/portal/auth/callback
      PORTAL_COOKIE_SECURE: "false"
      PORTAL_GATEWAY_USER_SYNC_ALLOWED: "true"
      PORTAL_GATEWAY_RULES_READ: "true"
    volumes:
      - portal-proxy-data:/data
      - ${TMP_DIR}/portal-seed.mjs:/app/e2e-portal-seed.mjs:ro
    depends_on:
      chat-postgres:
        condition: service_healthy
      control-plane:
        condition: service_healthy
      gateway-core:
        condition: service_healthy
    networks: [identity]
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:8788/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
      interval: 3s
      timeout: 3s
      retries: 60

  chat-portal-ui:
    build:
      context: ${ROOT_DIR}/enterprise-ai-portal
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://postgres:${CHAT_POSTGRES_PASSWORD}@chat-postgres:5432/enterprise_ai_portal
      AUTH_SECRET: ${AUTH_SECRET}
      AUTH_TRUST_HOST: "true"
      AUTH_URL: ${PORTAL_PUBLIC_URL}/api/auth
      NEXTAUTH_URL: ${PORTAL_PUBLIC_URL}/api/auth
      PORTAL_PUBLIC_URL: ${PORTAL_PUBLIC_URL}
      OIDC_ISSUER: ${JJD_SSO_PUBLIC_URL}/sso/realms/jjdguard
      OIDC_CLIENT_ID: enterprise-ai-portal
      OIDC_CLIENT_SECRET: ${PORTAL_CLIENT_SECRET}
      PORTAL_PROXY_URL: http://chat-portal-proxy:8788
      PORTAL_INTERNAL_TOKEN: ${PORTAL_INTERNAL_TOKEN}
      NEWAPI_CP_URL: http://control-plane:8081
      NEWAPI_PORTAL_API_SECRET: ${PORTAL_API_SECRET}
      BRAND_NAME: 企业 AI 对话门户
      BRAND_SHORT_NAME: AI 门户
    depends_on:
      chat-postgres:
        condition: service_healthy
      chat-portal-proxy:
        condition: service_healthy
    networks: [identity]
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:3100/chat/api/me').then(r=>process.exit(r.ok||r.status===401?0:1)).catch(()=>process.exit(1))"]
      interval: 3s
      timeout: 3s
      retries: 60
      start_period: 20s

  chat-edge:
    image: docker.1ms.run/library/caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648
    ports:
      - "0.0.0.0:${PORTAL_PORT}:3100"
      - "0.0.0.0:${PORTAL_ADMIN_PORT}:8280"
      - "0.0.0.0:${SSO_PORT}:8180"
    volumes:
      - ${ROOT_DIR}/deploy/docker-compose/chat/Caddyfile:/etc/caddy/Caddyfile:ro
    depends_on:
      chat-portal-proxy:
        condition: service_healthy
      chat-portal-ui:
        condition: service_healthy
      chat-idp:
        condition: service_started
    networks: [identity]

volumes:
  postgres-data:
  chat-postgres-data:
  upstream-data:
  identity-data:
  portal-proxy-data:

networks:
  identity:
    driver: bridge
YAML

cat >"$TMP_DIR/compose-psql" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exec docker compose --env-file "$E2E_ENV_FILE" --project-name "$E2E_PROJECT" \
  --file "$E2E_COMPOSE_FILE" exec -T postgres psql -U jjdguard -d jjdguard "$@"
SH
chmod 700 "$TMP_DIR/compose-psql"

cat >"$TMP_DIR/kcadm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exec docker compose --env-file "$E2E_ENV_FILE" --project-name "$E2E_PROJECT" \
  --file "$E2E_COMPOSE_FILE" exec -T identity-engine /opt/keycloak/bin/kcadm.sh "$@"
SH
chmod 700 "$TMP_DIR/kcadm"

cat >"$TMP_DIR/kcadm-upstream" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exec docker compose --env-file "$E2E_ENV_FILE" --project-name "$E2E_PROJECT" \
  --file "$E2E_COMPOSE_FILE" exec -T upstream-idp /opt/keycloak/bin/kcadm.sh "$@"
SH

export E2E_ENV_FILE="$ENV_FILE"
export E2E_PROJECT="$PROJECT"
export E2E_COMPOSE_FILE="$COMPOSE_FILE"

stage "校验并构建隔离测试镜像"
compose config --quiet
if ! compose build control-plane gateway-core chat-portal-ui >"$ARTIFACT_DIR/build.log" 2>&1; then
  tail -n 80 "$ARTIFACT_DIR/build.log" >&2 || true

stage "声明外部身份源 department 属性"
"$TMP_DIR/kcadm-upstream" config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password "$UPSTREAM_ADMIN_PASSWORD" >/dev/null 2>&1 ||
  fail "外部身份源管理凭据初始化失败"
upstream_profile="$("$TMP_DIR/kcadm-upstream" get users/profile -r upstream-enterprise)" ||
  fail "外部身份源用户属性配置读取失败"
printf '%s' "$upstream_profile" |
  python3 "$ROOT_DIR/deploy/docker-compose/chat/ensure-user-profile-department.py" |
  "$TMP_DIR/kcadm-upstream" update users/profile -r upstream-enterprise -f - >/dev/null ||
  fail "外部身份源 department 用户属性配置失败"
upstream_user_id="$("$TMP_DIR/kcadm-upstream" get users -r upstream-enterprise -q username=e2e.employee --fields id | jq -er '.[0].id')" ||
  fail "隔离测试镜像构建失败"
fi

stage "启动双身份域、数据库与内部管理代理"
COMPOSE_STARTED=1
compose up -d postgres redis chat-postgres upstream-idp upstream-edge identity-engine chat-idp
wait_http "外部企业身份源" "${UPSTREAM_PUBLIC_URL}/realms/upstream-enterprise/.well-known/openid-configuration"

stage "执行私有部署迁移"
if ! MIGRATION_PSQL="$TMP_DIR/compose-psql" \
  bash "$ROOT_DIR/deploy/lib/migration-runner.sh" \
    --migrations-dir "$ROOT_DIR/deploy/migrations" >"$ARTIFACT_DIR/migrations.log" 2>&1; then
  tail -n 80 "$ARTIFACT_DIR/migrations.log" >&2 || true
  fail "私有部署迁移失败"
fi

stage "创建最小权限身份运行态服务账号"
BOOTSTRAP_TEST_MODE=1 \
KCADM_BIN="$TMP_DIR/kcadm" \
KEYCLOAK_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
JJD_SSO_PUBLIC_URL="$JJD_SSO_PUBLIC_URL" \
JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=true \
IDENTITY_RUNTIME_ENV_FILE="$IDENTITY_RUNTIME_ENV_FILE" \
  "$ROOT_DIR/deploy/docker-compose/chat/bootstrap-identity-runtime.sh"
[ "$(stat -c '%a' "$IDENTITY_RUNTIME_ENV_FILE")" = "600" ] ||
  fail "身份运行态环境文件权限不是 0600"

stage "启动 JJDGuard 控制面与数据面"
compose up -d control-plane gateway-core
wait_http "JJDGuard 控制面" "http://127.0.0.1:${CONTROL_PORT}/health"
wait_http "JJDGuard 数据面" "http://127.0.0.1:${GATEWAY_PORT}/health"

login_local_admin "$ADMIN_PASSWORD"
[ "$login_code" = "200" ] || fail "JJDGuard 本地管理员初始登录失败（${login_code}）"
ADMIN_TOKEN="$(jq -er '.token | select(type == "string" and length > 0)' "$RESPONSE_FILE")"
jq -e '.password_change_required == true' "$RESPONSE_FILE" >/dev/null ||
  fail "bootstrap 管理员首次登录未要求改密"

password_payload="$(jq -n --arg current "$ADMIN_PASSWORD" --arg next "$ADMIN_ROTATED_PASSWORD" \
  '{current_password:$current,new_password:$next}')"
api_request POST /admin/v1/me/change-password "$password_payload" 200

login_local_admin "$ADMIN_ROTATED_PASSWORD"
[ "$login_code" = "200" ] || fail "JJDGuard 本地管理员改密后重新登录失败（${login_code}）"
ADMIN_TOKEN="$(jq -er '.token | select(type == "string" and length > 0)' "$RESPONSE_FILE")"
jq -e '.password_change_required == false' "$RESPONSE_FILE" >/dev/null ||
  fail "管理员改密后仍被要求再次改密"

stage "通过 JJDGuard API 保存、测试并发布企业 OIDC"
draft_payload="$(jq -n \
  --arg issuer "${UPSTREAM_PUBLIC_URL}/realms/upstream-enterprise" \
  --arg secret "$UPSTREAM_CLIENT_SECRET" \
  '{
    display_name:"企业账号",
    issuer_url:$issuer,
    client_id:"jjdguard-e2e-broker",
    client_secret:$secret,
    scopes:"openid email profile",
    subject_claim:"sub",
    username_claim:"preferred_username",
    name_claim:"name",
    email_claim:"email",
    phone_claim:"",
    dept_code_claim:"department",
    dept_name_claim:"",
    groups_claim:""
  }')"
api_request PUT /admin/v1/identity/sources/draft "$draft_payload" 200
SOURCE_ID="$(jq -er '.id' "$RESPONSE_FILE")"
api_request POST /admin/v1/identity/sources/test '' 200
jq -e '.success == true' "$RESPONSE_FILE" >/dev/null || fail "企业 OIDC 连接测试未通过"
pass "draft tested"

api_request POST /admin/v1/identity/sources/activate '' 200
api_request GET /admin/v1/identity/status '' 200
jq -e '.has_active == true and .publish_status == "active" and .drift == false' \
  "$RESPONSE_FILE" >/dev/null || fail "身份运行态未进入 active"
pass "runtime published"

stage "建立部门、应用与 SSO 属性映射"
team_payload='{"name":"E2E Security","create_app":true,"app_name":"E2E Security App","sso_department":"SEC-E2E"}'
api_request POST /admin/v1/teams "$team_payload" 201
TEAM_ID="$(jq -er '.team.id' "$RESPONSE_FILE")"
MAPPED_PROJECT_ID="$(jq -er '.app.id' "$RESPONSE_FILE")"
jq -e '.mapping_rule_id | type == "string" and length > 0' "$RESPONSE_FILE" >/dev/null ||
  fail "部门分组映射未创建"
mapping_payload="$(jq -n --arg team "$TEAM_ID" --arg project "$MAPPED_PROJECT_ID" \
  '{match_value:"SEC-E2E",mapped_team_id:$team,mapped_project_id:$project,priority:1,enabled:true}')"
api_request POST "/admin/v1/identity/dept-mappings?source_id=${SOURCE_ID}" "$mapping_payload" 200

CHAT_E2E_MODEL_ID="e2e-probe-model"
CHAT_E2E_MODEL_NAME="$CHAT_E2E_MODEL_ID"
stage "准备真实 Chat JIT 投影模型"
compose exec -T postgres psql -U jjdguard -d jjdguard -v ON_ERROR_STOP=1 \
  -v team_id="$TEAM_ID" -v model_id="$CHAT_E2E_MODEL_ID" -v model_name="$CHAT_E2E_MODEL_NAME" <<'SQL'
INSERT INTO providers (id,tenant_id,name,provider_type,base_url,auth_mode,is_default,status)
VALUES ('provider_e2e_probe','tenant_default','E2E Probe','openai','http://127.0.0.1:9','api_key',false,'active')
ON CONFLICT (id) DO UPDATE SET base_url=EXCLUDED.base_url,status=EXCLUDED.status;
INSERT INTO provider_credentials (id,provider_id,credential_name,secret_ciphertext,status)
VALUES ('credential_e2e_probe','provider_e2e_probe','e2e-probe','test-secret','active')
ON CONFLICT (id) DO UPDATE SET secret_ciphertext=EXCLUDED.secret_ciphertext,status=EXCLUDED.status;
INSERT INTO models (id,provider_id,model_name,model_label,status)
VALUES (:'model_id','provider_e2e_probe',:'model_name',:'model_name','active')
ON CONFLICT (id) DO UPDATE SET provider_id=EXCLUDED.provider_id,model_name=EXCLUDED.model_name,status=EXCLUDED.status;
INSERT INTO team_models (team_id,model_id,allowed,granted_by)
VALUES (:'team_id',:'model_id',TRUE,'user_admin')
ON CONFLICT (team_id,model_id) DO UPDATE SET allowed=EXCLUDED.allowed;
SQL

compose exec -T postgres psql -U jjdguard -d jjdguard -v ON_ERROR_STOP=1 \
  -c "UPDATE system_settings SET value='true' WHERE key='chat_portal_enabled'" >/dev/null

stage "启动员工门户与品牌化 SSO 边缘"
compose up -d chat-portal-proxy chat-portal-ui chat-edge
wait_http "JJDGuard SSO 边缘" "${JJD_SSO_PUBLIC_URL}/healthz"
wait_http "员工门户" "${PORTAL_PUBLIC_URL}/login"
compose exec -T -e E2E_PROJECT_ID="$MAPPED_PROJECT_ID" -e E2E_TEAM_ID="$TEAM_ID" \
  chat-portal-proxy node /app/e2e-portal-seed.mjs

stage "验证公共管理路径不可达"
for hidden_path in /admin /realms/jjdguard /resources/example.css /sso/admin /sso/realms/master; do
  hidden_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    "${JJD_SSO_PUBLIC_URL}${hidden_path}" || true)"
  case "$hidden_code" in
    403|404) ;;
    *) fail "公共身份管理路径 ${hidden_path} 返回 ${hidden_code}" ;;
  esac
done
discovery_code="$(curl -sS -o "$RESPONSE_FILE" -w '%{http_code}' --max-time 5 \
  "${JJD_SSO_PUBLIC_URL}/sso/realms/jjdguard/.well-known/openid-configuration")"
[ "$discovery_code" = "200" ] || fail "JJDGuard 业务 OIDC discovery 不可达"
jq -e --arg expected "${JJD_SSO_PUBLIC_URL}/sso/realms/jjdguard" '.issuer == $expected' \
  "$RESPONSE_FILE" >/dev/null || fail "JJDGuard 业务 OIDC issuer 与公开地址不一致"
if curl -sI --max-time 5 "${JJD_SSO_PUBLIC_URL}/sso/realms/jjdguard" | \
  grep -Eiq '^Server:.*(Keycloak|Caddy)'; then
  fail "公共身份响应泄漏底层实现 Server 头"
fi
pass "management paths hidden"

stage "验证本地管理员不依赖企业 SSO"
login_local_admin "$ADMIN_ROTATED_PASSWORD"
[ "$login_code" = "200" ] || fail "身份源发布后本地管理员登录失败"
jq -e '.user.role == "platform_admin" and (.token | type == "string" and length > 0)' \
  "$RESPONSE_FILE" >/dev/null || fail "本地管理员响应不符合预期"
pass "local admin login"

stage "使用 Playwright 完成员工企业 OIDC 登录"
PLAYWRIGHT_RUNNER_IMAGE="${IDENTITY_E2E_PLAYWRIGHT_RUNNER_IMAGE:-jjdguard-identity-e2e-playwright:1.55.0}"
if ! docker image inspect "$PLAYWRIGHT_RUNNER_IMAGE" >/dev/null 2>&1; then
  mkdir -p "$TMP_DIR/playwright-runner"
  cat >"$TMP_DIR/playwright-runner/Dockerfile" <<'DOCKERFILE'
FROM mcr.microsoft.com/playwright:v1.55.0-noble
WORKDIR /opt/e2e
RUN npm init -y >/dev/null 2>&1 \
    && npm install --no-audit --no-fund playwright@1.55.0 \
    && npm cache clean --force
ENV NODE_PATH=/opt/e2e/node_modules
DOCKERFILE
  if ! docker build -t "$PLAYWRIGHT_RUNNER_IMAGE" "$TMP_DIR/playwright-runner" \
    >"$ARTIFACT_DIR/playwright-build.log" 2>&1; then
    tail -n 60 "$ARTIFACT_DIR/playwright-build.log" >&2 || true
    fail "Playwright 运行镜像构建失败"
  fi
fi

PLAYWRIGHT_DOCKER_ENV=()
if [ -n "${IDENTITY_E2E_PLAYWRIGHT_CHROMIUM_PATH:-}" ]; then
  PLAYWRIGHT_DOCKER_ENV+=(-e "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=${IDENTITY_E2E_PLAYWRIGHT_CHROMIUM_PATH}")
fi
if [ -n "${IDENTITY_E2E_PLAYWRIGHT_NODE_PATH:-}" ]; then
  PLAYWRIGHT_DOCKER_ENV+=(-e "NODE_PATH=${IDENTITY_E2E_PLAYWRIGHT_NODE_PATH}")
fi

if ! docker run --rm --init --ipc=host --network bridge \
  --user "$(id -u):$(id -g)" \
  -e PORTAL_URL="$PORTAL_PUBLIC_URL" \
  -e UPSTREAM_PORT="$UPSTREAM_PORT" \
  -e SSO_PORT="$SSO_PORT" \
  -e UPSTREAM_USERNAME=e2e.employee \
  -e UPSTREAM_PASSWORD="$UPSTREAM_USER_PASSWORD" \
  -e E2E_CHAT_MODEL="$CHAT_E2E_MODEL_NAME" \
  "${PLAYWRIGHT_DOCKER_ENV[@]}" \
  -v "$ARTIFACT_DIR:/work" \
  "$PLAYWRIGHT_RUNNER_IMAGE" node /work/browser.js \
  >"$ARTIFACT_DIR/browser.log" 2>&1; then
  tail -n 60 "$ARTIFACT_DIR/browser.log" >&2 || true
  fail "Playwright 企业 OIDC 登录失败"
fi
[ -s "$ARTIFACT_DIR/browser-result.json" ] || fail "浏览器未产出身份结果"
CONTROL_PLANE_USER_ID="$(jq -er '.user_id' "$ARTIFACT_DIR/browser-result.json")"
# The portal profile is keyed by the control-plane user ID; keep the old
# artifact variable as a compatibility alias for the profile assertion below.
# Keep the legacy artifact name for the portal-profile assertion; its value is the control-plane user ID.
EXTERNAL_SUBJECT="$CONTROL_PLANE_USER_ID"
case "$CONTROL_PLANE_USER_ID" in
  ''|*[!A-Za-z0-9._:-]*) fail "浏览器返回的控制面 user_id 格式非法" ;;
esac
jq -e '.department == "SEC-E2E" and .role == "employee"' \
  "$ARTIFACT_DIR/browser-result.json" >/dev/null || fail "浏览器身份声明不正确"
jq -e '.chat_status != 403' "$ARTIFACT_DIR/browser-result.json" >/dev/null ||
  fail "真实 Chat 请求仍在门户模型门禁处被拒绝"
pass "browser OIDC login"

stage "验证用户归因、部门和应用映射"
wait_query_true "JJDGuard 员工用户同步" \
  "SELECT EXISTS(SELECT 1 FROM users u JOIN user_identity_links l ON l.user_id=u.id WHERE u.tenant_id='tenant_default' AND u.id='${CONTROL_PLANE_USER_ID}' AND l.source_type='oidc' AND l.external_subject <> '' AND u.role='developer' AND u.status='active')"
wait_query_true "JJDGuard 部门成员映射" \
  "SELECT EXISTS(SELECT 1 FROM users u JOIN team_members tm ON tm.user_id=u.id JOIN teams t ON t.id=tm.team_id WHERE u.tenant_id='tenant_default' AND u.id='${CONTROL_PLANE_USER_ID}' AND t.id='${TEAM_ID}')"
wait_query_true "JJDGuard 应用成员映射" \
  "SELECT EXISTS(SELECT 1 FROM users u JOIN project_users pu ON pu.user_id=u.id WHERE u.tenant_id='tenant_default' AND u.id='${CONTROL_PLANE_USER_ID}' AND pu.project_id='${MAPPED_PROJECT_ID}')"
wait_query_true "员工专属数据面密钥映射" \
  "SELECT EXISTS(SELECT 1 FROM users u JOIN internal_keys k ON k.user_id=u.id WHERE u.tenant_id='tenant_default' AND u.id='${CONTROL_PLANE_USER_ID}' AND k.project_id='${MAPPED_PROJECT_ID}' AND k.status='active')"

portal_profile="$(compose exec -T chat-postgres psql -U postgres -d enterprise_ai_portal \
  -At -F '|' -c "SELECT id,department,role FROM \"UserProfile\" WHERE id='${EXTERNAL_SUBJECT}'")"
[ "$portal_profile" = "${EXTERNAL_SUBJECT}|SEC-E2E|employee" ] ||
  fail "员工门户本地身份档案不正确"
pass "user provisioned and mapped"

stage "制造运行态漂移并通过 JJDGuard 修复"
"$TMP_DIR/kcadm" config credentials \
  --server http://localhost:8180/sso --realm master \
  --user admin --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null 2>&1
mapper_id="$("$TMP_DIR/kcadm" get \
  identity-provider/instances/enterprise/mappers -r jjdguard | \
  jq -er '.[] | select(.name | startswith("jjdguard-claim-")) | .id' | head -n 1)"
[ -n "$mapper_id" ] || fail "无法取得运行态 claim mapper"
"$TMP_DIR/kcadm" update \
  "identity-provider/instances/enterprise/mappers/${mapper_id}" -r jjdguard \
  -s 'config.claim=e2e-tampered-claim' >/dev/null

api_request GET /admin/v1/identity/status '' 200
jq -e '.publish_status == "drifted" and .drift == true' "$RESPONSE_FILE" >/dev/null ||
  fail "运行态结构漂移未被识别"
api_request POST /admin/v1/identity/sources/reconcile '' 200
api_request GET /admin/v1/identity/status '' 200
jq -e '.publish_status == "active" and .drift == false' "$RESPONSE_FILE" >/dev/null ||
  fail "漂移修复后未恢复 active"
pass "drift detected and reconciled"

stage "注入 Apply 后读回故障并验证旧配置回滚"
old_digest="$(compose exec -T postgres psql -U jjdguard -d jjdguard -tAc \
  "SELECT config_digest FROM identity_sources WHERE tenant_id='tenant_default' AND status='active'" | tr -d '[:space:]')"
case "$old_digest" in
  sha256:*) ;;
  *) fail "无法读取旧运行态摘要" ;;
esac

rollback_payload="$(jq -n \
  --arg issuer "${UPSTREAM_PUBLIC_URL}/realms/upstream-enterprise" \
  --arg secret "$UPSTREAM_CLIENT_SECRET" \
  '{
    display_name:"企业账号故障注入版本",
    issuer_url:$issuer,
    client_id:"jjdguard-e2e-broker",
    client_secret:$secret,
    scopes:"openid email profile",
    subject_claim:"sub",
    username_claim:"preferred_username",
    name_claim:"name",
    email_claim:"email",
    phone_claim:"",
    dept_code_claim:"department",
    dept_name_claim:"",
    groups_claim:""
  }')"
api_request PUT /admin/v1/identity/sources/draft "$rollback_payload" 200
api_request POST /admin/v1/identity/sources/test '' 200
jq -e '.success == true' "$RESPONSE_FILE" >/dev/null || fail "故障注入版本连接测试未通过"

compose exec -T chat-idp node -e \
  "fetch('http://127.0.0.1:8180/__e2e/fault',{method:'POST'}).then(r=>process.exit(r.status===204?0:1)).catch(()=>process.exit(1))"

activate_code="$(printf '' | curl -sS --max-time 30 -o "$RESPONSE_FILE" -w '%{http_code}' \
  -X POST "http://127.0.0.1:${CONTROL_PORT}/admin/v1/identity/sources/activate" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" --data-binary @-)"
case "$activate_code" in
  2??) fail "故障注入后发布仍意外成功" ;;
esac

api_request GET /admin/v1/identity/status '' 200
jq -e '.publish_status == "active" and .drift == false' "$RESPONSE_FILE" >/dev/null ||
  fail "发布失败后旧活动配置未恢复"
active_digest="$(compose exec -T postgres psql -U jjdguard -d jjdguard -tAc \
  "SELECT config_digest FROM identity_sources WHERE tenant_id='tenant_default' AND status='active'" | tr -d '[:space:]')"
[ "$active_digest" = "$old_digest" ] || fail "发布失败后数据库活动摘要发生变化"

provider_json="$("$TMP_DIR/kcadm" get identity-provider/instances/enterprise -r jjdguard)"
jq -e --arg digest "$old_digest" \
  '.enabled == true and .config.jjdguardConfigDigest == $digest' \
  <<<"$provider_json" >/dev/null || fail "发布失败后旧 provider 未保持 enabled"
pass "failed apply rolled back"

stage "验证身份服务停机不影响 API Key 数据面"
key_payload='{"project_id":"project_default","name":"identity-e2e-data-plane","scopes":["models"]}'
api_request POST /admin/v1/keys "$key_payload" 200
DATA_PLANE_KEY="$(jq -er '.full_key | select(type == "string" and length > 0)' "$RESPONSE_FILE")"

models_code="$(curl -sS --max-time 15 -o "$RESPONSE_FILE" -w '%{http_code}' \
  -H "Authorization: Bearer ${DATA_PLANE_KEY}" \
  "http://127.0.0.1:${GATEWAY_PORT}/v1/models")"
[ "$models_code" = "200" ] || fail "身份服务停机前 API Key 数据面请求失败"
jq -e '.object == "list" and (.data | type == "array")' "$RESPONSE_FILE" >/dev/null ||
  fail "API Key 数据面响应格式错误"

compose stop chat-idp identity-engine >/dev/null
models_code="$(curl -sS --max-time 15 -o "$RESPONSE_FILE" -w '%{http_code}' \
  -H "Authorization: Bearer ${DATA_PLANE_KEY}" \
  "http://127.0.0.1:${GATEWAY_PORT}/v1/models")"
DATA_PLANE_KEY=""
[ "$models_code" = "200" ] || fail "身份服务停机后 API Key 数据面中断"
jq -e '.object == "list" and (.data | type == "array")' "$RESPONSE_FILE" >/dev/null ||
  fail "身份服务停机后数据面响应格式错误"
pass "data plane independent from identity runtime"

printf '\nidentity SSO e2e passed\n'
