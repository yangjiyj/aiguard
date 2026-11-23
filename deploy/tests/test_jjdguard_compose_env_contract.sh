#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
. deploy/tests/lib/jjdguard_contract_env.sh
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
env_file="$tmpdir/contract.env"
write_jjdguard_contract_env "$env_file"
# 宿主环境里的同名变量会覆盖 --env-file 插值，先清掉，断言只看模板和下面写入的值。
unset BILLING_ENABLED GATEWAY_PUBLIC_URL GATEWAY_PUBLIC_BASE_URL GATEWAY_PUBLIC_ALIASES GATEWAY_STREAM_KEEPALIVE_INTERVAL
defaults_env="$tmpdir/defaults.env"
cp "$env_file" "$defaults_env"
# AgentShield 联动的出口清单接口（/admin/v1/integration/upstreams）只读 control-plane
# 进程环境里的这两个变量；模板漏传时该接口恒为 503 gateway_public_url_unavailable。
printf '%s\n' \
  'GATEWAY_PUBLIC_BASE_URL=https://gateway.contract.test:28880' \
  'GATEWAY_PUBLIC_ALIASES=https://tls-edge.contract.test:28880,https://192.0.2.20:28880' >>"$env_file"
compose_files=(
  deploy/docker-compose/docker-compose.yml
  deploy/docker-compose/docker-compose.offline.yml
  enterprise-ai-portal/compose.yml
)
: >"$tmpdir/environment-keys.tsv"
for compose in "${compose_files[@]}"; do
  docker compose --profile '*' --env-file "$env_file" -f "$compose" config --quiet
  docker compose --profile '*' --env-file "$env_file" -f "$compose" config --format json |
    jq -r --arg file "$compose" '
      .services | to_entries[] | .key as $service |
      (.value.environment // {} | keys[]) |
      [$file, $service, .] | @tsv
    ' >>"$tmpdir/environment-keys.tsv"
done

while IFS=$'\t' read -r compose service key; do
  case "$key" in
    NEWAPI_*)
      if [[ "$service" != "chat-portal-proxy" || "$key" != "NEWAPI_PORTAL_API_SECRET" || "$compose" == "enterprise-ai-portal/compose.yml" ]]; then
        printf 'forbidden legacy environment key: %s/%s/%s\n' "$compose" "$service" "$key" >&2
        exit 1
      fi
      ;;
  esac
done <"$tmpdir/environment-keys.tsv"

for compose in deploy/docker-compose/docker-compose.yml deploy/docker-compose/docker-compose.offline.yml; do
  json="$tmpdir/$(basename "$compose").json"
  docker compose --profile '*' --env-file "$env_file" -f "$compose" config --format json >"$json"
  jq -e '.services["chat-portal-ui"].image == "enterprise-ai-portal:0.2.0-slim"' "$json" >/dev/null
  jq -e '.services["chat-portal-ui"].environment.JJD_CP_URL == "http://jjdguard-portal-control-plane:8081"' "$json" >/dev/null
  jq -e '.services["chat-portal-ui"].environment.JJD_PORTAL_API_SECRET != null' "$json" >/dev/null
	jq -e '.services["chat-portal-ui"].environment.GATEWAY_PUBLIC_URL == "https://gateway.contract.test"' "$json" >/dev/null
  jq -e '.services["chat-portal-ui"].environment.OIDC_ENTERPRISE_IDP_HINT == "enterprise"' "$json" >/dev/null
  jq -e '.services["chat-portal-ui"].environment.OIDC_ACCOUNT_LOGIN_ENABLED == "true"' "$json" >/dev/null
  jq -e '.services["gateway-core"].environment.BILLING_ENABLED == "false"' "$json" >/dev/null
  jq -e '.services["gateway-core"].environment.BILLING_CUSTOMER_GROUP == "default"' "$json" >/dev/null
  # 先攒后发流式保活默认 15s；曾因 :-0 渲染成关闭，导致慢请求仍被中间层空闲超时掐断。
  if ! jq -e '.services["gateway-core"].environment.GATEWAY_STREAM_KEEPALIVE_INTERVAL == "15s"' "$json" >/dev/null; then
    printf 'gateway-core must default GATEWAY_STREAM_KEEPALIVE_INTERVAL to 15s in %s\n' "$compose" >&2
    exit 1
  fi
  # 只写进 docs 而没进 compose 的开关在容器里不存在：改 .env 无效，等于没有这个开关。
  if ! jq -e '.services["gateway-core"].environment.GATEWAY_FP_HISTORY_TASK_AGNOSTIC == "false"' "$json" >/dev/null; then
    printf 'gateway-core must pass GATEWAY_FP_HISTORY_TASK_AGNOSTIC (default false) in %s\n' "$compose" >&2
    exit 1
  fi
  jq -e '.services["control-plane"].environment.BILLING_ENABLED == "false"' "$json" >/dev/null
  jq -e '.services["control-plane"].environment.BILLING_DEFAULT_CURRENCY == "CNY"' "$json" >/dev/null
  jq -e '.services["control-plane"].environment.BILLING_TIMEZONE == "Asia/Shanghai"' "$json" >/dev/null
  jq -e '.services["control-plane"].environment.BILLING_REQUEST_LEASE_TTL == "35m"' "$json" >/dev/null
  if ! jq -e '.services["control-plane"].environment.GATEWAY_PUBLIC_BASE_URL == "https://gateway.contract.test:28880"' "$json" >/dev/null ||
     ! jq -e '.services["control-plane"].environment.GATEWAY_PUBLIC_ALIASES == "https://tls-edge.contract.test:28880,https://192.0.2.20:28880"' "$json" >/dev/null; then
    printf 'control-plane must receive GATEWAY_PUBLIC_BASE_URL and GATEWAY_PUBLIC_ALIASES in %s\n' "$compose" >&2
    exit 1
  fi
  # 未配置时也要以空值声明，不能用 :? 让没配这两项的老部署起不来；接口会按 503 明确报未配置。
  defaults_json="$tmpdir/$(basename "$compose").defaults.json"
  docker compose --profile '*' --env-file "$defaults_env" -f "$compose" config --format json >"$defaults_json"
  if ! jq -e '.services["control-plane"].environment | (.GATEWAY_PUBLIC_BASE_URL == "") and (.GATEWAY_PUBLIC_ALIASES == "")' "$defaults_json" >/dev/null; then
    printf 'control-plane must declare empty GATEWAY_PUBLIC_BASE_URL/GATEWAY_PUBLIC_ALIASES defaults in %s\n' "$compose" >&2
    exit 1
  fi
  jq -e '.services["chat-portal-ui"].environment.NEXT_PUBLIC_BILLING_ENABLED == "false"' "$json" >/dev/null
  if [[ "$compose" != *offline.yml ]]; then
    jq -e '.services["web-console"].build.args.VITE_BILLING_ENABLED == "false"' "$json" >/dev/null
  fi
  jq -e '.services["tier1-classifier"].environment.NEWAPI_INTERNAL_API_SECRET == null' "$json" >/dev/null
  for service in gateway-core control-plane worker proxy-server; do
	jq -e --arg service "$service" '.services[$service].environment.GATEWAY_ENVIRONMENT_SCOPE == "customer"' "$json" >/dev/null
  done
  if [[ "$compose" == *offline.yml ]]; then
    jq -e '.services["tier1-classifier"].environment.JJD_TIER1_INTERNAL_TOKEN != null' "$json" >/dev/null
  else
	jq -e '.services["proxy-server-vm"].environment.GATEWAY_ENVIRONMENT_SCOPE == "customer"' "$json" >/dev/null
  fi
  jq -e '.services["control-plane"].networks | has("jjdguard-portal-control")' "$json" >/dev/null
  jq -e '.services["chat-portal-ui"].networks | has("jjdguard-portal-control")' "$json" >/dev/null
  jq -e '[.services | to_entries[] | select(.value.networks | has("jjdguard-portal-control")) | .key] | sort == ["chat-portal-ui", "control-plane"]' "$json" >/dev/null
  if ! jq -e '.services["security-engine"].environment.SECURITY_NODE_ID == "security-engine:primary"' "$json" >/dev/null; then
    printf 'security-engine must use a stable SECURITY_NODE_ID in %s\n' "$compose" >&2
    exit 1
  fi
  if ! jq -e '.services["security-engine"].environment | has("JJD_COMMIT")' "$json" >/dev/null; then
    printf 'security-engine must receive the release JJD_COMMIT in %s\n' "$compose" >&2
    exit 1
  fi
  jq -e '.services.postgres.healthcheck.start_period == "15m0s"' "$json" >/dev/null
  jq -e '.services["security-engine"].healthcheck.start_period == "10m0s"' "$json" >/dev/null
  if [[ "$compose" == *offline.yml ]]; then
    jq -e '.services["tier1-classifier"].healthcheck.start_period == "15m0s"' "$json" >/dev/null
  fi
  jq -e '.services["chat-portal-ui"].healthcheck.start_period == "10m0s"' "$json" >/dev/null
  jq -e '.services["gateway-core"].environment.SECURITY_SEMANTIC_AGENT_ENABLED == "true"' "$json" >/dev/null
  jq -e '.services["gateway-core"].environment.RETENTION_STORE_PATH == "/var/lib/jjdguard/retention"' "$json" >/dev/null
  if ! jq -e '.services["gateway-core"].volumes | any(.type == "volume" and .source == "retention-data" and .target == "/var/lib/jjdguard/retention")' "$json" >/dev/null; then
    printf 'gateway-core must mount retention-data read-write in %s\n' "$compose" >&2
    exit 1
  fi
  # 部署只审计锁必须注入全部执行拦截的服务（含正向代理），否则 env=true 对该服务无效。
  for service in gateway-core control-plane security-engine proxy-server; do
    if ! jq -e --arg service "$service" '.services[$service].environment.SECURITY_AUDIT_ONLY == "false"' "$json" >/dev/null; then
      printf 'deployment audit-only ceiling must default false for %s in %s\n' "$service" "$compose" >&2
      exit 1
    fi
  done
  if jq -e '.services | has("proxy-server-vm")' "$json" >/dev/null; then
    if ! jq -e '.services["proxy-server-vm"].environment.SECURITY_AUDIT_ONLY == "false"' "$json" >/dev/null; then
      printf 'deployment audit-only ceiling must default false for proxy-server-vm in %s\n' "$compose" >&2
      exit 1
    fi
  fi
  jq -e '.services["security-engine"].environment.SECURITY_SEMANTIC_ENABLED == "true"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_SEMANTIC_INPUT_ENABLED == "true"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_SEMANTIC_OUTPUT_ENABLED == "false"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_SEMANTIC_TOTAL_TIMEOUT == "9"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_LLM_JUDGE_TIMEOUT == "8"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_TIER1_ENABLED == "true"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_TIER1_LOW_THRESHOLD == "0.30"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_TIER1_HIGH_THRESHOLD == "0.70"' "$json" >/dev/null
  for service in gateway-core control-plane security-engine proxy-server; do
    if ! jq -e --arg service "$service" '.services[$service].environment.SECURITY_FILE_CONTENT_DLP_ENABLED == "false"' "$json" >/dev/null; then
      printf 'file content DLP deployment gate must default false for %s in %s\n' "$service" "$compose" >&2
      exit 1
    fi
  done
  jq -e '.services["security-engine"].environment.SECURITY_SCAN_STORE_DIR == "/var/lib/jjdguard/scan-store"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_SCAN_STORE_DEPLOY_MAX_MB == "100"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_SCAN_STORE_HIGH_WATERMARK_MB == "512"' "$json" >/dev/null
  jq -e '.services["security-engine"].environment.SECURITY_SCAN_ADMIT_GLOBAL_CONCURRENT == "4"' "$json" >/dev/null
  if ! jq -e '.services["security-engine"].tmpfs | any(startswith("/var/lib/jjdguard/scan-store:"))' "$json" >/dev/null; then
    printf 'security-engine scan store must use a bounded tmpfs in %s\n' "$compose" >&2
    exit 1
  fi
  jq -e '.services["security-engine"].tmpfs | any(contains("size=512m"))' "$json" >/dev/null
  jq -e '.services["security-engine"].tmpfs | any(contains("mode=0700"))' "$json" >/dev/null
done

standalone="$tmpdir/standalone.json"
docker compose --profile '*' --env-file "$env_file" -f enterprise-ai-portal/compose.yml config --format json >"$standalone"
jq -e '.services.web.image == "enterprise-ai-portal:0.2.0-slim"' "$standalone" >/dev/null
jq -e '.services.web.environment.JJD_CP_URL == "http://jjdguard-portal-control-plane:8081"' "$standalone" >/dev/null
jq -e '.services.web.environment.JJD_PORTAL_API_SECRET != null' "$standalone" >/dev/null
jq -e '.services.web.environment.GATEWAY_PUBLIC_URL == "https://gateway.contract.test"' "$standalone" >/dev/null
jq -e '.services.web.environment.NEXT_PUBLIC_BILLING_ENABLED == "false"' "$standalone" >/dev/null
jq -e '.services.web.build.args.NEXT_PUBLIC_BILLING_ENABLED == "false"' "$standalone" >/dev/null
jq -e '.services.web.networks | has("jjdguard-portal-control")' "$standalone" >/dev/null
jq -e '.services.web.networks | has("jjdguard-portal-net")' "$standalone" >/dev/null
jq -e '.services.web.networks | has("newapi-net") | not' "$standalone" >/dev/null

test "$(awk '$1 == "enterprise-ai-portal:0.2.0-slim" && $2 == "chat" {n++} END {print n+0}' deploy/docker-compose/images.lst)" = 1
test "$(grep -c 'enterprise-ai-portal:0.1.0' deploy/docker-compose/images.lst || true)" = 0
test "$(grep -R -h 'image: enterprise-ai-portal:0.1.0' deploy/docker-compose/docker-compose.yml deploy/docker-compose/docker-compose.offline.yml enterprise-ai-portal/compose.yml | wc -l)" = 0
grep -qx 'BILLING_REQUEST_LEASE_TTL=35m' deploy/docker-compose/.env.example
grep -qx 'GATEWAY_PUBLIC_URL=' deploy/docker-compose/.env.example
for key in GATEWAY_PUBLIC_BASE_URL GATEWAY_PUBLIC_ALIASES; do
  if ! grep -qx "$key=" deploy/docker-compose/.env.example; then
    printf 'customer env template must document an empty %s\n' "$key" >&2
    exit 1
  fi
done
grep -qx 'SECURITY_AUDIT_ONLY=false' deploy/docker-compose/.env.example
for generator in deploy/docker-compose/deploy-oneclick.sh deploy/docker-compose/deploy-offline.sh; do
  test "$(grep -c '^SECURITY_AUDIT_ONLY=false$' "$generator")" = 1
  test "$(grep -c '^SECURITY_AUDIT_ONLY=true$' "$generator" || true)" = 0
done

# Execute the online generator's fresh/existing branches without reaching Docker.
oneclick_case="$tmpdir/oneclick/deploy/docker-compose"
mkdir -p "$oneclick_case" "$oneclick_case/../lib"
# 安装脚本开头 source 共享的安全 .env 读取库；夹具按正式包的相对位置放一份。
cp deploy/lib/jjd-env.sh "$oneclick_case/../lib/"
awk '/^load_env\(\)/ { exit } { print }' deploy/docker-compose/deploy-oneclick.sh >"$oneclick_case/deploy-oneclick.sh"
printf '\nensure_env\n' >>"$oneclick_case/deploy-oneclick.sh"
chmod 0700 "$oneclick_case/deploy-oneclick.sh"
(cd "$oneclick_case" && sh ./deploy-oneclick.sh >/dev/null)
grep -Fqx 'SECURITY_AUDIT_ONLY=false' "$oneclick_case/.env"
printf 'SECURITY_AUDIT_ONLY=true\n' >"$oneclick_case/.env"
(cd "$oneclick_case" && sh ./deploy-oneclick.sh >/dev/null)
grep -Fqx 'SECURITY_AUDIT_ONLY=true' "$oneclick_case/.env"
test "$(grep -c '^SECURITY_AUDIT_ONLY=false$' "$oneclick_case/.env" || true)" = 0

grep -Fq "('security_audit_only', 'true', NOW())" deploy/migrations/139_semantic_bundled_defaults.sql
# Fresh installs start in record mode via migration 139 while the deployment
# lock stays off, so the console can switch to protect. Any other migration that
# touches the execution-mode keys could silently change that default (or lock /
# unlock existing customers); it must be reviewed and added here explicitly.
mode_migrations="$(grep -lE 'security_audit_only|security_execution_mode' deploy/migrations/*.sql | sort | tr '\n' ' ')"
if [ "$mode_migrations" != "deploy/migrations/139_semantic_bundled_defaults.sql deploy/migrations/140_agent_destructive_operation_governance.sql " ]; then
	printf 'unexpected migrations touch the execution-mode keys (review fresh-install record default): %s\n' "$mode_migrations" >&2
	exit 1
fi
if grep -iE '(insert|update)[^;]*security_execution_mode' deploy/migrations/*.sql >/dev/null; then
	printf 'migrations must not write security_execution_mode; it is chosen in the console\n' >&2
	exit 1
fi
if grep -Fq '100.64.0.21' deploy/docker-compose/.env.example; then
	printf 'customer env template must not hard-code the home gateway address\n' >&2
	exit 1
fi
# 本契约必须随候选包静态闸执行；只靠人工执行时，模板漏传变量照样能出包（2.9.4～2.9.6 即如此）。
candidate_gate="$(sed -n '/^run_candidate_static_gates()/,/^}/p' deploy/docker-compose/package-offline-bundle.sh)"
if [[ "$candidate_gate" != *'test_jjdguard_compose_env_contract.sh'* ]]; then
  printf 'candidate package gate must run the compose environment contract\n' >&2
  exit 1
fi

printf 'compose_env_contract=ok files=3 legacy_exceptions=2 portal_tag=enterprise-ai-portal:0.2.0-slim\n'
