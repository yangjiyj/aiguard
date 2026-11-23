#!/usr/bin/env bash
# 公开 SSO 基址解析器的行为合约；只使用临时 .env，不接触实际部署配置。

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT_DIR/deploy/docker-compose/chat/ensure-public-sso-url.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

[ -x "$SCRIPT" ] || fail "缺少可执行 ensure-public-sso-url.sh"

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

assert_eq() {
  local expected="$1" actual="$2" message="$3"
  [ "$expected" = "$actual" ] || fail "$message: expected=$expected actual=$actual"
}

assert_file_value() {
  local file="$1" key="$2" expected="$3"
  grep -qx "$(printf '%s=%s' "$key" "$expected")" "$file" || fail "$file 缺少 $key=$expected"
}

count_key() {
  local file="$1" key="$2"
  grep -c "^$(printf '%s' "$key")=" "$file" 2>/dev/null || true
}

# 显式公开地址优先，且只保留一个规范化键。
explicit_env="$fixture/explicit.env"
cat >"$explicit_env" <<'EOF'
JJD_SSO_PUBLIC_URL=https://sso.customer.example/
CHAT_OIDC_HOST=10.20.30.40
CHAT_IDP_PORT=9080
KEEP_ME=present
SECRET_MUST_NOT_PRINT=hidden
EOF
explicit_output="$(JJD_ENV_FILE="$explicit_env" bash "$SCRIPT")"
assert_eq "https://sso.customer.example" "$explicit_output" "显式 HTTPS 地址未规范化"
assert_file_value "$explicit_env" JJD_SSO_PUBLIC_URL "https://sso.customer.example"
assert_file_value "$explicit_env" JJD_SSO_ALLOW_INSECURE_PUBLIC_URL "false"
assert_eq "1" "$(count_key "$explicit_env" JJD_SSO_PUBLIC_URL)" "显式地址重复写入"
grep -q 'hidden' "$explicit_env" || fail "测试 fixture 被意外破坏"

# 已有 Web 入口配置时，SSO 与 Chat 复用同一公开 origin，并在第二次运行时保持不漂移。
derived_env="$fixture/derived.env"
cat >"$derived_env" <<'EOF'
CHAT_OIDC_HOST=10.20.30.40
WEB_HTTPS_PORT=9443
TLS_ENABLED=true
EOF
derived_output="$(JJD_ENV_FILE="$derived_env" bash "$SCRIPT")"
assert_eq "https://10.20.30.40:9443" "$derived_output" "未按 Web HTTPS 入口生成地址"
assert_file_value "$derived_env" JJD_SSO_PUBLIC_URL "https://10.20.30.40:9443"
assert_file_value "$derived_env" JJD_SSO_ALLOW_INSECURE_PUBLIC_URL "false"
CHAT_OIDC_HOST=10.20.30.41 JJD_ENV_FILE="$derived_env" bash "$SCRIPT" >/dev/null
assert_file_value "$derived_env" JJD_SSO_PUBLIC_URL "https://10.20.30.40:9443"
assert_eq "1" "$(count_key "$derived_env" JJD_SSO_PUBLIC_URL)" "重复运行产生公开地址重复键"
assert_eq "1" "$(count_key "$derived_env" JJD_SSO_ALLOW_INSECURE_PUBLIC_URL)" "重复运行产生安全模式重复键"

# 无 Chat 主机时使用默认路由的非回环 IPv4。
fakebin="$fixture/fake-bin"
mkdir -p "$fakebin"
cat >"$fakebin/ip" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "route get 1.1.1.1")
    printf '%s\n' '1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.44 uid 0'
    ;;
  *)
    exit 1
    ;;
esac
EOF
cat >"$fakebin/hostname" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod 700 "$fakebin/ip" "$fakebin/hostname"
route_env="$fixture/route.env"
: >"$route_env"
route_output="$(PATH="$fakebin:$PATH" JJD_ENV_FILE="$route_env" bash "$SCRIPT")"
assert_eq "https://192.0.2.44" "$route_output" "未使用默认 Web HTTPS 地址"
assert_file_value "$route_env" JJD_SSO_PUBLIC_URL "https://192.0.2.44"

# 没有可用网卡地址时回退本机地址。
cat >"$fakebin/ip" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
fallback_env="$fixture/fallback.env"
: >"$fallback_env"
fallback_output="$(PATH="$fakebin:$PATH" JJD_ENV_FILE="$fallback_env" bash "$SCRIPT")"
assert_eq "https://127.0.0.1" "$fallback_output" "无可用地址时未回退 Web HTTPS 本机地址"

# 非 HTTP(S) origin、路径和非法端口必须拒绝，且不得写入半成品。
invalid_env="$fixture/invalid.env"
cat >"$invalid_env" <<'EOF'
JJD_SSO_PUBLIC_URL=ftp://sso.customer.example
EOF
if JJD_ENV_FILE="$invalid_env" bash "$SCRIPT" >/dev/null 2>"$fixture/invalid.err"; then
  fail "非法 scheme 被接受"
fi
grep -q '^JJD_SSO_PUBLIC_URL=ftp://' "$invalid_env" || fail "非法值被意外改写"

invalid_path_env="$fixture/invalid-path.env"
cat >"$invalid_path_env" <<'EOF'
JJD_SSO_PUBLIC_URL=https://sso.customer.example/sso
EOF
if JJD_ENV_FILE="$invalid_path_env" bash "$SCRIPT" >/dev/null 2>&1; then
  fail "带路径的公开地址被接受"
fi

invalid_port_env="$fixture/invalid-port.env"
cat >"$invalid_port_env" <<'EOF'
CHAT_OIDC_HOST=10.20.30.40
WEB_HTTPS_PORT=70000
EOF
if JJD_ENV_FILE="$invalid_port_env" bash "$SCRIPT" >/dev/null 2>&1; then
  fail "非法端口被接受"
fi
! grep -q '^JJD_SSO_PUBLIC_URL=' "$invalid_port_env" || fail "非法端口产生了半成品地址"

# 通配绑定地址绝不能被当成公开地址。
# 现场症状就是 callbackUrl=http://0.0.0.0:3100/ —— 0.0.0.0 是监听绑定地址，
# 浏览器跳过去必然失败。自动探测分支本来就排除 0.*，但已持久化的值会被
# 原样沿用，于是通配地址固化下来。这里锁死三条路径都要被纠正。
cat >"$fakebin/ip" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "route get 1.1.1.1")
    printf '%s\n' '1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.44 uid 0'
    ;;
  *)
    exit 1
    ;;
esac
EOF
chmod 700 "$fakebin/ip"

# 1) 已持久化的通配公开地址必须被迁移为真实地址，端口保持不变。
persisted_wildcard_env="$fixture/persisted-wildcard.env"
cat >"$persisted_wildcard_env" <<'EOF'
JJD_SSO_PUBLIC_URL=http://0.0.0.0:8180
EOF
persisted_wildcard_output="$(PATH="$fakebin:$PATH" JJD_ENV_FILE="$persisted_wildcard_env" bash "$SCRIPT")"
assert_eq "http://192.0.2.44:8180" "$persisted_wildcard_output" "已持久化的通配公开地址未被迁移"
assert_file_value "$persisted_wildcard_env" JJD_SSO_PUBLIC_URL "http://192.0.2.44:8180"
assert_eq "1" "$(count_key "$persisted_wildcard_env" JJD_SSO_PUBLIC_URL)" "迁移通配地址产生重复键"
! grep -q '0\.0\.0\.0' "$persisted_wildcard_env" || fail "环境文件仍残留通配地址"

# 2) CHAT_OIDC_HOST 是通配地址时也不能沿用。
wildcard_host_env="$fixture/wildcard-host.env"
cat >"$wildcard_host_env" <<'EOF'
CHAT_OIDC_HOST=0.0.0.0
CHAT_IDP_PORT=8180
EOF
wildcard_host_output="$(PATH="$fakebin:$PATH" JJD_ENV_FILE="$wildcard_host_env" bash "$SCRIPT")"
assert_eq "https://192.0.2.44" "$wildcard_host_output" "通配 CHAT_OIDC_HOST 未被纠正"

# 3) IPv6 通配同样不可用。
ipv6_wildcard_env="$fixture/ipv6-wildcard.env"
cat >"$ipv6_wildcard_env" <<'EOF'
JJD_SSO_PUBLIC_URL=http://[::]:8180
EOF
ipv6_wildcard_output="$(PATH="$fakebin:$PATH" JJD_ENV_FILE="$ipv6_wildcard_env" bash "$SCRIPT")"
assert_eq "http://192.0.2.44:8180" "$ipv6_wildcard_output" "IPv6 通配地址未被纠正"

# 4) 已经是真实地址时绝不能被改动（迁移必须只针对通配地址）。
stable_env="$fixture/stable.env"
cat >"$stable_env" <<'EOF'
JJD_SSO_PUBLIC_URL=https://sso.customer.example
EOF
stable_output="$(PATH="$fakebin:$PATH" JJD_ENV_FILE="$stable_env" bash "$SCRIPT")"
assert_eq "https://sso.customer.example" "$stable_output" "真实公开地址被误改"
assert_file_value "$stable_env" JJD_SSO_PUBLIC_URL "https://sso.customer.example"

pass "通配绑定地址迁移合约通过"

pass "公开 SSO 默认地址解析合约通过"
