#!/usr/bin/env bash
# 解析并持久化 Chat 使用的公开 SSO origin。
# stdout 只返回最终地址；错误和安全提示走 stderr，避免把环境内容带入日志。

set -eo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMPOSE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$COMPOSE_DIR/.env"
if [ -n "$JJD_ENV_FILE" ]; then
  ENV_FILE="$JJD_ENV_FILE"
fi

tmp_file=""

fail() {
  echo "[error] $*" >&2
  exit 1
}

cleanup() {
  if [ -n "$tmp_file" ] && [ -f "$tmp_file" ]; then
    rm -f "$tmp_file"
  fi
}
trap cleanup EXIT HUP INT TERM

read_env_value() {
  key="$1"
  if [ -f "$ENV_FILE" ]; then
    sed -n "s/^$key=//p" "$ENV_FILE" | tail -n 1
  fi
}

valid_ipv4() {
  candidate="$1"
  printf '%s\n' "$candidate" |
    awk -F. 'NF == 4 { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1; exit 0 } { exit 1 }' ||
    return 1
  case "$candidate" in
    0.*|127.*|169.254.*) return 1 ;;
  esac
}

detect_host() {
  route_source=""
  if command -v ip >/dev/null 2>&1; then
    route_source="$(ip route get 1.1.1.1 2>/dev/null |
      awk '{ for (i = 1; i <= NF; i++) if ($i == "src" && i < NF) { print $(i + 1); exit } }' |
      head -n 1 || true)"
    if valid_ipv4 "$route_source"; then
      printf '%s' "$route_source"
      return 0
    fi

    for candidate in $(ip -o -4 addr show scope global 2>/dev/null |
      awk '$2 !~ /^(docker|br-|veth|virbr)/ { split($4, a, "/"); print a[1] }' || true); do
      if valid_ipv4 "$candidate"; then
        printf '%s' "$candidate"
        return 0
      fi
    done
  fi

  if command -v hostname >/dev/null 2>&1; then
    for candidate in $(hostname -I 2>/dev/null || true); do
      if valid_ipv4 "$candidate"; then
        printf '%s' "$candidate"
        return 0
      fi
    done
  fi

  printf '127.0.0.1'
}

validate_port() {
  local port="$1"
  local port_name="${2:-CHAT_IDP_PORT}"
  case "$port" in
    ''|*[!0-9]*) fail "$port_name 必须是 1 到 65535 的数字" ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    fail "$port_name 必须是 1 到 65535"
  fi
}

validate_host() {
  host="$1"
  [ -n "$host" ] || fail "公开 SSO 地址缺少主机"

  case "$host" in
    *:*)
      printf '%s' "$host" | grep -Eq '^[0-9A-Fa-f:.]+$' ||
        fail "公开 SSO 地址的 IPv6 主机格式非法"
      ;;
    *)
      printf '%s' "$host" | grep -Eq '^[A-Za-z0-9._-]+$' ||
        fail "公开 SSO 地址的主机格式非法"
      ;;
  esac
}

# 通配绑定地址不是可达地址：0.0.0.0 / :: / [::] 只表示「监听所有网卡」，
# 浏览器跳到它必然失败（现场就是 callbackUrl=http://0.0.0.0:3100/）。
is_wildcard_host() {
  case "$1" in
    # 注意加引号：未加引号的 [::] 是字符类（只匹配单个 :），不是字面量。
    # normalize_origin 已剥掉方括号，IPv6 通配到这里是 ::；带括号形式一并兜住。
    0.0.0.0|::|'[::]'|0000:0000:0000:0000:0000:0000:0000:0000) return 0 ;;
  esac
  return 1
}

# 只替换主机，保留 scheme 与端口：迁移的目的是让地址可达，不是改端口。
replace_origin_host() {
  origin_scheme="$1"
  origin_host="$2"
  origin_port="$3"
  case "$origin_host" in
    *:*) origin_host="[$origin_host]" ;;
  esac
  if [ -n "$origin_port" ]; then
    printf '%s://%s:%s' "$origin_scheme" "$origin_host" "$origin_port"
  else
    printf '%s://%s' "$origin_scheme" "$origin_host"
  fi
}

normalize_origin() {
  url="$1"
  authority=""
  host=""
  port=""
  suffix=""
  url="$(printf '%s' "$url" | sed 's:/*$::')"

  case "$url" in
    http://*) authority="$(printf '%s' "$url" | sed 's#^http://##')" ;;
    https://*) authority="$(printf '%s' "$url" | sed 's#^https://##')" ;;
    *) fail "JJD_SSO_PUBLIC_URL 必须是 http(s) origin" ;;
  esac

  case "$authority" in
    ''|*/*|*\?*|*\#*|*@*|*[[:space:]]*|*\\*) fail "JJD_SSO_PUBLIC_URL 含非法路径或字符" ;;
  esac

  case "$authority" in
    \[*\]*)
      host="$(printf '%s' "$authority" | sed 's/].*$//; s/^\[//')"
      suffix="$(printf '%s' "$authority" | sed 's/^[^]]*]//')"
      validate_host "$host"
      case "$suffix" in
        '') ;;
        :*)
          port="$(printf '%s' "$suffix" | sed 's/^://')"
          validate_port "$port"
          ;;
        *) fail "JJD_SSO_PUBLIC_URL 的 IPv6 端口格式非法" ;;
      esac
      ;;
    *:*)
      case "$authority" in
        *:*:*) fail "JJD_SSO_PUBLIC_URL 的 IPv6 地址必须使用方括号" ;;
      esac
      host="$(printf '%s' "$authority" | sed 's/:[^:]*$//')"
      port="$(printf '%s' "$authority" | sed 's/^.*://')"
      validate_host "$host"
      validate_port "$port"
      ;;
    *)
      host="$authority"
      validate_host "$host"
      ;;
  esac

  # 供调用方判断是否需要迁移通配主机（host/port 已在上面校验过）。
  normalized_host="$host"
  normalized_port="${port:-}"
  case "$url" in
    http://*) normalized_scheme=http ;;
    https://*) normalized_scheme=https ;;
  esac
  normalized_url="$normalized_scheme://$authority"
}

setting_from_file_or_env() {
  key="$1"
  value="$(read_env_value "$key")"
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return 0
  fi
  case "$key" in
    CHAT_OIDC_HOST) printf '%s' "$CHAT_OIDC_HOST" ;;
    CHAT_IDP_PORT) printf '%s' "$CHAT_IDP_PORT" ;;
    WEB_PORT) printf '%s' "$WEB_PORT" ;;
    WEB_HTTPS_PORT) printf '%s' "$WEB_HTTPS_PORT" ;;
    TLS_ENABLED) printf '%s' "$TLS_ENABLED" ;;
    JJD_SSO_PUBLIC_URL) printf '%s' "$JJD_SSO_PUBLIC_URL" ;;
    JJD_SSO_ALLOW_INSECURE_PUBLIC_URL) printf '%s' "$JJD_SSO_ALLOW_INSECURE_PUBLIC_URL" ;;
  esac
}

ensure_env_file() {
  if [ -L "$ENV_FILE" ]; then
    fail "拒绝写入符号链接环境文件: $ENV_FILE"
  fi
  if [ -e "$ENV_FILE" ] && [ ! -f "$ENV_FILE" ]; then
    fail "环境文件必须是普通文件: $ENV_FILE"
  fi
  if [ ! -e "$ENV_FILE" ]; then
    mkdir -p "$(dirname "$ENV_FILE")"
    (umask 077; : >"$ENV_FILE")
    chmod 600 "$ENV_FILE"
  fi
}

write_env_values() {
  ensure_env_file
  owner="$(stat -c '%u:%g' "$ENV_FILE" 2>/dev/null ||
    stat -f '%u:%g' "$ENV_FILE" 2>/dev/null)" ||
    fail "无法读取环境文件所有者"
  mode="$(stat -c '%a' "$ENV_FILE" 2>/dev/null ||
    stat -f '%Lp' "$ENV_FILE" 2>/dev/null)" ||
    fail "无法读取环境文件权限"

  tmp_file="$(mktemp "$ENV_FILE.tmp.XXXXXX")"
  awk -v public_url="$normalized_url" -v insecure="$allow_insecure" '
    BEGIN { public_seen = 0; insecure_seen = 0 }
    /^JJD_SSO_PUBLIC_URL=/ {
      if (!public_seen) { print "JJD_SSO_PUBLIC_URL=" public_url; public_seen = 1 }
      next
    }
    /^JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=/ {
      if (!insecure_seen) { print "JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=" insecure; insecure_seen = 1 }
      next
    }
    { print }
    END {
      if (!public_seen) print "JJD_SSO_PUBLIC_URL=" public_url
      if (!insecure_seen) print "JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=" insecure
    }
  ' "$ENV_FILE" >"$tmp_file"

  chmod "$mode" "$tmp_file"
  chown "$owner" "$tmp_file" 2>/dev/null ||
    fail "无法保留环境文件所有者"
  mv -f "$tmp_file" "$ENV_FILE"
  tmp_file=""

  [ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || fail "环境文件替换后校验失败"
  [ "$(stat -c '%u:%g' "$ENV_FILE" 2>/dev/null ||
    stat -f '%u:%g' "$ENV_FILE" 2>/dev/null)" = "$owner" ] ||
    fail "环境文件所有者校验失败"
  [ "$(stat -c '%a' "$ENV_FILE" 2>/dev/null ||
    stat -f '%Lp' "$ENV_FILE" 2>/dev/null)" = "$mode" ] ||
    fail "环境文件权限校验失败"
}

persisted_url="$(read_env_value JJD_SSO_PUBLIC_URL)"
if [ -n "$persisted_url" ]; then
  raw_url="$persisted_url"
elif [ -n "$JJD_SSO_PUBLIC_URL" ]; then
  raw_url="$JJD_SSO_PUBLIC_URL"
else
  chat_host="$(setting_from_file_or_env CHAT_OIDC_HOST)"
  web_port="$(setting_from_file_or_env WEB_PORT)"
  web_https_port="$(setting_from_file_or_env WEB_HTTPS_PORT)"
  tls_enabled="$(setting_from_file_or_env TLS_ENABLED)"
  [ -n "$web_port" ] || web_port=3000
  [ -n "$web_https_port" ] || web_https_port=443
  [ -n "$tls_enabled" ] || tls_enabled=true
  validate_port "$web_port" WEB_PORT
  validate_port "$web_https_port" WEB_HTTPS_PORT
  [ -n "$chat_host" ] || chat_host="$(detect_host)"

  case "$chat_host" in
    *:*)
      case "$chat_host" in
        \[*\]) formatted_host="$chat_host" ;;
        *) formatted_host="[$chat_host]" ;;
      esac
      ;;
    *) formatted_host="$chat_host" ;;
  esac
  validate_host "$chat_host"
  case "$tls_enabled" in
    false|0|no|off)
      if [ "$web_port" = "80" ]; then
        raw_url="http://$formatted_host"
      else
        raw_url="http://$formatted_host:$web_port"
      fi
      ;;
    *)
      if [ "$web_https_port" = "443" ]; then
        raw_url="https://$formatted_host"
      else
        raw_url="https://$formatted_host:$web_https_port"
      fi
      ;;
  esac
fi

# normalize_origin 直接设置 normalized_url / normalized_host /
# normalized_port / normalized_scheme（不用命令替换，否则子 shell 里
# 的变量拿不回来）。
normalize_origin "$raw_url"
if is_wildcard_host "$normalized_host"; then
  detected_host="$(detect_host)"
  validate_host "$detected_host"
  normalized_url="$(replace_origin_host "$normalized_scheme" "$detected_host" "$normalized_port")"
  echo "[warn] 公开 SSO 地址曾被设为通配绑定地址，已改用可达地址" >&2
fi
case "$normalized_url" in
  http://*) allow_insecure=true ;;
  https://*) allow_insecure=false ;;
esac

write_env_values
printf '%s\n' "$normalized_url"
