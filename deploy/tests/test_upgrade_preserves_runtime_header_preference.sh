#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/deploy/docker-compose/upgrade-bundle.sh"
tmp="$(mktemp -d)";trap 'rm -rf "$tmp"' EXIT
SCRIPT_DIR="$tmp";EXISTING_GATEWAY_CONTAINER=trusted-gateway
runtime_value=true
docker(){ [[ "$1" == inspect ]] || return 1; printf 'IGNORED_PRIVATE_SECRET=not-exported\nSECURITY_ACTION_HEADER_ENABLED=%s\n' "$runtime_value"; }
printf 'POSTGRES_DB=customer\n' > "$tmp/.env"
preserve_gateway_header_preference
[[ "$(read_literal_dotenv_key "$tmp/.env" SECURITY_ACTION_HEADER_ENABLED)" == true ]]
[[ "$(stat -c %a "$tmp/.env")" == 600 ]]
printf 'SECURITY_ACTION_HEADER_ENABLED=\n' > "$tmp/.env"
preserve_gateway_header_preference
[[ "$(read_literal_dotenv_key "$tmp/.env" SECURITY_ACTION_HEADER_ENABLED)" == true ]]
printf 'SECURITY_ACTION_HEADER_ENABLED=false\n' > "$tmp/.env"
preserve_gateway_header_preference
[[ "$(read_literal_dotenv_key "$tmp/.env" SECURITY_ACTION_HEADER_ENABLED)" == false ]]
runtime_value=false;printf 'POSTGRES_DB=customer\n' > "$tmp/.env"
preserve_gateway_header_preference
[[ "$(read_literal_dotenv_key "$tmp/.env" SECURITY_ACTION_HEADER_ENABLED)" == false ]]
printf 'POSTGRES_DB=customer\n' > "$tmp/.env";runtime_value='invalid;touch impossible'
if (preserve_gateway_header_preference) >/dev/null 2>&1;then echo 'invalid boolean accepted';exit 1;fi
[[ ! -e impossible ]]
runtime_value=$'true\nSECURITY_ACTION_HEADER_ENABLED=false'
if (preserve_gateway_header_preference) >/dev/null 2>&1;then echo 'duplicate runtime values accepted';exit 1;fi
echo '[ok] explicit old runtime header preference retained; configured override and malformed-value rejection verified'
