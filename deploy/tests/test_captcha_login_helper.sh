#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER="$ROOT/deploy/lib/captcha-login.sh"

fail() { echo "[fail] $*" >&2; exit 1; }

[[ -f "$HELPER" ]] || fail "missing helper: $HELPER"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

svg='<svg xmlns="http://www.w3.org/2000/svg"><text x="1" y="1">A</text><text x="2" y="1">7</text><text x="3" y="1">B</text><text x="4" y="1">K</text><text x="5" y="1">2</text></svg>'
if base64 --help 2>&1 | grep -q -- '-w'; then
  image_b64="$(printf '%s' "$svg" | base64 -w0)"
else
  image_b64="$(printf '%s' "$svg" | base64 | tr -d '\n')"
fi

cat >"$work/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

payload=''
url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--data|--data-raw|--data-binary)
      payload="${2:-}"
      shift 2
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

printf 'URL=%s\nPAYLOAD=%s\n' "$url" "$payload" >>"${FAKE_CURL_LOG:?}"

case "$url" in
  */captcha)
    printf '{"captcha_id":"challenge-1","image":"data:image/svg+xml;base64,%s","expires_in":300}\n' "${FAKE_CAPTCHA_IMAGE:?}"
    ;;
  */login)
    case "$payload" in
      *'"captcha_id":"challenge-1"'*'"captcha_code":"A7BK2"'*)
        printf '{"token":"token-1","password_change_required":true}\n'
        ;;
      *)
        printf '{"error":{"code":"invalid_captcha"}}\n'
        exit 22
        ;;
    esac
    ;;
  *)
    printf 'unexpected URL: %s\n' "$url" >&2
    exit 7
    ;;
esac
SH
chmod +x "$work/curl"

export PATH="$work:$PATH"
export FAKE_CURL_LOG="$work/curl.log"
export FAKE_CAPTCHA_IMAGE="$image_b64"

# shellcheck disable=SC1090
. "$HELPER"

response="$(captcha_login_json 'https://127.0.0.1:27443/admin/v1' 'admin' 'GateAdmin#abcd')"
[[ "$response" == *'"token":"token-1"'* ]] || fail "login helper did not return token response: $response"
captcha_login_response_succeeded "$response" || fail 'fresh bootstrap login response was rejected'
rotated_response='{"token":"token-2","password_change_required":false}'
captcha_login_response_succeeded "$rotated_response" || fail 'rotated administrator login response was rejected'
if captcha_login_password_change_required "$rotated_response"; then
  fail 'rotated administrator was incorrectly treated as requiring password change'
fi
if captcha_login_response_succeeded '{"error":{"code":"invalid_credentials"}}'; then
  fail 'error response was incorrectly treated as a successful login'
fi
grep -Fq '"captcha_id":"challenge-1"' "$FAKE_CURL_LOG" || fail 'login payload missed captcha_id'
grep -Fq '"captcha_code":"A7BK2"' "$FAKE_CURL_LOG" || fail 'login payload missed parsed captcha code'

echo '[ok] captcha login helper accepts fresh and already-rotated administrator sessions'
