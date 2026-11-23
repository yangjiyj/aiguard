#!/bin/sh
# Shared login helper for installer smoke tests and delivery gates.
# The admin login endpoint requires a short-lived SVG captcha; this helper
# fetches the challenge, extracts the rendered text from the SVG, and submits it
# with the username/password login payload.

captcha_json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

captcha_json_field() {
  field="$1"
  sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1
}

captcha_base64_decode() {
  if base64 -d >/dev/null 2>/dev/null <<EOF
$1
EOF
  then
    base64 -d <<EOF
$1
EOF
    return 0
  fi
  base64 --decode <<EOF
$1
EOF
}

captcha_code_from_image() {
  image="$1"
  case "$image" in
    data:image/svg+xml\;base64,*) encoded="${image#data:image/svg+xml;base64,}" ;;
    data:image/svg+xml\;charset=utf-8\;base64,*) encoded="${image#data:image/svg+xml;charset=utf-8;base64,}" ;;
    *) return 1 ;;
  esac

  svg="$(captcha_base64_decode "$encoded" 2>/dev/null)" || return 1
  code="$(printf '%s\n' "$svg" \
    | grep -o '<text[^>]*>[^<][^<]*</text>' \
    | sed 's/^.*<text[^>]*>\([^<]*\)<\/text>.*$/\1/' \
    | tr -d '\n\r[:space:]')"
  [ -n "$code" ] || return 1
  printf '%s\n' "$code"
}

captcha_login_json() {
  base_url="${1%/}"
  username="$2"
  password="$3"
  timeout_seconds="${CAPTCHA_LOGIN_TIMEOUT:-15}"

  challenge="$(curl -ksS -m "$timeout_seconds" "$base_url/captcha")" || return 1
  captcha_id="$(printf '%s' "$challenge" | captcha_json_field captcha_id)"
  image="$(printf '%s' "$challenge" | captcha_json_field image)"
  captcha_code="$(captcha_code_from_image "$image")" || return 1
  [ -n "$captcha_id" ] || return 1

  user_json="$(captcha_json_escape "$username")"
  pass_json="$(captcha_json_escape "$password")"
  id_json="$(captcha_json_escape "$captcha_id")"
  code_json="$(captcha_json_escape "$captcha_code")"
  payload="{\"username\":\"$user_json\",\"password\":\"$pass_json\",\"captcha_id\":\"$id_json\",\"captcha_code\":\"$code_json\"}"

  curl -ksS -m "$timeout_seconds" -X POST "$base_url/login" \
    -H 'Content-Type: application/json' \
    -d "$payload"
}

captcha_login_response_succeeded() {
  printf '%s' "$1" | grep -Eq '"token"[[:space:]]*:[[:space:]]*"[^"]+"'
}

captcha_login_password_change_required() {
  printf '%s' "$1" | grep -Eq '"password_change_required"[[:space:]]*:[[:space:]]*true'
}
