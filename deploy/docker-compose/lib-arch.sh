#!/bin/sh

normalize_offline_arch() {
  case "${1:-}" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *)
      echo "[error] unsupported architecture: ${1:-unknown}; only amd64 and arm64 are supported" >&2
      return 1
      ;;
  esac
}

docker_static_arch_dir() {
  case "$(normalize_offline_arch "$1")" in
    amd64) printf 'x86_64\n' ;;
    arm64) printf 'aarch64\n' ;;
  esac
}

compose_asset_arch() {
  docker_static_arch_dir "$1"
}

offline_bundle_name() {
  _version="$1"
  _profile="$2"
  _chat_suffix="$3"
  _arch="$(normalize_offline_arch "$4")" || return 1
  _stamp="$5"
  printf 'jjdguard-%s-offline-%s%s-%s-%s\n' "$_version" "$_profile" "$_chat_suffix" "$_arch" "$_stamp"
}

assert_host_arch() {
  _expected="$(normalize_offline_arch "$1")" || return 1
  _machine="${OFFLINE_TEST_UNAME_M:-$(uname -m 2>/dev/null || printf unknown)}"
  _actual="$(normalize_offline_arch "$_machine")" || return 1
  if [ "$_actual" != "$_expected" ]; then
    echo "[error] package architecture ($_expected) does not match host ($_actual)" >&2
    return 1
  fi
}
