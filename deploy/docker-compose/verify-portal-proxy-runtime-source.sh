#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf '[portal-proxy-runtime-source][error] %s\n' "$*" >&2
  exit 1
}

usage() {
  die 'usage: verify-portal-proxy-runtime-source.sh --repo ABSOLUTE_PATH --runtime-revision SHA1 --release-revision SHA1'
}

repo=
runtime_revision=
release_revision=
while (($#)); do
  case "$1" in
    --repo) repo=${2:-}; shift 2 ;;
    --runtime-revision) runtime_revision=${2:-}; shift 2 ;;
    --release-revision) release_revision=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$repo" == /* && -d "$repo" && ! -L "$repo" ]] ||
  die 'repository must be an absolute real directory'
[[ "$(realpath -e "$repo")" == "$repo" ]] ||
  die 'repository must be canonical'
[[ "$runtime_revision" =~ ^[0-9a-f]{40}$ ]] || die 'runtime revision is invalid'
[[ "$release_revision" =~ ^[0-9a-f]{40}$ ]] || die 'release revision is invalid'

for revision in "$runtime_revision" "$release_revision"; do
  resolved="$(git -C "$repo" rev-parse --verify "${revision}^{commit}" 2>/dev/null || true)"
  [[ "$resolved" == "$revision" ]] || die "revision is not a known commit: $revision"
done

application_paths=(
  portal-proxy/Dockerfile
  portal-proxy/package.json
  portal-proxy/pnpm-lock.yaml
  portal-proxy/prisma
  portal-proxy/src
  portal-proxy/tsconfig.json
)
if ! git -C "$repo" diff --quiet \
  "$runtime_revision" "$release_revision" -- "${application_paths[@]}"; then
  die 'Portal Proxy runtime application source differs from release source'
fi

printf '[ok] Portal Proxy runtime application source matches release source\n'
