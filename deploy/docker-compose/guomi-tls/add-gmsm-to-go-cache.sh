#!/usr/bin/env bash
# W10: add github.com/emmansun/gmsm v0.43.0 to an offline Go module cache
# input (OFFLINE_RELEASE_GO_CACHE_INPUT) without network access at build time.
#
#   add-gmsm-to-go-cache.sh <new-cache-dir> [<source-cache-dir>]
#
# <source-cache-dir> is any GOMODCACHE that already holds the module (for
# example one prepared online with "go mod download github.com/emmansun/gmsm@v0.43.0").
# The script copies the existing release cache to <new-cache-dir> (never
# modifies it in place) and verifies the module zip hash against the h1:
# sum pinned in packages/shared-go/go.sum.
set -Eeuo pipefail
umask 077

MODULE=github.com/emmansun/gmsm
VERSION=v0.43.0
WANT_H1='h1:uiT92B9Ge99oxK1qT+LEls2OqX7WinGGNzUGF1hIZ4A='
WANT_ZIP_SHA256=c1de8ec1a83f6ff65b6e7302751eb18d1a5fed9157f26f172711918a21bf7161

DST=${1:?usage: add-gmsm-to-go-cache.sh <new-cache-dir> [<source-cache-dir>]}
SRC=${2:-$(go env GOMODCACHE)}
BASE=${OFFLINE_RELEASE_GO_CACHE_INPUT:?set OFFLINE_RELEASE_GO_CACHE_INPUT to the current release go cache}

[[ ! -e "$DST" ]] || { echo "refusing to overwrite $DST" >&2; exit 1; }
from="$SRC/cache/download/$MODULE/@v"
for ext in info mod zip ziphash; do
  [[ -s "$from/$VERSION.$ext" ]] || { echo "missing $from/$VERSION.$ext" >&2; exit 1; }
done
[[ "$(sha256sum "$from/$VERSION.zip" | cut -d' ' -f1)" == "$WANT_ZIP_SHA256" ]] || { echo "zip sha256 mismatch" >&2; exit 1; }
[[ "$(cat "$from/$VERSION.ziphash")" == "$WANT_H1" ]] || { echo "ziphash does not match pinned go.sum" >&2; exit 1; }

cp -a "$BASE" "$DST"
chmod -R u+w "$DST/pkg/mod/cache/download"
to="$DST/pkg/mod/cache/download/$MODULE/@v"
mkdir -p "$to"
cp "$from/$VERSION".{info,mod,zip,ziphash} "$to/"
grep -qx "$VERSION" "$to/list" 2>/dev/null || printf '%s\n' "$VERSION" >>"$to/list"
echo "[ok] $DST = $BASE + $MODULE@$VERSION"
