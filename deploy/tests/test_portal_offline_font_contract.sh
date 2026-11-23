#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAYOUT="$ROOT_DIR/enterprise-ai-portal/src/app/layout.tsx"
STYLES="$ROOT_DIR/enterprise-ai-portal/src/app/globals.css"

fail() {
  printf '[portal-offline-font] %s\n' "$*" >&2
  exit 1
}

for file in "$LAYOUT" "$STYLES"; do
  [[ -f "$file" && ! -L "$file" ]] || fail "required file is missing or unsafe: $file"
done

if rg -n -i 'next/font/google|fonts\.googleapis\.com|Geist_Mono\(|Geist\(' "$LAYOUT" "$STYLES"; then
  fail 'Portal source still depends on a network-fetched font'
fi

rg -Fq -- '--font-sans: ui-sans-serif, system-ui' "$STYLES" ||
  fail 'Portal sans font must start with an offline system stack'
rg -Fq -- '--font-mono: ui-monospace' "$STYLES" ||
  fail 'Portal mono font must start with an offline system stack'
rg -Fq -- 'className="h-full antialiased"' "$LAYOUT" ||
  fail 'Portal root layout must keep its non-font layout classes'

printf '[portal-offline-font] PASS\n'
