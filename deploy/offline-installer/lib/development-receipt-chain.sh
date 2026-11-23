#!/usr/bin/env bash
# The console publisher stores its predecessor pointer as an escaped JSON string.
# Follow only this bounded, hash-bound format; never execute receipt content.
development_chain_protected() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" && "$(realpath -e -- "$path")" == "$path" ]] || return 1
  [[ "$(stat -Lc %u -- "$path")" == "$EUID" && "$(stat -Lc %a -- "$path")" == 600 ]]
}
development_chain_field() {
  local key="${1//./\\.}" path="$2" value
  value="$(grep -oE "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$path" | head -1 | sed 's/^[^:]*:[[:space:]]*"//;s/"$//' || true)"
  [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
  printf '%s' "$value"
}
development_receipt_chain_valid() {
  local file="$1" expected path extra count=0
  development_chain_protected "$file" || return 1
  while IFS=$'\t' read -r expected path extra; do
    [[ -z "$extra" && "$expected" =~ ^[0-9a-f]{64}$ && "$path" == /* ]] || return 1
    development_chain_protected "$path" || return 1
    [[ "$(sha256_file "$path")" == "$expected" ]] || return 1
    count=$((count+1))
  done <"$file"
  (( count > 0 && count <= 194 ))
}
development_receipt_anchor() {
  local root="$1" index="$2" target="$3" step release expected receipt actual previous pointer manifest version revision before after
  install -d -m 700 "$target"
  : >"$target/chain.tsv"; chmod 600 "$target/chain.tsv"
  for ((step=0;step<32;step++)); do
    development_chain_protected "$index" || return 1
    printf '%s\t%s\n' "$(sha256_file "$index")" "$index" >>"$target/chain.tsv"
    release="$(development_chain_field release "$index")" || return 1
    expected="$(development_chain_field receipt_sha256 "$index")" || return 1
    [[ "$expected" =~ ^[0-9a-f]{64}$ && "$release" == "$root"/dev-* && "${release##*/}" =~ ^dev-[A-Za-z0-9-]+$ ]] || return 1
    [[ "$(realpath -e -- "$release")" == "$release" ]] || return 1
    receipt="$release/receipt.json"; development_chain_protected "$receipt" || return 1
    actual="$(sha256_file "$receipt")"; [[ "$actual" == "$expected" ]] || return 1
    [[ "$(development_chain_field status "$receipt")" == deployed && "$(development_chain_field release_id "$receipt")" == "${release##*/}" ]] || return 1
    printf '%s\t%s\n' "$actual" "$receipt" >>"$target/chain.tsv"
    version="$(development_chain_field version "$receipt" || true)"
    if [[ "$version" =~ ^2[.][0-9A-Za-z.-]+$ ]]; then
      DEV_RECEIPT_ANCHOR_INDEX="$index"; DEV_RECEIPT_ANCHOR_RELEASE="$release"
      development_receipt_chain_valid "$target/chain.tsv"
      return $?
    fi
    [[ "$(development_chain_field purpose "$receipt")" == console-only ]] || return 1
    grep -Eq '"schema"[[:space:]]*:[[:space:]]*1([[:space:]]*[,}]|[[:space:]]*$)' "$receipt" || return 1
    for pair in manifest.json:manifest_sha256 state/before.json:before_sha256 state/after.json:after_sha256 state/previous-current.json:previous-current.json; do
      local path="$release/${pair%%:*}" key="${pair#*:}" checksum
      checksum="$(development_chain_field "$key" "$receipt")" || return 1
      [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || return 1
      development_chain_protected "$path" || return 1
      [[ "$(sha256_file "$path")" == "$checksum" ]] || return 1
      printf '%s\t%s\n' "$checksum" "$path" >>"$target/chain.tsv"
    done
    manifest="$release/manifest.json"
    [[ "$(development_chain_field version "$manifest")" =~ ^2[.][0-9A-Za-z.-]+$ ]] || return 1
    revision="$(development_chain_field revision "$receipt")" || return 1
    [[ "$revision" =~ ^[0-9a-f]{40}$ && "$(development_chain_field revision "$manifest")" == "$revision" ]] || return 1
    previous="$release/state/previous-current.json"
    [[ "$(head -c 1 "$previous")" == '"' ]] || return 1
    pointer="$(sed 's/^"//;s/"$//;s/\\n/\n/g;s/\\"/"/g' "$previous")"
    [[ "$pointer" != *'\'* && "$pointer" != *$'\r'* ]] || return 1
    index="$target/predecessor-$step.json"
    printf '%s\n' "$pointer" >"$index"; chmod 600 "$index"
  done
  return 1
}
