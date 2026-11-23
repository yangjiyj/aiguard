#!/usr/bin/env bash

sanitize_mcp_e2e_log() {
  local input_file="$1"
  local output_file="$2"
  [[ -r "$input_file" ]] || return 1

  LC_ALL=C sed -E \
    -e 's/((TOKEN|PASSWORD|SECRET|API_KEY)[=:])[[:space:]]*[^[:space:]]+/\1[REDACTED]/Ig' \
    -e 's/(Authorization:[[:space:]]*Bearer[[:space:]]+)[^[:space:]]+/\1[REDACTED]/Ig' \
    "$input_file" >"$output_file"
}
