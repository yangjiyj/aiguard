#!/usr/bin/env bash

# Interpret `claude mcp get` output without depending on a particular glyph,
# terminal color, or locale. Explicit negative states win over the positive
# whole-word Connected state.
claude_mcp_output_connected() {
  local output_file="$1"
  [[ -r "$output_file" ]] || return 1

  if LC_ALL=C grep -Eiq \
    '(^|[^[:alpha:]])(not[[:space:]]+connected|failed([[:space:]]+to)?[[:space:]]+connect|connection[[:space:]]+(failed|error)|unreachable|timed?[[:space:]]*out)([^[:alpha:]]|$)' \
    "$output_file"; then
    return 1
  fi

  LC_ALL=C grep -Eiq \
    '(^|[^[:alpha:]])connected([^[:alpha:]]|$)' \
    "$output_file"
}
