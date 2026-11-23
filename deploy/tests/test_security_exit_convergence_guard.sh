#!/usr/bin/env bash
# P0-3 guard: interrupting exits must go through securityexit.Decide.
# New inline "auditOnly" branches that decide whether to interrupt traffic are
# forbidden in the converged services. Historical sites are listed below with
# their current count; the list may only shrink.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Inline branches on an auditOnly variable, or on the securityAuditOnly /
# outputSecurityAuditOnly accessors.
pattern='!auditOnly|auditOnly[[:space:]]*(&&|\|\|)|(&&|\|\|)[[:space:]]*!?auditOnly|if[[:space:]]+auditOnly[[:space:]]*\{'
pattern+='|!h\.(output)?[sS]ecurityAuditOnly\(|(if|&&|\|\|)[[:space:]]*[A-Za-z]+\.(output)?[sS]ecurityAuditOnly\(|(output)?[sS]ecurityAuditOnly\([^)]*\)[[:space:]]*(&&|\|\||\{)'

# path<TAB>allowed count (reason)
allow_file="$(mktemp)"
trap 'rm -f "$allow_file"' EXIT
cat >"$allow_file" <<'ALLOW'
apps/proxy-server/internal/handler/inspection_queue.go	3
apps/gateway-core/internal/handler/reverse_proxy.go	2
apps/gateway-core/internal/handler/mcp_proxy_audit.go	2
apps/gateway-core/internal/handler/chat_completions.go	1
apps/gateway-core/internal/handler/mcp_proxy.go	1
apps/gateway-core/internal/handler/streaming_relay.go	2
apps/gateway-core/internal/handler/messages_live_stream.go	1
apps/gateway-core/internal/handler/responses_live_stream.go	1
apps/gateway-core/internal/handler/tool_interceptor.go	1
ALLOW
# inspection_queue.go: 352 picks the inspection budget (not an exit);
#   404/424 clamp through clampFileDLPActionForAudit -> securityexit.Clamp.
# reverse_proxy.go / mcp_proxy_audit.go: security_events.action_taken labels
#   (security_audit_only vs security_blocked), not exits.
# chat_completions.go agentGuardMode / mcp_proxy.go mcpGuardMode: mode clamp
#   into agentguard.CallerMode; exits still go through Decide.
# streaming_relay.go / messages_live_stream.go / responses_live_stream.go:
#   resolve the live-stream posture (stream_audit); exits use
#   liveStreamExitMode -> Decide.
# tool_interceptor.go: the runtime cache setter signature, not a branch.

scan_paths=(
  apps/proxy-server/internal/handler
  apps/control-plane/internal/handler/portal_upload_ingest.go
  apps/gateway-core/internal/handler
)

fail=0
while IFS= read -r file; do
  count="$(grep -cE "$pattern" "$file" || true)"
  [[ "$count" == "0" ]] && continue
  allowed="$(awk -F'\t' -v f="$file" '$1==f {print $2}' "$allow_file")"
  allowed="${allowed:-0}"
  if (( count > allowed )); then
    printf 'inline auditOnly exit decision in %s: %s (allowed %s); use securityexit.Decide\n' "$file" "$count" "$allowed" >&2
    grep -nE "$pattern" "$file" >&2
    fail=1
  fi
done < <(find "${scan_paths[@]}" -name '*.go' ! -name '*_test.go' -type f | sort)

# The blocking set is defined once, in shared-go/securityexit.
blocking_set_files=(
  apps/proxy-server/internal/handler/security.go
  apps/control-plane/internal/handler/portal_upload_ingest.go
  apps/gateway-core/internal/handler/semantic_status.go
  apps/gateway-core/internal/handler/reverse_proxy_messages.go
  apps/gateway-core/internal/handler/native_streaming_pending.go
  apps/gateway-core/internal/handler/streaming_relay.go
  apps/gateway-core/internal/handler/messages_live_stream.go
  apps/gateway-core/internal/handler/responses_live_stream.go
)
for file in "${blocking_set_files[@]}"; do
  if grep -nE 'case[[:space:]]+"block",' "$file" >&2; then
    printf 'a local blocking-action set was redefined in %s; use securityexit.Blocks\n' "$file" >&2
    fail=1
  fi
done

# Capacity and transport failures must not look like security blocks.
for code in inspection_capacity inspection_body_unavailable; do
  if grep -rn --include='*.go' --exclude='*_test.go' "\"$code\"" apps/proxy-server apps/control-plane >&2; then
    printf 'retired exit code %s is back\n' "$code" >&2
    fail=1
  fi
done

# Detection failure is a coverage gap in every mode: no fail-close branch on
# the guardrail failure mode may come back in gateway-core.
if grep -rnE --include='*.go' --exclude='*_test.go' '(mode|failureMode|FailureMode)[[:space:]]*==[[:space:]]*"close"' apps/gateway-core/internal/handler >&2; then
  printf 'a fail-close branch is back in gateway-core; detection failure must forward (securityexit.DetectionFailure)\n' >&2
  fail=1
fi

# Single sanctioned exception (2026-09-28-p0-explicit-fail-closed-design.md):
# the explicit console option guardrail_fail_closed_enabled, decided only by
# securityexit.DecideWithPolicy with the policy from guardrailPolicy. A handler
# must not build its own Policy (hard-wired or env-driven fail-closed), and
# DecideWithPolicy may only be fed guardrailPolicy(...).
policy_resolver=apps/gateway-core/internal/handler/guardrail_policy.go
if grep -rnE --include='*.go' --exclude='*_test.go' 'securityexit\.Policy[[:space:]]*\{' apps/gateway-core/internal/handler apps/proxy-server apps/control-plane | grep -v "^$policy_resolver:" >&2; then
  printf 'securityexit.Policy is constructed outside %s; resolve it through guardrailPolicy\n' "$policy_resolver" >&2
  fail=1
fi
if grep -rnE --include='*.go' --exclude='*_test.go' 'DecideWithPolicy\(' apps/gateway-core/internal/handler apps/proxy-server apps/control-plane | grep -vE 'guardrailPolicy\(ctx, ([A-Za-z.]*[tT]oolRiskClient|client)\)\)' >&2; then
  printf 'securityexit.DecideWithPolicy must take guardrailPolicy(ctx, <ToolRiskClient>) as its policy\n' >&2
  fail=1
fi
if grep -rnE --include='*.go' --exclude='*_test.go' 'GuardrailFailClosedEnabled\(' apps/gateway-core/internal/handler | grep -v "^$policy_resolver:" | grep -v 'func (c \*ToolRiskClient) GuardrailFailClosedEnabled' >&2; then
  printf 'the fail-closed option is read outside %s\n' "$policy_resolver" >&2
  fail=1
fi
# Capacity never enforces, even with the option on.
if ! grep -qE 'cause == DetectionFailure && mode == Protect && policy\.FailClosedOnDetectionFailure' packages/shared-go/securityexit/policy.go; then
  printf 'securityexit.DecideWithPolicy must only enforce DetectionFailure in protect mode\n' >&2
  fail=1
fi

exit "$fail"
