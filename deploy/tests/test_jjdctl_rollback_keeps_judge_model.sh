#!/usr/bin/env bash
# Regression: upgrades retire the legacy judge model from the shared volume, so
# `jjdctl rollback` must keep the judge on the model the current release runs.
# Without this the rolled-back llm-judge crash-loops on a missing GGUF.
# The upgrader must also still trust that rollback override as a digest proof,
# otherwise the rolled-back stack can never be upgraded again.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CTL="$ROOT/deploy/offline-installer/jjdctl"
UPGRADER="$ROOT/deploy/docker-compose/upgrade-bundle.sh"
PACKAGER="$ROOT/deploy/docker-compose/package-offline-bundle.sh"

fail() { echo "[fail] $*" >&2; exit 1; }

candidate_gate="$(sed -n '/^run_candidate_static_gates()/,/^}/p' "$PACKAGER")"
[[ "$candidate_gate" == *'test_jjdctl_rollback_keeps_judge_model.sh'* ]] || \
  fail 'candidate package gate must run the rollback judge model regression'

rollback_body="$(sed -n '/^rollback_cmd()/,/^}/p' "$CTL")"
[[ "$rollback_body" == *'current_judge_model_path'* ]] || fail 'rollback must read the current judge model path'
[[ "$rollback_body" == *'write_rollback_image_override "$previous_dc" "$judge_model_path"'* ]] || \
  fail 'rollback must pass the current judge model to the image override'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
sed '/^main "\$@"$/d' "$CTL" >"$tmp/jjdctl"
mkdir -p "$tmp/prev/.upgrade" "$tmp/bin"

G="sha256:$(printf 'g%.0s' {1..64} | tr g 1)"
J="sha256:$(printf 'j%.0s' {1..64} | tr j 2)"
O="sha256:$(printf 'o%.0s' {1..64} | tr o 3)"
MODEL=/models/jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf

cat >"$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
if [[ "$1" == inspect ]]; then
  printf 'PATH=/usr/bin\nJUDGE_MODEL_PATH=%s\n' "$JJD_TEST_JUDGE_PATH"
elif [[ "$1" == compose ]]; then
  printf '%s\n' gateway-core control-plane security-engine proxy-server web-console worker llm-judge tier1-classifier
fi
SH
chmod 755 "$tmp/bin/docker"
cat >"$tmp/prev/compose-wrapper.sh" <<'SH'
#!/bin/sh
exec docker compose "$@"
SH


run() {
  PATH="$tmp/bin:$PATH" JJD_TEST_JUDGE_PATH="$1" G="$G" J="$J" O="$O" bash -c '
    source "$1"
    compose() { printf "cid-judge\n"; }
    GATEWAY_CORE_IMAGE=$G CONTROL_PLANE_IMAGE=$O SECURITY_ENGINE_IMAGE=$O
    PROXY_SERVER_IMAGE=$O WEB_CONSOLE_IMAGE=$O WORKER_IMAGE=$O
    LLM_JUDGE_IMAGE=$J TIER1_CLASSIFIER_IMAGE=$O CHAT_PORTAL_UI_IMAGE="" CHAT_PORTAL_PROXY_IMAGE=""
    p="$(current_judge_model_path)" || p=""
    echo "path=$p"
    write_rollback_image_override "$2/prev" "$p"
  ' bash "$tmp/jjdctl" "$tmp"
}

# Feed a file to the upgrader's strict rollback-override parser.
upgrader_accepts() {
  local file="$1" fp
  fp="$(stat -Lc '%d|%i|%u|%a|%s|%h' -- "$file")|$(sha256sum -- "$file" | awk '{print $1}')"
  EXISTING_CONFIG_IDENTITIES="$file|$fp" bash -c '
    source "$1"
    validate_config_snapshots() { return 0; }
    strict_rollback_override_matches_digest "$2" "$3"
  ' bash "$UPGRADER" "$file" "$G"
}

f="$tmp/prev/.upgrade/compose.upgrade.yml"

out="$(run "$MODEL")"
grep -Fxq "path=$MODEL" <<<"$out" || fail "current path not read: $out"
[[ "$(stat -c %a "$f")" == 600 ]] || fail 'override must be 0600'
python3 - "$f" "$G" "$MODEL" <<'PY' || fail "override content wrong: $(cat "$f")"
import sys, yaml
text = open(sys.argv[1]).read()
assert text.startswith("services:\n"), text
doc = yaml.safe_load(text)
assert doc["services"]["llm-judge"]["environment"]["JUDGE_MODEL_PATH"] == sys.argv[3], doc
assert doc["services"]["gateway-core"]["image"] == sys.argv[2], doc
PY
upgrader_accepts "$f" || fail "upgrader must trust the judge-pinned rollback override: $(cat "$f")"

# Unsafe value from the container environment is never written.
out="$(run '/models/../etc/passwd')"
grep -Fxq 'path=' <<<"$out" || fail "unsafe path must be rejected: $out"
grep -Fq 'JUDGE_MODEL_PATH' "$f" && fail "unsafe path leaked into override: $(cat "$f")"
upgrader_accepts "$f" || fail 'upgrader must still trust a plain rollback override'

# The parser only relaxes for exactly one JUDGE_MODEL_PATH under llm-judge.
bad="$tmp/bad.yml"
printf 'services:\n  gateway-core:\n    image: %s\n    environment:\n      JUDGE_MODEL_PATH: %s\n' "$G" "$MODEL" >"$bad"
upgrader_accepts "$bad" && fail 'environment under a non-judge service must be rejected'
printf 'services:\n  gateway-core:\n    image: %s\n  llm-judge:\n    image: %s\n    environment:\n      OTHER: x\n' "$G" "$J" >"$bad"
upgrader_accepts "$bad" && fail 'non-model environment keys must be rejected'
printf 'services:\n  gateway-core:\n    image: %s\n  llm-judge:\n    image: %s\n    environment:\n      JUDGE_MODEL_PATH: /etc/passwd\n' "$G" "$J" >"$bad"
upgrader_accepts "$bad" && fail 'model path outside /models must be rejected'

echo '[ok] rollback keeps the current judge model path and stays upgradable'
