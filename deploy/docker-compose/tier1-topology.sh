#!/bin/sh
# Single implementation of the Tier-1 topology contract.
#
# Sourced by:
#   deploy/docker-compose/tier1-scale.sh               (writes the topology)
#   deploy/docker-compose/engine-resource-autotune.sh  (sizes against it)
#   deploy/docker-compose/upgrade.sh                   (restores it)
#   deploy/docker-compose/upgrade-bundle.sh            (restores it)
#   deploy/docker-compose/deploy-offline.sh            (restores it)
#
# The point of one file is that the supply/demand verdict has exactly one
# formula. autotune and tier1-scale.sh used to size the sidecar separately, so a
# scaled-out install was modelled as one replica by whichever ran last and the
# /health verdict flipped between within_limit and over_limit on its own.
#
# State persisted in .env by `tier1-scale.sh --apply`:
#   TIER1_SCALE_MODE=cpu|gpu   which overlay the running stack was built with
#   TIER1_REPLICAS=<1..32>     how many tier1-classifier replicas must survive
# Both empty/absent means "no scaling": base compose, single replica.

# Value of KEY in an env file. Always returns 0: callers run under `set -e` and
# use this in command substitution, where a non-zero status would abort them.
tier1_env_value() {
  _t1_file=$1
  _t1_key=$2
  [ -f "$_t1_file" ] || return 0
  # One process, no pipeline: callers source this under `set -o pipefail` and a
  # SIGPIPE from an early-closing `head` would abort them.
  awk -v key="$_t1_key" '
    index($0, key "=") == 1 { sub(/\r$/, "", $0); print substr($0, length(key) + 2); exit }
  ' "$_t1_file" 2>/dev/null || true
  return 0
}

# cpu|gpu|'' ; return 2 when the persisted value is not one of those.
tier1_scale_mode() {
  _t1_mode=$(tier1_env_value "$1" TIER1_SCALE_MODE)
  case "$_t1_mode" in
    ''|cpu|gpu) printf '%s' "$_t1_mode" ;;
    *) return 2 ;;
  esac
  return 0
}

# 1..32, default 1 ; return 2 when the persisted value is out of range.
tier1_replicas() {
  _t1_raw=$(tier1_env_value "$1" TIER1_REPLICAS)
  [ -n "$_t1_raw" ] || { printf '1'; return 0; }
  case "$_t1_raw" in
    *[!0-9]*) return 2 ;;
  esac
  if [ "$_t1_raw" -lt 1 ] || [ "$_t1_raw" -gt 32 ]; then
    return 2
  fi
  printf '%s' "$_t1_raw"
  return 0
}

# Overlay path for a mode, empty when the install is unscaled.
tier1_scale_overlay() {
  case "$2" in
    cpu) printf '%s/tier1-cpu.override.yml' "$1" ;;
    gpu) printf '%s/tier1-gpu.override.yml' "$1" ;;
    *) printf '' ;;
  esac
  return 0
}

# Coerce a possibly-empty/non-numeric value to a positive default.
tier1_int() {
  case "${1:-}" in
    ''|*[!0-9]*) printf '%s' "$2" ;;
    *) if [ "$1" -gt 0 ]; then printf '%s' "$1"; else printf '%s' "$2"; fi ;;
  esac
  return 0
}

# Prints "<status> <demand> <supply>".
#   demand = engine replicas x web concurrency x engine-side in-flight per worker
#   supply = tier1 replicas x uvicorn workers x per-process inference capacity
# A demand above supply means the sidecar answers 503 under peak load, and those
# 503s surface as "degraded" detection rather than as a capacity error.
tier1_capacity_verdict() {
  _t1_replicas=$1
  _t1_workers=$2
  _t1_capacity=$3
  _t1_engine_replicas=$4
  _t1_web=$5
  _t1_inflight=$6
  _t1_supply=$(( _t1_replicas * _t1_workers * _t1_capacity ))
  _t1_demand=$(( _t1_engine_replicas * _t1_web * _t1_inflight ))
  if [ "$_t1_supply" -ge "$_t1_demand" ]; then
    _t1_status=within_limit
  else
    _t1_status="over_limit:${_t1_demand}/${_t1_supply}"
  fi
  printf '%s %s %s' "$_t1_status" "$_t1_demand" "$_t1_supply"
  return 0
}

# GPU preconditions, identical for first scaling and for every later upgrade.
# Rising into CPU here would be invisible: the stack would look healthy while
# tier1 silently fell back to the CPU image. $1 is the digest-pinned image ref
# the caller already resolved for this release.
tier1_gpu_preflight() {
  _t1_image=${1:-}
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    echo "[tier1-topology][error] nvidia-smi is unavailable: the host has no NVIDIA driver, refusing to run GPU Tier-1" >&2
    return 1
  fi
  if ! nvidia-smi -L >/dev/null 2>&1; then
    echo "[tier1-topology][error] nvidia-smi cannot see a GPU; check the driver and the device mapping" >&2
    return 1
  fi
  if ! docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"nvidia"'; then
    echo "[tier1-topology][error] the Docker NVIDIA runtime is not registered; install nvidia-container-toolkit" >&2
    return 1
  fi
  if ! printf '%s\n' "$_t1_image" | grep -Eq '@sha256:[0-9a-f]{64}$'; then
    echo "[tier1-topology][error] TIER1_GPU_IMAGE must be pinned by sha256 digest, got: ${_t1_image:-<empty>}" >&2
    return 1
  fi
  if ! docker run --rm --pull=never --network=none --gpus all \
      --entrypoint python "$_t1_image" -c \
      'import onnxruntime as ort; assert "CUDAExecutionProvider" in ort.get_available_providers()'; then
    echo "[tier1-topology][error] the Tier-1 image cannot expose the CUDAExecutionProvider" >&2
    return 1
  fi
  return 0
}
