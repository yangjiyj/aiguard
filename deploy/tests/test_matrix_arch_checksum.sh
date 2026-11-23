#!/usr/bin/env bash
# #7 架构不匹配 + #8 校验和错误：纯逻辑验收，复用 self-extracting fixture。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HEADER="$ROOT/deploy/offline-installer/self-extracting-header.sh"
# shellcheck source=lib-self-extracting-v2-fixture.sh
. "$ROOT/deploy/tests/lib-self-extracting-v2-fixture.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
[[ -f "$HEADER" ]] || fail "missing header"
command -v docker >/dev/null 2>&1 || { echo "[skip] 无 docker"; exit 0; }
docker info >/dev/null 2>&1 || { echo "[skip] docker daemon 不可用"; exit 0; }
stamp='python:3.12-slim'
docker image inspect "$stamp" >/dev/null 2>&1 || { echo "[skip] $stamp 不可用"; exit 0; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
OUTER="$WORK/outer"; mkdir -p "$OUTER"

# 构造一个 payload + 签名材料（不直接封装 .run，便于篡改后重封）
build_payload() {
  local arch="$1"
  local fr="$WORK/payload/jjdguard-fixture"
  if [[ ! -f "$WORK/k" ]]; then
    openssl genpkey -algorithm Ed25519 -out "$WORK/k" 2>/dev/null
    openssl pkey -in "$WORK/k" -pubout -out "$WORK/pub" 2>/dev/null
  fi
  rm -rf -- "$WORK/payload"
  mkdir -p "$WORK/payload"
  jjd_v2_make_bundle "$fr" "$WORK/k" "$arch" "$ROOT/deploy/docker-compose/release-toolchain.lock"
  jjd_v2_write_inventory "$fr"
}

# 根据 target_arch 生成 manifest + 签名 + 封装 .run 到 $1
seal_run() {
  local arch="$1" out="$2"
  rm -rf -- "$OUTER"
  jjd_v2_seal_run "$HEADER" "$WORK/k" "$WORK/pub" "$WORK/payload/jjdguard-fixture" "$out" "$OUTER" "$arch"
}

# ===== #7 架构不匹配：target_arch=arm64 的包在 amd64 机跑 → exit 21 =====
build_payload arm64
seal_run arm64 "$WORK/arm64.run"
# This is an isolated candidate fixture. Formal delivery must enter through
# the independent trusted verifier, while this regression exercises only the
# installer architecture guard.
o7="$(docker run --rm -v "$WORK/arm64.run:/f.run:ro" "$stamp" bash -c 'bash /f.run 2>&1; echo EXIT=$?' </dev/null)"
echo "$o7" | grep -q "EXIT=21" || fail "#7 架构不匹配应 exit 21，实际: $o7"
echo "$o7" | grep -qiE "arm64|amd64|架构|architecture" || fail "#7 未提示架构信息: $o7"
echo '[ok] #7 架构不匹配正确拒绝(exit 21)'

# ===== #8 校验和错误：篡改 payload.tar.gz → --verify-only exit 40 =====
build_payload amd64
seal_run amd64 "$WORK/good.run"
# 先确认未篡改 verify 通过
docker run --rm -v "$WORK/good.run:/f.run:ro" "$stamp" bash /f.run --verify-only >/dev/null || fail "#8 未篡改应 verify 通过"
# 篡改 payload.tar.gz（追加 1 字节，改变其实际 sha256），但保留旧的 run-manifest（旧 sha）+ 旧签名
# → header 验签通过（签名覆盖 manifest，manifest 未变），但 payload sha256 与 manifest 记录不符 → fail_signature exit 40
printf 'X' >>"$OUTER/payload.tar.gz"
# 用篡改后的 payload + 未改的 manifest/sig 重打 outer.tar
tar -C "$OUTER" -cf "$WORK/outer.tar" payload.tar.gz run-manifest.json run-manifest.sig
sed "s|__EMBEDDED_PUBLIC_KEY__|$(openssl base64 -A <"$WORK/pub")|" "$HEADER" >"$WORK/tampered.run"
dd if="$WORK/outer.tar" of="$WORK/tampered.run" bs=1M oflag=append conv=notrunc status=none
chmod 755 "$WORK/tampered.run"
set +e
o8="$(docker run --rm -v "$WORK/tampered.run:/f.run:ro" "$stamp" bash -c 'bash /f.run --verify-only 2>&1; echo EXIT=$?' </dev/null)"
set -e
echo "$o8" | grep -q "EXIT=40" || fail "#8 校验和错误应 exit 40，实际: $o8"
echo "$o8" | grep -qiE "签名或内容校验失败" || fail "#8 未报校验失败: $o8"
echo '[ok] #8 校验和错误正确拒绝(exit 40)'

echo '[ok] #7/#8 测试通过'
