#!/bin/sh
# 构建 docker-compose-llm-judge:latest。
# 从 llama.cpp build-cpu 暂存二进制 + .so 进构建上下文 bin/，再 docker build。
# 在构建机（home）上跑。LLAMA_BIN_DIR 可 env 覆盖。
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
LLAMA_BIN_DIR="${LLAMA_BIN_DIR:-/home/dev/local-llm/llama.cpp-src/build-cpu/bin}"

[ -x "$LLAMA_BIN_DIR/llama-server" ] || { echo "[error] 未找到 llama-server: $LLAMA_BIN_DIR" >&2; exit 1; }

rm -rf "$SCRIPT_DIR/bin"
mkdir -p "$SCRIPT_DIR/bin"
cp -P "$LLAMA_BIN_DIR/llama-server" "$SCRIPT_DIR/bin/"
cp -P "$LLAMA_BIN_DIR"/*.so* "$SCRIPT_DIR/bin/"
echo "[step] staged $(ls -1 "$SCRIPT_DIR/bin" | wc -l | tr -d ' ') files into bin/"

docker build -t docker-compose-llm-judge:latest "$SCRIPT_DIR"
echo "[ok] built docker-compose-llm-judge:latest"
