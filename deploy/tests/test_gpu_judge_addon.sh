#!/bin/bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADDON="$ROOT/docker-compose/gpu-judge-addon"
PACKAGER="$ROOT/docker-compose/package-offline-bundle.sh"
LOCK="$ROOT/docker-compose/owned-judge-model.lock.json"
fail() { echo "[fail] $*" >&2; exit 1; }
for file in Dockerfile Dockerfile.runtime prepare-runtime-input.py runtime-input.lock.json entrypoint.sh healthcheck.sh compose.yml install.sh verify.sh rollback.sh render-topology.sh README.md package.sh; do
  [[ -f "$ADDON/$file" ]] || fail "missing $file"
done
for file in entrypoint.sh healthcheck.sh install.sh verify.sh rollback.sh render-topology.sh package.sh; do bash -n "$ADDON/$file"; done

grep -Fq 'BUNDLE_VARIANT:-full-stack' "$PACKAGER" || fail 'top-level packager does not route variants'
grep -Fq 'gpu-judge-addon/package.sh' "$PACKAGER" || fail 'GPU addon bypasses the required package entry point'
grep -Fq 'bash "$SOURCE_GATE"' "$ADDON/package.sh" || fail 'non-executable source gate is invoked directly'
grep -Fq -- '--list-devices' "$ADDON/entrypoint.sh" || fail 'entrypoint does not fail closed without CUDA'
grep -Fq -- '--offline' "$ADDON/entrypoint.sh" || fail 'runtime does not force offline mode'
grep -Fq -- '--n-gpu-layers' "$ADDON/entrypoint.sh" || fail 'model layers are not offloaded'
grep -Fq -- '--flash-attn' "$ADDON/entrypoint.sh" || fail 'Flash Attention is not configured'
grep -Fq -- '--cont-batching' "$ADDON/entrypoint.sh" || fail 'continuous batching is not configured'
grep -Fq -- '--cache-type-k q8_0 --cache-type-v q8_0' "$ADDON/entrypoint.sh" || fail 'q8_0 KV cache is not configured'
grep -Fq -- '--api-key-file /tmp/jjdguard/api-key' "$ADDON/entrypoint.sh" || fail 'each instance must enforce the API key'
! grep -Fq -- '--ssl-cert-file' "$ADDON/entrypoint.sh" || fail 'TLS must terminate at the load balancer, not per instance'
grep -Fq 'healthcheck.sh /usr/local/bin/jjdguard-gpu-judge-health' "$ADDON/Dockerfile" || fail 'instance health check is not installed'
grep -Fq '/health' "$ADDON/healthcheck.sh" || fail 'instance health check must wait for model load (/health)'
grep -Fq 'test: ["CMD", "nginx", "-t", "-q", "-c", "/etc/nginx/nginx.conf"]' "$ADDON/compose.yml" || fail 'load balancer health check must use a command present in the pinned image'
! grep -Fq '"wget"' "$ADDON/compose.yml" || fail 'load balancer health check depends on wget, which is absent from the pinned image'
grep -Fq 'sha256sum -c manifest.sha256' "$ADDON/install.sh" || fail 'installer lacks fail-closed integrity verification'
grep -Fq 'chmod 0755 "$(dirname "$MODEL_FILE")"' "$ADDON/install.sh" || fail 'installer does not repair the model directory mode'
grep -Fq 'chmod 0444 "$MODEL_FILE"' "$ADDON/install.sh" || fail 'installer does not make the model readable by the non-root runtime'
grep -Fq 'docker run --rm --gpus all' "$ADDON/install.sh" || fail 'installer does not verify container GPU allocation'
grep -Fq 'render-topology.sh' "$ADDON/install.sh" || fail 'installer does not render the multi-instance topology'
grep -Fq 'runtime.env.pre-2.0.0' "$ADDON/install.sh" || fail '1.x runtime.env upgrade path missing'
grep -Fq -- '--remove-orphans' "$ADDON/install.sh" || fail 'installer must remove the 1.x single-instance container'
grep -Fq -- '--remove-orphans' "$ADDON/rollback.sh" || fail 'rollback must stop every generated instance'
grep -Fq 'compose.instances.yml' "$ADDON/rollback.sh" || fail 'rollback must include generated instances'
grep -Fq 'concurrency in 1 2 4' "$ADDON/verify.sh" || fail '1/2/4 concurrency verification missing'
grep -Fq 'llamacpp:tokens_predicted_total' "$ADDON/verify.sh" || fail 'verify must prove every instance received traffic'
! grep -Fq 'date +%s%3N' "$ADDON/verify.sh" || fail 'non-portable millisecond timing remains'
grep -Fq 'CUDA evidence' "$ADDON/verify.sh" || fail 'CUDA runtime evidence gate missing'
grep -Fq 'compatible_jjdguard_versions' "$ADDON/package.sh" || fail 'compatibility manifest missing'
grep -Fq '"2.6.15"' "$ADDON/package.sh" || fail '2.6.15 compatibility missing'
grep -Fq '"2.7.1"' "$ADDON/package.sh" || fail '2.7.1 compatibility missing'
grep -Fq 'read_env JUDGE_API_KEY' "$ADDON/verify.sh" || fail 'runtime.env must be parsed without shell execution'
grep -Fq 'JUDGE_API_KEY contains unsafe characters' "$ADDON/install.sh" || fail 'API key input validation missing'
grep -Fq 'openssl verify' "$ADDON/install.sh" || fail 'TLS chain and IP SAN verification missing'
grep -Fq 'acceptance-last.log' "$ADDON/install.sh" || fail 'acceptance evidence is not retained'
grep -Fq 'openssl s_client' "$ADDON/verify.sh" || fail 'runtime probe does not verify HTTPS'
grep -Fq -- '--build-context "gpu-runtime-input=' "$ADDON/package.sh" || fail 'sealed GPU runtime context is missing'
grep -Fq 'cuobjdump' "$ADDON/package.sh" || fail 'packager does not inspect compiled CUDA architectures'
grep -Fq 'libcuda.so.1:ro' "$ADDON/package.sh" || fail 'packager cannot validate the CUDA binary without a container runtime'
grep -Fq 'nginx -t' "$ADDON/package.sh" || fail 'packager does not validate the generated nginx configuration'
grep -Eq '^NGINX_BASE_IMAGE=".*@sha256:[0-9a-f]{64}"$' "$ADDON/package.sh" || fail 'nginx base image must be pinned by digest'
! grep -Fq -- '--remote ' "$ADDON/package.sh" || fail 'packager uses test-only upstream source arguments'
grep -Fq '(cd "$OUT" && sha256sum "$NAME.tar.gz"' "$ADDON/package.sh" || fail 'outer checksum is not relocatable'
if grep -Eq 'JUDGE_API_KEY=(bundled-judge|local-test-key)' "$ADDON"/*; then
  fail 'fixed API key leaked into the customer addon'
fi
# 4B 随包模型：不可商用 3B 不得再出现在附加包里；文件名与模型锁一致。
if grep -Eqi 'qwen2\.5-3b' "$ADDON"/*; then fail 'the non-commercial 3B model is still referenced by the GPU addon'; fi
lock_file="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["file"])' "$LOCK")"
for file in install.sh package.sh render-topology.sh entrypoint.sh; do
  grep -Fq "$lock_file" "$ADDON/$file" || fail "$file does not use the locked model file $lock_file"
done
grep -Fq 'JUDGE_ALIAS: bundled-judge' "$ADDON/render-topology.sh" || fail 'instances must serve the bundled-judge alias'
grep -Fq '"model":"bundled-judge"' "$ADDON/verify.sh" || fail 'verify must probe the bundled-judge alias'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
render() { bash "$ADDON/render-topology.sh" "$1" "$2"; }
write_env() {
  cat >"$tmp/$1.env" <<EOF
JUDGE_API_KEY=test-only
JUDGE_BIND_IP=127.0.0.1
JUDGE_HOST_PORT=18094
JUDGE_GPU_IDS=$2
JUDGE_INSTANCES_PER_GPU=$3
JUDGE_PARALLEL=$4
JUDGE_CTX=$5
JUDGE_THREADS=4
JUDGE_GPU_LAYERS=99
JUDGE_FLASH_ATTN=on
JUDGE_KV_CACHE_TYPE=q8_0
EOF
}

# 正样本：2 张卡 x 3 实例 = 6 个后端，每个实例绑定自己的卡。
mkdir -p "$tmp/ok"
write_env ok 0,1 3 16 131072
render "$tmp/ok.env" "$tmp/ok" >/dev/null || fail 'valid topology must render'
[[ "$(grep -c '^  judge-g[0-9]*-i[0-9]*:$' "$tmp/ok/compose.instances.yml")" == 6 ]] || fail 'expected 6 judge instances'
[[ "$(grep -c 'server judge-g[0-9]*-i[0-9]*:8080' "$tmp/ok/nginx/nginx.conf")" == 6 ]] || fail 'expected 6 nginx upstream servers'
grep -Fq 'least_conn;' "$tmp/ok/nginx/nginx.conf" || fail 'nginx must balance with least_conn'
grep -Fq 'zone judge_backends' "$tmp/ok/nginx/nginx.conf" || fail 'least_conn state must be shared across nginx workers (zone)'
grep -Fq 'listen 8443 ssl;' "$tmp/ok/nginx/nginx.conf" || fail 'nginx must terminate TLS'
grep -Fq 'proxy_next_upstream error http_502 http_503;' "$tmp/ok/nginx/nginx.conf" || fail 'nginx must fail over on dead instances only'
! grep -q 'proxy_next_upstream .*timeout' "$tmp/ok/nginx/nginx.conf" || fail 'nginx must not retry timed-out requests'
awk '/^  judge-g1-i2:$/{f=1} f && /device_ids:/{print; exit}' "$tmp/ok/compose.instances.yml" | grep -Fq '["1"]' ||
  fail 'judge-g1-i2 must be pinned to GPU 1'
! grep -q 'ports:' "$tmp/ok/compose.instances.yml" || fail 'judge instances must not publish host ports'
grep -Fq 'condition: service_healthy' "$tmp/ok/compose.instances.yml" || fail 'nginx must wait for healthy instances'
mode="$(stat -c '%a' "$tmp/ok/nginx/nginx.conf")"
[[ "$mode" == 644 ]] || fail "nginx.conf must be readable by the nginx user, got $mode"

# 负样本：非法拓扑一律拒绝，且不留下半成品。
reject() {
  local name="$1"; shift
  mkdir -p "$tmp/$name"
  write_env "$name" "$@"
  if render "$tmp/$name.env" "$tmp/$name" >/dev/null 2>&1; then fail "topology must be rejected: $name"; fi
  [[ ! -e "$tmp/$name/compose.instances.yml" ]] || fail "rejected topology left output behind: $name"
}
reject dup-gpu 0,0 3 16 32768
reject bad-gpu 'all' 3 16 32768
reject zero-inst 0 0 16 32768
reject many-inst 0 9 16 32768
reject big-parallel 0 3 33 65536
reject small-slot 0 3 16 16384
reject old-2k-slot 0 1 2 4096
reject below-long-bound 0 1 2 16052
mkdir -p "$tmp/rtx12g"
write_env rtx12g 0 1 2 16384
render "$tmp/rtx12g.env" "$tmp/rtx12g" >/dev/null || fail '12 GiB GPU topology must render'
[[ "$(grep -c '^  judge-g' "$tmp/rtx12g/compose.instances.yml")" == 1 ]] || fail '12 GiB GPU must use one instance'
missing="$tmp/missing"; mkdir -p "$missing"
grep -v '^JUDGE_INSTANCES_PER_GPU=' "$tmp/ok.env" >"$missing.env"
if render "$missing.env" "$missing" >/dev/null 2>&1; then fail 'missing JUDGE_INSTANCES_PER_GPU must be rejected'; fi

# 真实 Compose 合并：基础层 + 生成层可渲染，且只有 nginx 对外发布端口。
cp "$ADDON/compose.yml" "$tmp/ok/compose.yml"
cp "$tmp/ok.env" "$tmp/ok/runtime.env"
mkdir -p "$tmp/ok/models" "$tmp/ok/tls"
touch "$tmp/ok/models/$lock_file"
dc() { docker compose -p jjdguard-gpu-judge-test --env-file "$tmp/ok/runtime.env" -f "$tmp/ok/compose.yml" -f "$tmp/ok/compose.instances.yml" "$@"; }
rendered="$(dc config)" || fail 'combined Compose must render'
[[ "$(grep -c 'published:' <<<"$rendered")" == 1 && "$(grep -c 'published: "18094"' <<<"$rendered")" == 1 ]] ||
  fail 'only judge-lb may publish exactly one host port'
[[ "$(dc config --services | grep -c .)" == 7 ]] || fail 'expected judge-lb plus 6 instances'

# rollback.sh 行为：用假 docker 记录参数，必须同时带上生成的实例层并清理孤儿容器。
fakebin="$tmp/fakebin"; mkdir -p "$fakebin"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>"$FAKE_DOCKER_LOG"\n' >"$fakebin/docker"
chmod 0755 "$fakebin/docker"
cp "$ADDON/rollback.sh" "$tmp/ok/rollback.sh"
PATH="$fakebin:$PATH" FAKE_DOCKER_LOG="$tmp/rollback.log" bash "$tmp/ok/rollback.sh" >/dev/null ||
  fail 'rollback.sh must succeed'
grep -Fq -- "-f $tmp/ok/compose.yml -f $tmp/ok/compose.instances.yml down --remove-orphans" "$tmp/rollback.log" ||
  fail "rollback must stop the load balancer and every generated instance, got: $(cat "$tmp/rollback.log")"

# 真实 nginx 语法检查（有本地 nginx 镜像时执行；打包时 package.sh 强制执行）。
nginx_image="$(sed -n 's/^NGINX_BASE_IMAGE="\(.*\)"$/\1/p' "$ADDON/package.sh")"
if docker image inspect "$nginx_image" >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=check' \
    -keyout "$tmp/ok/tls/server.key" -out "$tmp/ok/tls/server.crt" >/dev/null 2>&1
  chmod 0644 "$tmp/ok/tls/server.key"
  hosts=()
  for h in $(grep -oE 'judge-g[0-9]+-i[0-9]+' "$tmp/ok/nginx/nginx.conf" | sort -u); do hosts+=(--add-host "$h:127.0.0.1"); done
  docker run --pull=never --network=none --rm "${hosts[@]}" \
    -v "$tmp/ok/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$tmp/ok/tls:/tls:ro" \
    "$nginx_image" nginx -t -c /etc/nginx/nginx.conf >/dev/null 2>&1 || fail 'generated nginx configuration is invalid'
  echo '[ok] generated nginx configuration passed nginx -t'
else
  echo '[skip] nginx syntax check: locked nginx image not cached (package.sh enforces it)'
fi
# install.sh 行为（假 nvidia-smi / docker，真实 openssl）：1.x runtime.env 升级 + 拓扑渲染 + 等待全部健康。
inst="$tmp/inst"; ibin="$tmp/ibin"
mkdir -p "$inst/images" "$inst/models" "$ibin"
for f in install.sh render-topology.sh compose.yml; do cp "$ADDON/$f" "$inst/$f"; done
printf '#!/bin/bash\necho "[ok] verify stub"\n' >"$inst/verify.sh"; chmod 0755 "$inst/verify.sh"
: >"$inst/images/llm-judge-gpu.tar"; : >"$inst/images/judge-lb-nginx.tar"; : >"$inst/models/$lock_file"
chmod 0700 "$inst/models"; chmod 0400 "$inst/models/$lock_file"
(cd "$inst" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
cat >"$ibin/nvidia-smi" <<'EOS'
#!/bin/sh
case "$*" in *--query-gpu=index*) printf '0\n1\n' ;; *) echo 'GPU 0: fake' ;; esac
EOS
cat >"$ibin/docker" <<'EOS'
#!/bin/bash
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$*" in
  *' config --services'*)
    { for f in "$@"; do [[ "$f" == *compose.instances.yml ]] && grep -oE '^  judge-[a-z0-9-]+:' "$f" | tr -d ' :'; done
      echo judge-lb; } | sort -u ;;
  *' ps --format json'*)
    n=$(grep -c '^  judge-g' "$FAKE_ROOT/compose.instances.yml"); n=$((n + ${FAKE_UNHEALTHY_OFFSET:-1}))
    # 慢启动：前两次轮询只有一个服务健康。
    if [[ -n "${FAKE_SLOW_COUNTER:-}" ]]; then
      c=$(( $(cat "$FAKE_SLOW_COUNTER" 2>/dev/null || echo 0) + 1 )); echo "$c" >"$FAKE_SLOW_COUNTER"
      (( c <= 2 )) && n=1
    fi
    for ((i = 0; i < n; i++)); do printf '{"Health":"healthy"}\n'; done ;;
esac
exit 0
EOS
chmod 0755 "$ibin/nvidia-smi" "$ibin/docker"
cat >"$inst/runtime.env" <<'EOF'
JUDGE_API_KEY=0123456789abcdef0123456789abcdef
JUDGE_BIND_IP=127.0.0.1
JUDGE_HOST_PORT=8094
JUDGE_PARALLEL=4
JUDGE_CTX=16384
JUDGE_THREADS=4
JUDGE_GPU_LAYERS=99
JUDGE_FLASH_ATTN=on
EOF
chmod 0600 "$inst/runtime.env"
run_install() {
  (cd "$inst" && PATH="$ibin:$PATH" FAKE_DOCKER_LOG="$tmp/install.log" FAKE_ROOT="$inst" GPU_JUDGE_HEALTH_TIMEOUT=5 \
    "$@" timeout 60 bash "$inst/install.sh" 2>&1 </dev/null)
}
out="$(run_install env)" || fail "install.sh must upgrade a 1.x runtime.env, got: $out"
[[ -f "$inst/runtime.env.pre-2.0.0" ]] || fail '1.x runtime.env must be backed up'
[[ "$(stat -c '%a' "$inst/models")" == 755 ]] || fail 'install must make the model directory traversable by the non-root runtime'
[[ "$(stat -c '%a' "$inst/models/$lock_file")" == 444 ]] ||
  fail 'install must make the model readable by the non-root runtime'
grep -Fxq 'JUDGE_PARALLEL=2' "$inst/runtime.env" && grep -Fxq 'JUDGE_CTX=16384' "$inst/runtime.env" ||
  fail '1.x default P4/16K must move to the measured P16/32K defaults'
grep -Fxq 'JUDGE_GPU_IDS=0,1' "$inst/runtime.env" && grep -Fxq 'JUDGE_INSTANCES_PER_GPU=1' "$inst/runtime.env" ||
  fail 'upgrade must add all GPUs with 3 instances per GPU'
grep -Fxq 'JUDGE_API_KEY=0123456789abcdef0123456789abcdef' "$inst/runtime.env" || fail 'upgrade must keep the API key'
[[ "$(grep -c '^  judge-g' "$inst/compose.instances.yml")" == 2 ]] || fail 'install must render 2 GPUs x 1 instance'
grep -q 'up -d --remove-orphans' "$tmp/install.log" || fail 'install must start with --remove-orphans'
[[ "$out" == *'3 services healthy'* ]] || fail "install must wait for every service, got: $out"
# 第二次执行：已是 2.x 布局，runtime.env 原样保留；实例慢启动时必须等到全部健康。
cp "$inst/runtime.env" "$tmp/env.after"
out="$(run_install env FAKE_SLOW_COUNTER="$tmp/slow.count")" || fail "reinstall must wait for slow instances, got: $out"
[[ "$(cat "$tmp/slow.count")" -ge 3 ]] || fail 'install must keep polling until every service is healthy'
cmp -s "$inst/runtime.env" "$tmp/env.after" || fail 'reinstall must not rewrite a 2.x runtime.env'
# 客户自定义过并发的 1.x 配置：保留其值，只补新键。
cp "$inst/runtime.env.pre-2.0.0" "$inst/runtime.env"; rm -f "$inst/runtime.env.pre-2.0.0"
sed -i -e 's/^JUDGE_PARALLEL=4/JUDGE_PARALLEL=8/' -e 's/^JUDGE_CTX=16384/JUDGE_CTX=65536/' "$inst/runtime.env"
out="$(run_install env)" || fail "custom 1.x runtime.env must upgrade, got: $out"
grep -Fxq 'JUDGE_PARALLEL=8' "$inst/runtime.env" && grep -Fxq 'JUDGE_CTX=65536' "$inst/runtime.env" ||
  fail 'customised 1.x concurrency must be preserved'
# 负样本：不存在的 GPU、实例不健康。
sed -i 's/^JUDGE_GPU_IDS=.*/JUDGE_GPU_IDS=0,5/' "$inst/runtime.env"
if out="$(run_install env)"; then fail "unknown GPU index must be rejected, got: $out"; fi
[[ "$out" == *'nvidia-smi only reports'* ]] || fail "unknown GPU error must be explicit, got: $out"
sed -i 's/^JUDGE_GPU_IDS=.*/JUDGE_GPU_IDS=0/' "$inst/runtime.env"
if out="$(run_install env FAKE_UNHEALTHY_OFFSET=0 GPU_JUDGE_HEALTH_TIMEOUT=1)"; then
  fail "install must fail when an instance never becomes healthy, got: $out"
fi
grep -q ' down' "$tmp/install.log" || fail 'failed install must stop the services'

echo '[ok] GPU Judge addon static, topology, and Compose contract passed'
