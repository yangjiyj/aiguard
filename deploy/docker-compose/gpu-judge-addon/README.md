# JJDGuard GPU Judge 2.1.0 candidate

This component runs the bundled owned 4B Judge behind an HTTPS nginx endpoint.
It does not change gateway policy, database contents, or the installed gateway.
The repair targets requests that exceeded the old 2048-token slot capacity.

## Qualified geometry

- One RTX 3060 12 GiB (SM86), one instance, parallel 2.
- Total context 16384: 8192 tokens per slot. Smaller slots are rejected.
- F16 KV, Flash Attention on, GPU layers 99, threads 4.
- Batch 512, microbatch 128, prompt cache 1024 MiB.
- Original owned model, full semantic prompt, strict schema, reply limit 128,
  temperature 0, Judge timeout 24 seconds and semantic timeout 25 seconds.

The native host pilot completed 32 calls with no timeout (maximum 4.18 seconds).
These figures are pilot evidence. Container, HTTPS and complete application
acceptance must be reported separately; they are not implied by that pilot.
Policy smoke cases were extracted from examples in the system prompt and do
not establish held-out accuracy or production throughput.

## Build and provenance

Use the official top-level package-offline-bundle.sh GPU addon variant.
The source gate still requires clean main matching live Gitee and central bare.
Set JUDGE_OWNED_MODEL_INPUT, JUDGE_GPU_CORE_INPUT and
JUDGE_GPU_EXTENSION_RECEIPT to the reviewed local input paths.

The build reuses the frozen original 33 native files and the admitted SM86 CUDA
extension. It performs no recompilation. runtime-input.lock.json binds the base
image, original build receipt, extension receipt, CUDA libraries and license
files. CUDA toolkit version is 12.4. The NVIDIA driver is supplied by the host.
The resulting image is checked against every original file, added library,
symlink kind and source wrapper. A checksum failure stops packaging.
A100/H200 and the old L40 throughput figures are not qualifications for this
SM86 artifact. Other architectures require their own admitted extension.

## Install on a separate GPU host

Requires Linux amd64, an NVIDIA driver, Docker Compose v2, NVIDIA Container
Toolkit and OpenSSL. Validate GPU availability with nvidia-smi before install.

    JUDGE_BIND_IP=10.0.0.25 bash install.sh

Defaults: all selected GPU IDs, one instance per GPU, parallel 2, context 16384,
F16 KV. API keys are generated per installation and are not printed. TLS uses a
per-installation CA and an IP SAN certificate, or supplied internal PKI files.
Model instances expose only the internal network; nginx publishes HTTPS.
Existing configurations are preserved. An old context smaller than 8192 tokens
per slot is rejected and needs an explicit operator configuration update.
The recognized 1.x default is migrated to parallel 2/context 16384.

Trust tls/ca.crt on the gateway and set custom Judge to
https://GPU_HOST:8094/v1/chat/completions, model bundled-judge, the generated key,
and allow private egress. Keep Judge 24 seconds and semantic timeout 25 seconds.
No production endpoint is switched by building or validating this candidate.

## Validate and roll back

Run bash verify.sh. Its legacy short smoke is supplementary; release acceptance
must also exercise real product payloads, long and uncommon-character inputs,
strict response parsing, concurrency 2, authentication and verified TLS.
Restore the previous gateway endpoint before bash rollback.sh. Rollback stops
only the addon project and preserves models, keys, certificates and evidence.
