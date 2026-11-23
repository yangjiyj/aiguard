# Tier-1 自训基线模型部署说明

把 Tier-1 模型从 gated Prompt-Guard-2（hf-mirror 403、Llama 许可传导）换成自训开源融合分类器
（多语 embedder + LR 头，MIT/Apache）。解锁此前卡在「下 gated 模型」的部署。

## 一、厂商侧正式构建（home 构建机）

正式 r7 包只接受已训练、已审核的本地模型输入；不下载 Hugging Face 权重，也不在构建机训练替代模型。

先从 home 已验证的本地 Tier1 镜像抽取 Python 依赖快照。该步骤只读取 Docker
本地镜像，显式使用 `--network none`，不会访问任何软件源：

```bash
bash deploy/docker-compose/prepare-tier1-python-deps-input.sh \
  --source-image docker-compose-tier1-classifier:latest \
  --output /home/dev/jjdguard-release-inputs/tier1-python-deps-local

bash deploy/docker-compose/prepare-alpine-runtime-input.sh \
  --source-image <home-current-gateway-image-id> \
  --output /home/dev/jjdguard-release-inputs/alpine-runtime-current

bash deploy/docker-compose/prepare-security-engine-python-deps-input.sh \
  --source-image <home-running-security-engine-image-id> \
  --output /home/dev/jjdguard-release-inputs/security-engine-python-deps-current
```

```bash
TIER1_OWNED_MODEL_INPUT=/home/dev/jjdguard-model-inputs/tier1-prompt-guard-2-5abf5273fc4c \
TIER1_PYTHON_DEPS_INPUT=/home/dev/jjdguard-release-inputs/tier1-python-deps-local \
JUDGE_OWNED_MODEL_INPUT=/home/dev/local-llm/models/Qwen3-4B-Instruct-2507-Q4_K_M.gguf \
OFFLINE_RELEASE_GO_CACHE_INPUT=/home/dev/go \
OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT=/home/dev/jjdguard-release-inputs/alpine-runtime-current \
OFFLINE_RELEASE_SECURITY_ENGINE_PYTHON_DEPS_INPUT=/home/dev/jjdguard-release-inputs/security-engine-python-deps-current \
OFFLINE_RELEASE_LLM_JUDGE_RUNTIME_INPUT=docker-compose-llm-judge:latest \
OFFLINE_RELEASE_THIRD_PARTY_INPUT_MODE=cache-only \
BUNDLE_PROFILE=full INCLUDE_CHAT=1 \
bash deploy/docker-compose/build-offline-images-for-arch.sh amd64
```

两个输入分别由 `owned-tier1-model.lock.json` 与 `owned-judge-model.lock.json` 按文件名、大小和 SHA-256 核验；任一不匹配即拒绝构建。旧的 `scripts/build-baseline-model.sh`、`scripts/build-tier1-image.sh` 和 `scripts/fetch-model.sh` 已固定拒绝，不能用于正式包。

Tier1 的 Python 依赖快照还会逐包比对 `requirements.lock`、记录来源镜像 ID 与
内容 SHA-256；正式 Docker 构建只复制该快照并执行 `pip check`。

## 二、客户/home 部署侧（需用户发起的 live 步骤）

> 以下为 home 上的 live 部署，需用户发起执行。

1. 起 full profile（自带 sidecar）：
   ```bash
   docker compose --profile full up -d tier1-classifier
   ```
2. 在 `.env` 开启级联（默认关，observe-only）：
   ```
   SECURITY_TIER1_ENABLED=true
   ```
   阈值沿用 `SECURITY_TIER1_LOW_THRESHOLD=0.2` / `SECURITY_TIER1_HIGH_THRESHOLD=0.8`（bench 产初值，可调）。
3. 跑验收闸坐实自训模型生效（中文越狱高分 / 良性低分）：
   ```bash
   GATE_PROFILE=full bash deploy/lib/acceptance-gate.sh
   ```
   预期：`tier1-classifier /classify 中文越狱样本高分(...自训融合 ONNX 生效)` + `良性样本低分`。

## 三、红线（沿用，不破）

- sidecar fail-open 不变：模型缺/依赖缺 → /classify 503 → security-engine fail-open，绝不假阳。
- observe-only：Tier-1 只产 finding 进收件箱，不改 security-engine 决策链/gateway/bridge。
- 许可干净：基线由训练产，不再下 gated 模型；embedder 限 MIT/Apache 白名单。

## 有界语义覆盖与联合升级

security-engine 和 tier1-classifier 必须联合升级：新的 `/classify` 成功响应带
`coverage_complete: true`。旧分类器缺少该字段时引擎报告未完成，不把旧版前 512 token
评分当成全量通过。模型无需重新训练，但上线前要用真实 ONNX/本地 tokenizer 验证多窗口评分。

- 引擎按 1200 字符、200 字符重叠切片，裁判处理同一风险片段；一次请求共用总截止时间。
- `SECURITY_SEMANTIC_MAX_WINDOWS` 默认 32，允许 1–256；超出数量或时间预算记录
  `semantic_status=incomplete`、已覆盖字符数、未覆盖区间，不自动判安全或攻击。
- 分类器按 512 token 窗口、64 token 重叠评分；`TIER1_MAX_TOKEN_WINDOWS` 默认 16，
  允许 1–32。请求最大 4096 字符，超预算拒绝而非静默截断；最大攻击概率来自任一窗口。
- 窗口数量增加 CPU 成本；按文本长度、触发比例、实际硬件测单实例容量。该预算与产品
  QPS 上限无关，可独立增加推理实例。检测阈值由效果评估决定，硬件 benchmark 只调执行超时。
- 工具/RAG/检索正文进入间接注入语义扫描；系统模板、工具定义和助手历史保留原精度处理。
  来源角色不是内容可信证明；上下文中的任务/动作仅是引用证据，不授予权限。
