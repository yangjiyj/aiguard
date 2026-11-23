# Tier-1 自训分类器：离线训练/重训管线

厂商侧离线产出「冻结多语 embedder + LR 头」融合单 `model.onnx`，替换 gated Prompt-Guard。
v1 与 Phase 2 共用同一条 `retrain` job + 同一张 `tier1_labels` 表（换后端不改 job）。

## 训练环境（研究用途，非正式打包链）

训练依赖（sklearn/skl2onnx/onnx/onnxruntime/optimum/transformers/torch）与 sidecar 运行时分离：

```
python3 -m venv .venv-train && . .venv-train/bin/activate
pip install -r requirements-train.txt
```

许可红线：embedder 只用 MIT/Apache/BSD（`training/license_gate.py` 白名单闸），零 gated、零 Llama 传导。
默认 embedder = `intfloat/multilingual-e5-small`（MIT，revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`）。所有 `from_pretrained` 调用均使用 `local_files_only=True`；训练前必须由操作者提供已审核的本地快照，不能联网下载。

## 标签存储契约

表 `tier1_labels(id, text, label, category, source, created_at)`：
- `label ∈ {benign, attack}`；`source ∈ {seed, distill, correction}`；
- `category` 对齐 `semantic.py` 4 类 key（semantic_jailbreak/roleplay/instruction_override/exfil_induce）或 `"none"`。

v1 后端 = 本地 SQLite（`training/label_store.py`）。Phase 2 客户侧同 schema 映射 postgres。

## 种子入库 + 重训

```
# 1) 种子 JSONL → 标签库（label 1/0→attack/benign，source=seed）
python -c "from training.label_store import LabelStore; from training.seed_ingest import ingest_seed_jsonl; \
s=LabelStore('labels.db'); ingest_seed_jsonl(['../security-engine/bench/data/zh_jailbreak.jsonl','../security-engine/bench/data/zh_benign.jsonl'], s)"

# 2) retrain：只能消费预先准备好的本地快照
export TIER1_EMBEDDER_SNAPSHOT=/absolute/path/to/reviewed/embedder-snapshot
export TIER1_EMBEDDER_ID=intfloat/multilingual-e5-small
export TIER1_EMBEDDER_REVISION=614241f622f53c4eeff9890bdc4f31cfecc418b3
python -m training.retrain --db labels.db --out-dir models/selftrained
```

产物：`models/selftrained/{model.onnx, config.json, tokenizer*}`，`config.id2label = {0:benign, 1:attack}`。
融合图对齐校验（融合 ONNX 攻击概率 ≈ sklearn LR 概率，容差 1e-3）不过则阻断出模型。

## 测试运行

测试在装了 `requirements-train.txt` 的训练 venv 跑（无依赖时相关测试经 `pytest.importorskip` 自动跳过）：

```
python3 -m pytest training/tests/ -q
```

需真模型的端到端（默认 embedder 真编码/真 optimum 导 ONNX）测试标记为 `slow`，
日常 CI 不跑。核心融合/对齐/训练逻辑均用极小 mock embedder ONNX 与 mock 编码器覆盖；真模型测试也只读取上面指定的本地快照：`python3 -m pytest training/tests/ -q -m slow`。
