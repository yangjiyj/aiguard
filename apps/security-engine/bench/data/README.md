# 中文 bench 数据集（Tier-1 分类器判定门）

两份 JSONL，给 `bench/run_bench.py` 消费，产出召回/精度/延迟 + 裁判升级率。

## 字段
- `zh_jailbreak.jsonl`：`{"text": str, "label": 1, "category": <semantic.py _CATEGORY_CN 的 key>}`
- `zh_benign.jsonl`：`{"text": str, "label": 0}`（含硬负样本：良性角色扮演 / 安全从业者合法提问 / 运维问 system prompt / 写作类「扮演」）

## 标注口径
- label=1（攻击）：意图操纵模型行为——越狱 / 角色扮演绕过 / 指令覆盖 / 数据外泄诱导。
- label=0（良性）：正常业务、写作、安全科普/授权研究、运维配置；尤其纳入「字面像攻击实则正常」的硬负样本，避免良性误升级率虚低。
- `category` 仅对攻击样本标注，5 类与 `app/detectors/semantic.py` 的 `_CATEGORY_CN` key 一一对应，用于 label→category 映射核对。

## 扩充方法
- 越狱样本可参考公开越狱语料（DAN/AIM/grandma exploit 等范式）改写为中文，**不可直接照搬英文原文**——本期门是中文召回。
- 每新增一批，跑 `tests/test_bench_dataset.py` 守 schema/去重/类目齐全；跑 `run_bench.py` 复核阈值不漂移。
- 数量原则：当前攻击/良性各 ≥80 条（v1 自训种子扩充，4 类均衡 + 难负样本足）；home e2e 阶段可再扩。

## 来源
- 手工高质量中文样本（越狱范式改写 + 业务场景良性/难负样本）。
- v1 种子另由 `apps/tier1-classifier/training/seedgen` 合成器（真 LLM 在 home 构建机跑）+ 开源集清洗产出，灌入 `tier1_labels(source=seed)`。
