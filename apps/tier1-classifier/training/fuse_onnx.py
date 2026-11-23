"""融合 ONNX 导出（D6：embedder+LR 头拼成单 model.onnx）。

机制：skl2onnx 把 LogisticRegression 转 ONNX（输入=句向量→输出 label+probabilities）
→ onnx.compose.merge_models 把 embedder 的 sentence_embedding 输出接到 LR 输入 → 单图。
id2label={0:benign,1:attack}（与 head.LABEL_ORDER 对齐）。
"""
from __future__ import annotations

import onnx
from onnx import compose, helper, TensorProto
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# ai.onnx（默认算子域）的 domain 字符串为空串 ""。skl2onnx 另带 ai.onnx.ml 域。
_AI_ONNX_DOMAIN = ""

_HIDDEN_OUTPUT = "last_hidden_state"
_SENTENCE_EMBEDDING = "sentence_embedding"


def _drop_token_type_ids(
    model, *, ids_name: str = "input_ids", tti_name: str = "token_type_ids"
):
    """若 embedder ONNX 把 token_type_ids 列为**必需输入**，就地移除它并烘成图内零常量。

    根因：optimum 导出的 e5/BERT ONNX 硬把 token_type_ids 设为必需输入，但生产/训练用的
    tokenizer（XLM-R/BERT，单段）只出 input_ids+attention_mask——numpy 的 TextEncoder.encode
    也从不喂 token_type_ids（torch BertModel 内部默认零）。若不剥离，融合图会要一个分词器
    从不产出的输入，parity/bench/生产 sidecar 全喂不进 → 图不可用。

    单段句向量 token_type 恒 0，故用 input_ids 的形状生成同形 int64 零张量替代该输入
    （Shape(input_ids)→ConstantOfShape(0)），语义与「全零 token_type_ids」完全一致。
    图不含该输入时原样返回（如已用别的路径导出/mock 图）。"""
    g = model.graph
    if tti_name not in [i.name for i in g.input]:
        return model
    zero_nodes = [
        helper.make_node("Shape", [ids_name], ["_tti_shape"]),
        helper.make_node(
            "ConstantOfShape", ["_tti_shape"], [tti_name],
            value=helper.make_tensor("_tti_zero", TensorProto.INT64, [1], [0])),
    ]
    # 供给节点须在消费者之前 → 插到图节点表头部（保持相对顺序）。
    for n in reversed(zero_nodes):
        g.node.insert(0, n)
    keep = [i for i in g.input if i.name != tti_name]
    del g.input[:]
    g.input.extend(keep)
    return model


def add_mean_pool_l2norm(
    embedder_onnx,
    *,
    hidden_name: str = _HIDDEN_OUTPUT,
    mask_name: str = "attention_mask",
    out_name: str = _SENTENCE_EMBEDDING,
):
    """池化桥（RFIX）：给只出 3D last_hidden_state 的 embedder ONNX 追加
    mean-pool(按 attention_mask)+L2 归一 节点，产 2D 句向量 sentence_embedding。

    背景：ORTModelForFeatureExtraction 导出的 embedder ONNX 只有 3D last_hidden_state，
    **没有** 2D sentence_embedding；但训练时 encoder.TextEncoder.encode 的句向量是 numpy 里
    对 last_hidden_state 做 mask 加权 mean-pool + L2 归一得来的。融合图的 embedder 输出必须
    是句向量（LR 头就是在句向量上训的），否则维度/语义与 LR 输入对不上、LR 头白训。

    追加的节点与 encoder._mean_pool + L2 **逐步一致**（数值一致性由 test_pooling_bridge /
    真 e5 端到端 parity 证明 max_abs_diff < 1e-4）：
      maskf   = Cast(attention_mask, float)           # [b,s]
      mask3   = Unsqueeze(maskf, axis=-1)             # [b,s,1]
      summed  = ReduceSum(hidden * mask3, axis=1)     # [b,h]
      counts  = Max(ReduceSum(mask3, axis=1), 1e-9)   # [b,1]（clip 下限，防全 0 mask 除零）
      vecs    = summed / counts                        # [b,h]
      norm    = Max(Sqrt(ReduceSum(vecs^2, axis=1, keepdims)), 1e-9)  # [b,1]
      out     = vecs / norm                            # [b,h] = 句向量

    同时剥离 token_type_ids 必需输入（见 _drop_token_type_ids），使融合图输入与生产
    tokenizer 输出（input_ids+attention_mask）一致。就地修改并返回同一 model（已过 checker）。
    opset 保持 embedder 原样（e5 导出为 ai.onnx 18；Unsqueeze/ReduceSum 的 axes 走 input 形式，
    与 opset≥13 一致，融合时再由 _align_ai_onnx_opset 与 LR 对齐）。"""
    embedder_onnx = _drop_token_type_ids(embedder_onnx)
    g = embedder_onnx.graph

    hidden_dim = None
    for o in g.output:
        if o.name == hidden_name:
            dims = o.type.tensor_type.shape.dim
            if len(dims) >= 1:
                hidden_dim = dims[-1].dim_value or None
            break
    else:
        raise ValueError(
            f"embedder ONNX 无 {hidden_name!r} 输出，无法加池化桥（现有输出："
            f"{[o.name for o in g.output]}）"
        )

    nodes = [
        helper.make_node("Cast", [mask_name], ["_maskf"], to=TensorProto.FLOAT),
        helper.make_node("Constant", [], ["_ax_last"],
                         value=helper.make_tensor("_ax_last", TensorProto.INT64, [1], [-1])),
        helper.make_node("Unsqueeze", ["_maskf", "_ax_last"], ["_mask3"]),  # [b,s,1]
        helper.make_node("Mul", [hidden_name, "_mask3"], ["_masked"]),
        helper.make_node("Constant", [], ["_ax1"],
                         value=helper.make_tensor("_ax1", TensorProto.INT64, [1], [1])),
        helper.make_node("ReduceSum", ["_masked", "_ax1"], ["_summed"], keepdims=0),  # [b,h]
        helper.make_node("ReduceSum", ["_mask3", "_ax1"], ["_counts_raw"], keepdims=0),  # [b,1]
        helper.make_node("Constant", [], ["_lo"],
                         value=helper.make_tensor("_lo", TensorProto.FLOAT, [], [1e-9])),
        helper.make_node("Max", ["_counts_raw", "_lo"], ["_counts"]),
        helper.make_node("Div", ["_summed", "_counts"], ["_vecs"]),  # mean-pool = [b,h]
        helper.make_node("Mul", ["_vecs", "_vecs"], ["_sq"]),
        helper.make_node("ReduceSum", ["_sq", "_ax1"], ["_ssum"], keepdims=1),  # [b,1]
        helper.make_node("Sqrt", ["_ssum"], ["_norm_raw"]),
        helper.make_node("Max", ["_norm_raw", "_lo"], ["_norm"]),
        helper.make_node("Div", ["_vecs", "_norm"], [out_name]),  # L2 归一 = 句向量
    ]
    g.node.extend(nodes)

    # 输出换成 2D sentence_embedding（丢弃 3D last_hidden_state，融合只接句向量）。
    del g.output[:]
    g.output.append(
        helper.make_tensor_value_info(out_name, TensorProto.FLOAT, ["batch_size", hidden_dim])
    )
    onnx.checker.check_model(embedder_onnx)
    return embedder_onnx


def lr_to_onnx(clf, *, input_dim: int, input_name: str = "sentence_embedding"):
    """LogisticRegression → ONNX。输出 zipmap 关闭，得纯 (n,2) probabilities 张量。"""
    onnx_model = convert_sklearn(
        clf,
        initial_types=[(input_name, FloatTensorType([None, input_dim]))],
        options={id(clf): {"zipmap": False}},
        target_opset=17,
    )
    return onnx_model


def _ai_onnx_opset(model) -> int | None:
    """读 model 的 ai.onnx（domain=""）opset 版本。skl2onnx 常写重复的 "" 条目，取 max。"""
    versions = [o.version for o in model.opset_import if (o.domain or "") == _AI_ONNX_DOMAIN]
    return max(versions) if versions else None


def _dedup_opset_imports(model) -> None:
    """原地去重 opset_import：每 domain 仅保留一条（取最高 version）。

    skl2onnx 会为 ai.onnx 写两条相同 "" 条目；version_converter 升级后又可能留下
    版本不一致的重复 "" 条目（如 [""=17, ""=18]，这本身是非法模型）。归一成每 domain
    唯一条目，既满足 merge_models 的一致性检查，也让 checker 通过。"""
    best: dict[str, int] = {}
    for o in model.opset_import:
        d = o.domain or ""
        if d not in best or o.version > best[d]:
            best[d] = o.version
    del model.opset_import[:]
    for d, v in best.items():
        model.opset_import.append(onnx.helper.make_opsetid(d, v))


def _align_ai_onnx_opset(embedder_onnx, lr_onnx):
    """对齐两子图的 ai.onnx（domain=""）opset，使 merge_models 不再因 opset 不一致报错。

    根因：optimum 导出的 embedder 用 ai.onnx opset 18，skl2onnx 转的 LR 用 opset 17
    （另带 ai.onnx.ml 域）。merge_models 要求同一 domain 的 opset 一致。策略：把 opset
    较低的子图用 onnx.version_converter 升到两者中的较高版本（只动 ai.onnx，ai.onnx.ml
    域保留 skl2onnx 默认），再去重 opset_import。升级方向（升到较高 opset）保证被升子图
    的算子在目标 opset 下有定义，比降级更稳。返回（可能已替换的）(embedder, lr)。"""
    emb_ver = _ai_onnx_opset(embedder_onnx)
    lr_ver = _ai_onnx_opset(lr_onnx)
    if emb_ver is None or lr_ver is None or emb_ver == lr_ver:
        # 无法判定或已一致：仅去重（防 skl2onnx 的重复 "" 条目干扰 merge）。
        _dedup_opset_imports(embedder_onnx)
        _dedup_opset_imports(lr_onnx)
        return embedder_onnx, lr_onnx

    target = max(emb_ver, lr_ver)
    if emb_ver < target:
        embedder_onnx = onnx.version_converter.convert_version(embedder_onnx, target)
    if lr_ver < target:
        lr_onnx = onnx.version_converter.convert_version(lr_onnx, target)
    _dedup_opset_imports(embedder_onnx)
    _dedup_opset_imports(lr_onnx)
    return embedder_onnx, lr_onnx


def fuse_embedder_and_head(embedder_onnx, lr_onnx, *, bridge_name: str = "sentence_embedding"):
    """把 embedder 的 bridge_name 输出接到 LR 的 bridge_name 输入，合成单图。

    要求 embedder 已导出 sentence_embedding 输出，LR 用同名输入（见 lr_to_onnx）。

    merge 前对齐两子图，避免 onnx.compose.merge_models 的两类一致性检查失败：

    1) ai.onnx（默认算子域）opset 对齐（本次修的 bug）：optimum 导出的 embedder 用
       ai.onnx opset 18，skl2onnx 转的 LR 用 opset 17（另带 ai.onnx.ml 域）。
       merge_models 要求同一 domain 的 opset 一致，否则报
       "Can't merge two models with different operator set ids"。
       _align_ai_onnx_opset 把较低子图升到较高 opset 并去重 opset_import。
       （旧 mock 测试两边恰好同为 17，没暴露此 bug。）

    2) IR 版本对齐：skl2onnx 的 LR IR 常低于 embedder，而 merge_models 要求两图 IR
       一致。对齐到较低 IR（min）：skl2onnx 的 IR 较保守，且 onnxruntime 对 IR 设上限
       （如 1.19 仅支持 ≤10），对齐到较低版本同时满足 merge 一致性与 runtime 可加载性。
    """
    embedder_onnx, lr_onnx = _align_ai_onnx_opset(embedder_onnx, lr_onnx)

    target_ir = min(embedder_onnx.ir_version, lr_onnx.ir_version)
    embedder_onnx.ir_version = target_ir
    lr_onnx.ir_version = target_ir
    merged = compose.merge_models(
        embedder_onnx,
        lr_onnx,
        io_map=[(bridge_name, bridge_name)],
    )
    onnx.checker.check_model(merged)
    return merged
