"""池化桥单测（RFIX：真实 embedder ONNX 只出 3D last_hidden_state，缺句向量输出）。

融合链要求 embedder 子图输出 2D `sentence_embedding`，且必须与训练时
`TextEncoder.encode` 的 numpy 句向量**逐元素一致**（否则 LR 头白训）。
add_mean_pool_l2norm 在导出图里追加 mean-pool(按 attention_mask)+L2 归一 节点，
本测用纯 numpy 参照证明数值一致（真 e5 模型的一致性由 test_real_embedder 覆盖，
此处用确定性小图快测节点语义 + token_type_ids 剥离）。
"""
import numpy as np
import pytest

pytest.importorskip("onnx")
ort = pytest.importorskip("onnxruntime")

import onnx
from onnx import helper, TensorProto

from training.fuse_onnx import add_mean_pool_l2norm
from training.encoder import _mean_pool


def _hidden_stub_onnx(hidden=6, with_token_type_ids=False):
    """占位 embedder：input_ids/attention_mask(+可选 token_type_ids) →
    last_hidden_state[b,s,hidden]（把 input_ids 广播/映射成确定的隐藏态，便于对拍）。

    构造：idsf=Cast(input_ids)->[b,s]，Unsqueeze(-1)->[b,s,1]，Mul 常量[1,hidden]广播
    ->last_hidden_state[b,s,hidden]（每个隐藏维 = input_ids * (0.1*d)）。
    与是否含 token_type_ids 无关（token_type 单段恒 0，不参与），用于验证剥离后语义不变。
    """
    ins = [
        helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["b", "s"]),
        helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["b", "s"]),
    ]
    nodes = []
    if with_token_type_ids:
        ins.append(helper.make_tensor_value_info("token_type_ids", TensorProto.INT64, ["b", "s"]))
        # 制造对 token_type_ids 的真实依赖：Cast 一下让它成为必需输入（输出丢弃，不接主链）。
        nodes.append(helper.make_node("Cast", ["token_type_ids"], ["ttf"], to=TensorProto.FLOAT))
    out = helper.make_tensor_value_info("last_hidden_state", TensorProto.FLOAT, ["b", "s", hidden])
    nodes += [
        helper.make_node("Cast", ["input_ids"], ["idsf"], to=TensorProto.FLOAT),
        helper.make_node("Constant", [], ["axn"],
            value=helper.make_tensor("axn", TensorProto.INT64, [1], [-1])),
        helper.make_node("Unsqueeze", ["idsf", "axn"], ["ids3"]),  # [b,s,1]
        helper.make_node("Constant", [], ["scale"],
            value=helper.make_tensor("scale", TensorProto.FLOAT, [1, hidden],
                                     [0.1 * (d + 1) for d in range(hidden)])),
        helper.make_node("Mul", ["ids3", "scale"], ["last_hidden_state"]),  # [b,s,hidden]
    ]
    g = helper.make_graph(nodes, "hidden_stub", ins, [out])
    m = helper.make_model(g, opset_imports=[helper.make_opsetid("", 18)])
    # 真 e5 导出 IR=8；onnxruntime 1.19 上限 IR≤10，与生产口径一致（默认 IR=12 会加载失败）。
    m.ir_version = 8
    onnx.checker.check_model(m)
    return m


def _numpy_reference(model_hidden, input_ids, attention_mask, hidden):
    """复刻 TextEncoder.encode 的 numpy 句向量：last_hidden(占位映射) → mean-pool → L2。"""
    idsf = input_ids.astype(np.float32)[..., None]  # [b,s,1]
    scale = np.array([0.1 * (d + 1) for d in range(hidden)], dtype=np.float32)  # [hidden]
    last_hidden = idsf * scale  # [b,s,hidden]
    vecs = _mean_pool(last_hidden, attention_mask)  # [b,hidden]（与生产同一函数）
    norms = np.clip(np.linalg.norm(vecs, axis=1, keepdims=True), 1e-9, None)
    return (vecs / norms).astype(np.float32)


def test_pooling_bridge_matches_numpy_encode():
    """池化桥输出 == numpy TextEncoder.encode 句向量（红线：max_abs_diff < 1e-4）。"""
    hidden = 6
    emb = _hidden_stub_onnx(hidden=hidden)
    bridged = add_mean_pool_l2norm(emb)
    # 输出应为 2D sentence_embedding，输入不含 3D 隐藏态输出
    out_names = [o.name for o in bridged.graph.output]
    assert out_names == ["sentence_embedding"], out_names
    onnx.checker.check_model(bridged)

    ids = np.array([[3, 5, 7, 0], [11, 13, 0, 0]], dtype=np.int64)
    mask = np.array([[1, 1, 1, 0], [1, 1, 0, 0]], dtype=np.int64)

    sess = ort.InferenceSession(bridged.SerializeToString())
    got = sess.run(["sentence_embedding"], {"input_ids": ids, "attention_mask": mask})[0]
    ref = _numpy_reference(emb, ids, mask, hidden)

    assert got.shape == ref.shape == (2, hidden)
    max_abs = float(np.max(np.abs(got - ref)))
    assert max_abs < 1e-4, f"池化桥与 numpy 句向量不一致 max_abs_diff={max_abs}"


def test_pooling_bridge_strips_token_type_ids():
    """真实 e5 ONNX 把 token_type_ids 列为必需输入，但 tokenizer 只出 input_ids+attention_mask。
    池化桥须剥离 token_type_ids（单段恒 0，烘成图内零常量），使融合图输入与分词器一致。"""
    emb = _hidden_stub_onnx(hidden=6, with_token_type_ids=True)
    assert "token_type_ids" in [i.name for i in emb.graph.input]

    bridged = add_mean_pool_l2norm(emb)
    in_names = [i.name for i in bridged.graph.input]
    assert "token_type_ids" not in in_names, in_names
    assert set(in_names) == {"input_ids", "attention_mask"}, in_names
    onnx.checker.check_model(bridged)

    # 剥离后仍可跑（token_type_ids 由图内零常量供给），且输出 2D 句向量
    sess = ort.InferenceSession(bridged.SerializeToString())
    ids = np.array([[3, 5, 7]], dtype=np.int64)
    mask = np.array([[1, 1, 1]], dtype=np.int64)
    got = sess.run(["sentence_embedding"], {"input_ids": ids, "attention_mask": mask})[0]
    assert got.shape == (1, 6)
