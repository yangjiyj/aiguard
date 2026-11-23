import numpy as np
import pytest

pytest.importorskip("sklearn")
pytest.importorskip("skl2onnx")
pytest.importorskip("onnx")
ort = pytest.importorskip("onnxruntime")

import onnx
from onnx import helper, TensorProto

from training.head import train_head
from training.fuse_onnx import lr_to_onnx, fuse_embedder_and_head


def _toy_clf(dim=4):
    rng = np.random.default_rng(0)
    Xb = rng.normal(0, 0.1, size=(20, dim))
    Xa = rng.normal(0, 0.1, size=(20, dim)) + 3.0
    X = np.vstack([Xb, Xa]).astype(np.float32)
    y = ["benign"] * 20 + ["attack"] * 20
    return train_head(X, y), X


def test_lr_to_onnx_outputs_two_class_proba():
    clf, X = _toy_clf(4)
    model = lr_to_onnx(clf, input_dim=4, input_name="sentence_embedding")
    sess = ort.InferenceSession(model.SerializeToString())
    out = sess.run(None, {"sentence_embedding": X})
    # 找概率输出（n,2）
    proba = next(o for o in out if getattr(o, "ndim", 0) == 2 and o.shape[1] == 2)
    assert proba.shape == (40, 2)
    np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-4)


def _toy_embedder_onnx(dim=4):
    """极小'embedder'：input_ids(int64,[b,s]) → 对每行求均值广播成 [b,dim] sentence_embedding。"""
    ids = helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["b", "s"])
    mask = helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["b", "s"])
    emb = helper.make_tensor_value_info("sentence_embedding", TensorProto.FLOAT, ["b", dim])
    cast = helper.make_node("Cast", ["input_ids"], ["idsf"], to=TensorProto.FLOAT)
    rmean = helper.make_node("ReduceMean", ["idsf"], ["m"], axes=[1], keepdims=1)  # [b,1]
    ones = helper.make_node(
        "Constant", [], ["ones"],
        value=helper.make_tensor("ones", TensorProto.FLOAT, [1, dim], [1.0] * dim),
    )
    mul = helper.make_node("Mul", ["m", "ones"], ["sentence_embedding"])
    graph = helper.make_graph([cast, rmean, ones, mul], "toy_emb", [ids, mask], [emb])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    onnx.checker.check_model(model)
    return model


def test_fuse_merges_into_single_token_input_graph():
    clf, _ = _toy_clf(4)
    emb = _toy_embedder_onnx(4)
    lr = lr_to_onnx(clf, input_dim=4, input_name="sentence_embedding")
    fused = fuse_embedder_and_head(emb, lr, bridge_name="sentence_embedding")
    sess = ort.InferenceSession(fused.SerializeToString())
    in_names = {i.name for i in sess.get_inputs()}
    assert "input_ids" in in_names and "attention_mask" in in_names
    out = sess.run(None, {
        "input_ids": np.array([[1, 2, 3]], dtype=np.int64),
        "attention_mask": np.array([[1, 1, 1]], dtype=np.int64),
    })
    proba = next(o for o in out if getattr(o, "ndim", 0) == 2 and o.shape[1] == 2)
    assert proba.shape == (1, 2)


def _toy_embedder_onnx_opset(dim=4, opset=18):
    """极小'embedder'，ai.onnx opset 可指定：input_ids(int64,[b,s]) → MatMul 常量 → [b,dim]。

    用 MatMul（跨 opset 稳定）而非 ReduceMean（opset 18 把 axes 从属性改为输入，
    toy 图用属性形式在 18 下非法），以构造一个在 opset 18 下合法的占位 embedder。
    """
    ids = helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["b", 3])
    mask = helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["b", 3])
    emb = helper.make_tensor_value_info("sentence_embedding", TensorProto.FLOAT, ["b", dim])
    cast = helper.make_node("Cast", ["input_ids"], ["idsf"], to=TensorProto.FLOAT)  # [b,3]
    w = helper.make_node(
        "Constant", [], ["W"],
        value=helper.make_tensor("W", TensorProto.FLOAT, [3, dim], [0.01] * (3 * dim)))
    mm = helper.make_node("MatMul", ["idsf", "W"], ["sentence_embedding"])  # [b,3]x[3,dim]
    graph = helper.make_graph([cast, w, mm], "toy_emb", [ids, mask], [emb])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", opset)])
    onnx.checker.check_model(model)
    return model


def test_fuse_aligns_mismatched_ai_onnx_opset():
    """回归：optimum 导出的 embedder 用 ai.onnx opset 18，skl2onnx 的 LR 用 opset 17
    （还带 ai.onnx.ml 域）。merge_models 要求同 domain opset 一致，直接融合会报
    "different operator set ids"。fuse_embedder_and_head 须在 merge 前对齐 ai.onnx
    opset，融合成功。（旧 mock 测试两边恰好同为 17，没暴露此 bug。）"""
    clf, _ = _toy_clf(4)
    emb18 = _toy_embedder_onnx_opset(4, opset=18)  # 模拟 optimum：ai.onnx=18
    lr17 = lr_to_onnx(clf, input_dim=4, input_name="sentence_embedding")  # skl2onnx：ai.onnx=17

    emb_ai = max(o.version for o in emb18.opset_import if (o.domain or "") == "")
    lr_ai = max(o.version for o in lr17.opset_import if (o.domain or "") == "")
    assert emb_ai != lr_ai, "前置条件：两子图 ai.onnx opset 须不一致才测得到对齐"

    fused = fuse_embedder_and_head(emb18, lr17, bridge_name="sentence_embedding")

    # 融合图 ai.onnx opset 统一，且能真跑出 (n,2) 概率。
    fused_ai = {o.version for o in fused.opset_import if (o.domain or "") == ""}
    assert len(fused_ai) == 1, f"融合图 ai.onnx opset 应统一，得到 {fused_ai}"
    sess = ort.InferenceSession(fused.SerializeToString())
    out = sess.run(None, {
        "input_ids": np.array([[1, 2, 3], [4, 5, 6]], dtype=np.int64),
        "attention_mask": np.ones((2, 3), dtype=np.int64),
    })
    proba = next(o for o in out if getattr(o, "ndim", 0) == 2 and o.shape[1] == 2)
    assert proba.shape == (2, 2)
    np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-4)
