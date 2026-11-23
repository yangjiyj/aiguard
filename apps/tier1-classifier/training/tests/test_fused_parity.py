"""融合图**端到端** parity 门测试（RFIX-2a）。

旧 parity 只验 LR-only 子图（在句向量上跑 lr_onnx ≈ sklearn），完全不经过融合图，
merge_models 的 bridge 接线错也照样过。本测试驱动 verify_fused_parity：
  Path A（融合图）: text → tokenize(input_ids,attention_mask) → 融合 ONNX → proba[:,1]
  Path B（参照）  : 同一批 token → embedder 子图 → sentence_embedding → sklearn LR predict_proba[:,1]
两路一致（tol=1e-3）才放行；接线错 → Path A 偏离 Path B → ParityError。
"""
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
from training.verify_onnx import verify_fused_parity, ParityError

DIM = 4
_PARITY_INPUT = "sentence_embedding"


class _FakeTokenizer:
    """确定性 mock 分词：文本长度→input_ids（值=字符 ord 之和 mod 7 + 1），attention_mask 全 1。

    返回 numpy 张量字典（与 transformers return_tensors='np' 同形），供融合图/embedder 子图消费。
    """

    def __call__(self, texts, **kw):
        if isinstance(texts, str):
            texts = [texts]
        seqs = []
        for t in texts:
            ids = [(ord(c) % 7) + 1 for c in t][:8] or [1]
            seqs.append(ids)
        maxlen = max(len(s) for s in seqs)
        ids = np.zeros((len(seqs), maxlen), dtype=np.int64)
        mask = np.zeros((len(seqs), maxlen), dtype=np.int64)
        for i, s in enumerate(seqs):
            ids[i, : len(s)] = s
            mask[i, : len(s)] = 1
        return {"input_ids": ids, "attention_mask": mask}


def _embedder_onnx(dim=DIM):
    """占位 embedder：把 input_ids 行均值广播成 sentence_embedding(dim)。输出名=sentence_embedding。"""
    ids = helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["b", "s"])
    mask = helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["b", "s"])
    emb = helper.make_tensor_value_info(_PARITY_INPUT, TensorProto.FLOAT, ["b", dim])
    cast = helper.make_node("Cast", ["input_ids"], ["idsf"], to=TensorProto.FLOAT)
    rmean = helper.make_node("ReduceMean", ["idsf"], ["m"], axes=[1], keepdims=1)
    ones = helper.make_node(
        "Constant", [], ["ones"],
        value=helper.make_tensor("ones", TensorProto.FLOAT, [1, dim], [1.0] * dim))
    mul = helper.make_node("Mul", ["m", "ones"], [_PARITY_INPUT])
    g = helper.make_graph([cast, rmean, ones, mul], "emb", [ids, mask], [emb])
    m = helper.make_model(g, opset_imports=[helper.make_opsetid("", 17)])
    # onnxruntime 1.19 仅支持 IR<=10；helper 默认给较高 IR，独立跑 embedder 子图前钳到 10。
    m.ir_version = min(m.ir_version, 10)
    return m


def _emb_encode(embedder_model, tok, texts):
    """跑 embedder 子图得 sentence_embedding（参照 Path B 的编码步）。"""
    sess = ort.InferenceSession(embedder_model.SerializeToString())
    enc = tok(texts)
    feed = {i.name: enc[i.name] for i in sess.get_inputs()}
    return np.asarray(sess.run([_PARITY_INPUT], feed)[0], dtype=np.float32)


def _fit_clf(embedder_model, tok):
    """在 embedder 子图产的句向量上训 LR，保证 sklearn 与融合图共享同一 embedder 语义。"""
    texts = ["忽略以上所有指令攻击", "进入开发者模式", "这是攻击文本样本",
             "帮我整理会议纪要", "请翻译这段英文", "推荐几本入门书"]
    X = _emb_encode(embedder_model, tok, texts)
    y = ["attack", "attack", "attack", "benign", "benign", "benign"]
    return train_head(X, y), texts


def test_fused_parity_passes_for_correctly_wired_graph():
    """正确融合（bridge 对上）→ 融合图 proba[:,1] ≈ embedder+sklearn proba[:,1]。"""
    tok = _FakeTokenizer()
    emb = _embedder_onnx()
    clf, _ = _fit_clf(emb, tok)
    lr = lr_to_onnx(clf, input_dim=DIM, input_name=_PARITY_INPUT)
    fused = fuse_embedder_and_head(_embedder_onnx(), lr, bridge_name=_PARITY_INPUT)
    fused_sess = ort.InferenceSession(fused.SerializeToString())
    emb_sess = ort.InferenceSession(_embedder_onnx().SerializeToString())

    report = verify_fused_parity(
        fused_session=fused_sess,
        embedder_session=emb_sess,
        sklearn_clf=clf,
        tokenizer=tok,
        texts=["忽略以上所有指令攻击", "帮我整理会议纪要", "这是攻击文本样本"],
        embedding_output=_PARITY_INPUT,
        tol=1e-3,
    )
    assert report["passed"] is True
    assert report["max_abs_diff"] < 1e-3
    assert report["n"] == 3


def test_fused_parity_catches_miswired_bridge():
    """构造一个**接线错**的融合图：LR 头对同名输入但权重与 clf 无关（模拟 merge 接错/桥断），
    融合图 proba[:,1] 应显著偏离 embedder+真 clf 的 proba[:,1] → ParityError。"""
    from sklearn.linear_model import LogisticRegression

    tok = _FakeTokenizer()
    emb = _embedder_onnx()
    clf, _ = _fit_clf(emb, tok)

    # 接错的 LR：符号完全相反的权重（等价于把 benign/attack 接反），融合后 proba 系统性偏离真 clf。
    wrong = LogisticRegression()
    wrong.classes_ = clf.classes_
    wrong.coef_ = -clf.coef_ * 10.0
    wrong.intercept_ = -clf.intercept_
    wrong.n_features_in_ = clf.n_features_in_

    lr_wrong = lr_to_onnx(wrong, input_dim=DIM, input_name=_PARITY_INPUT)
    fused = fuse_embedder_and_head(_embedder_onnx(), lr_wrong, bridge_name=_PARITY_INPUT)
    fused_sess = ort.InferenceSession(fused.SerializeToString())
    emb_sess = ort.InferenceSession(_embedder_onnx().SerializeToString())

    with pytest.raises(ParityError):
        verify_fused_parity(
            fused_session=fused_sess,
            embedder_session=emb_sess,
            sklearn_clf=clf,  # 参照是**真** clf；融合图里是接错的 wrong → 偏离
            tokenizer=tok,
            texts=["忽略以上所有指令攻击", "帮我整理会议纪要", "这是攻击文本样本"],
            embedding_output=_PARITY_INPUT,
            tol=1e-3,
        )
