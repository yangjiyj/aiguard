"""融合 ONNX 对齐校验（红线：融合图输出 ≈ sklearn LR 概率，容差 1e-3）。

证明融合图与训练一致：对同一批样本，(融合 ONNX 攻击概率) ≈ (sklearn LR 攻击概率)。
不达容差 → ParityError 阻断出模型。

两个层级：
- attack_proba/verify_parity：LR-only 子图口径（在句向量上），单元测试用。
- verify_fused_parity：**完整融合图端到端**口径——text→tokenize(input_ids,attention_mask)
  →融合 ONNX→proba[:,1] 与 embedder 子图→sklearn LR predict_proba[:,1] 对齐。
  这条真实经过 merge_models 拼出的 bridge，接线错（io_map 桥断/接反）会被此门挡住。
"""
from __future__ import annotations

from typing import Callable, Dict, List, Sequence

import numpy as np


class ParityError(RuntimeError):
    pass


def attack_proba(session, input_name: str, X: np.ndarray) -> np.ndarray:
    """对句向量批跑 ONNX，返回攻击类(index 1)概率。

    取输出中 (n,2) 的概率张量第 1 列（id2label={0:benign,1:attack}）。
    """
    outs = session.run(None, {input_name: X.astype(np.float32)})
    proba = None
    for o in outs:
        arr = np.asarray(o)
        if arr.ndim == 2 and arr.shape[1] == 2:
            proba = arr
            break
    if proba is None:
        raise ParityError("ONNX 输出未找到 (n,2) 概率张量")
    return proba[:, 1].astype(np.float64)


def _proba_col1(outputs: Sequence[object]) -> np.ndarray:
    """从一次融合图 run 的输出里定位 (n,2) 概率张量，返回攻击类(列1)概率。

    与 attack_proba / model.py / scorers.py 同口径：按 ndim==2 且 shape[1]==2 定位，
    跳过 (n,) 的 label 输出，绝不 softmax（已是概率）。
    """
    for o in outputs:
        arr = np.asarray(o)
        if arr.ndim == 2 and arr.shape[1] == 2:
            return arr[:, 1].astype(np.float64)
    raise ParityError("融合 ONNX 输出未找到 (n,2) 概率张量")


def _run_fused(fused_session, enc: Dict[str, np.ndarray]) -> np.ndarray:
    """喂 token（input_ids/attention_mask，仅取融合图真实需要的输入名）跑融合图，取攻击概率。"""
    input_names = {i.name for i in fused_session.get_inputs()}
    feed = {k: v for k, v in enc.items() if k in input_names}
    return _proba_col1(fused_session.run(None, feed))


def _run_embedder(embedder_session, enc: Dict[str, np.ndarray], embedding_output: str) -> np.ndarray:
    """喂同一批 token 跑 embedder 子图，取 sentence_embedding（参照路径的编码步）。"""
    input_names = {i.name for i in embedder_session.get_inputs()}
    feed = {k: v for k, v in enc.items() if k in input_names}
    return np.asarray(
        embedder_session.run([embedding_output], feed)[0], dtype=np.float32
    )


def verify_fused_parity(
    *,
    fused_session,
    embedder_session,
    sklearn_clf,
    tokenizer: Callable[..., Dict[str, np.ndarray]],
    texts: Sequence[str],
    embedding_output: str = "sentence_embedding",
    tol: float = 1e-3,
) -> Dict[str, object]:
    """**完整融合图端到端** parity（红线：真实经过 merge 出的 bridge，接线错必被挡）。

    Path A（融合图）: texts → tokenizer → input_ids/attention_mask → 融合 ONNX → proba[:,1]
    Path B（参照）  : 同一批 token → embedder 子图 → sentence_embedding → sklearn LR predict_proba[:,1]

    两路一致（max_abs_diff <= tol）→ 融合图与训练一致且 bridge 接线正确；
    不一致 → 抛 ParityError，阻断出模型（merge_models io_map 桥断/接反在此暴露）。

    tokenizer 须可调用 tokenizer(list_of_texts) → {"input_ids", "attention_mask": np.ndarray}
    （生产用 transformers AutoTokenizer(return_tensors="np")，测试可注入确定性 mock）。
    """
    text_list: List[str] = list(texts)
    if not text_list:
        raise ParityError("verify_fused_parity 需要非空 texts（无样本无法证明端到端一致）")

    enc = tokenizer(text_list)
    if "input_ids" not in enc:
        raise ParityError("tokenizer 输出缺 input_ids（融合图需 token id 输入）")

    # Path A：完整融合图
    fused_p = _run_fused(fused_session, enc)
    # Path B：embedder 子图 → sklearn LR 攻击概率（列1）
    emb = _run_embedder(embedder_session, enc, embedding_output)
    ref_p = sklearn_clf.predict_proba(emb.astype(np.float32))[:, 1]

    report = verify_parity(sklearn_attack_proba=ref_p, onnx_attack_proba=fused_p, tol=tol)
    report["mode"] = "fused_end_to_end"
    return report


def verify_parity(*, sklearn_attack_proba: np.ndarray, onnx_attack_proba: np.ndarray,
                  tol: float = 1e-3) -> Dict[str, object]:
    a = np.asarray(sklearn_attack_proba, dtype=np.float64).ravel()
    b = np.asarray(onnx_attack_proba, dtype=np.float64).ravel()
    if a.shape != b.shape:
        raise ParityError(f"样本数不一致：sklearn={a.shape} onnx={b.shape}")
    max_abs_diff = float(np.max(np.abs(a - b))) if a.size else 0.0
    passed = max_abs_diff <= tol
    if not passed:
        raise ParityError(
            f"融合 ONNX 与 sklearn LR 概率不一致：max_abs_diff={max_abs_diff:.6f} > tol={tol}"
        )
    return {"passed": True, "max_abs_diff": max_abs_diff, "n": int(a.size), "tol": tol}
