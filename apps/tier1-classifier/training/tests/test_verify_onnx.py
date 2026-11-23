import numpy as np
import pytest

pytest.importorskip("sklearn")
pytest.importorskip("skl2onnx")
ort = pytest.importorskip("onnxruntime")

from training.head import train_head
from training.fuse_onnx import lr_to_onnx
from training.verify_onnx import verify_parity, ParityError, attack_proba


def _clf_and_data(dim=4):
    rng = np.random.default_rng(1)
    Xb = rng.normal(0, 0.1, size=(30, dim))
    Xa = rng.normal(0, 0.1, size=(30, dim)) + 2.5
    X = np.vstack([Xb, Xa]).astype(np.float32)
    y = ["benign"] * 30 + ["attack"] * 30
    return train_head(X, y), X


def test_attack_proba_matches_sklearn_column_1():
    clf, X = _clf_and_data()
    ref = clf.predict_proba(X)[:, 1]
    sess = ort.InferenceSession(lr_to_onnx(clf, input_dim=X.shape[1]).SerializeToString())
    got = attack_proba(sess, "sentence_embedding", X)
    np.testing.assert_allclose(got, ref, atol=1e-3)


def test_verify_parity_passes_for_matching_graph():
    clf, X = _clf_and_data()
    sess = ort.InferenceSession(lr_to_onnx(clf, input_dim=X.shape[1]).SerializeToString())
    # 直接以 LR 输入名校验（融合图的 token 输入版在 retrain e2e 覆盖）
    report = verify_parity(
        sklearn_attack_proba=clf.predict_proba(X)[:, 1],
        onnx_attack_proba=attack_proba(sess, "sentence_embedding", X),
        tol=1e-3,
    )
    assert report["passed"] is True
    assert report["max_abs_diff"] < 1e-3


def test_verify_parity_raises_on_mismatch():
    a = np.array([0.1, 0.9, 0.5])
    b = np.array([0.2, 0.9, 0.5])  # 首元素差 0.1 > 1e-3
    with pytest.raises(ParityError):
        verify_parity(sklearn_attack_proba=a, onnx_attack_proba=b, tol=1e-3)
