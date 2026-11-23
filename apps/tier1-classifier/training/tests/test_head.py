import numpy as np
import pytest

pytest.importorskip("sklearn")

from training.head import train_head, LABEL_ORDER


def _toy_xy():
    # benign 聚在原点附近，attack 沿 +x 偏移 → 线性可分
    rng = np.random.default_rng(0)
    Xb = rng.normal(0, 0.1, size=(20, 4))
    Xa = rng.normal(0, 0.1, size=(20, 4)) + np.array([3.0, 0, 0, 0])
    X = np.vstack([Xb, Xa]).astype(np.float32)
    y = ["benign"] * 20 + ["attack"] * 20
    return X, y


def test_label_order_is_benign_then_attack():
    assert LABEL_ORDER == ["benign", "attack"]


def test_train_head_returns_lr_with_fixed_class_order():
    X, y = _toy_xy()
    clf = train_head(X, y)
    # sklearn classes_ 必须按 LABEL_ORDER（0=benign,1=attack），保证 id2label 对齐
    assert list(clf.classes_) == [0, 1]
    assert clf.coef_.shape[1] == X.shape[1]


def test_train_head_separates_linearly_separable_data():
    X, y = _toy_xy()
    clf = train_head(X, y)
    proba = clf.predict_proba(X)  # 列序对应 classes_=[0,1]=[benign,attack]
    attack_p = proba[:, 1]
    assert attack_p[:20].mean() < 0.2   # benign 攻击概率低
    assert attack_p[20:].mean() > 0.8   # attack 攻击概率高


def test_train_head_rejects_single_class():
    X = np.zeros((4, 4), dtype=np.float32)
    with pytest.raises(ValueError):
        train_head(X, ["benign"] * 4)


def test_default_C_is_loosened_for_unit_norm_embeddings():
    """回归（RFIX 校准修复）：默认正则强度 C 须显著大于 sklearn 默认 1.0，锁死校准决策。

    根因（真 e5 build 实测）：句向量经 L2 归一是单位向量，类间余弦间隔虽足以线性可分
    （C=1.0 训练集准确率仍 ~0.99），但 C=1.0 的 L2 正则把攻击/良性概率压进 [0.42,0.57] 窄带；
    bench 门用固定阈值网格 (low∈0.1..0.3, high∈0.7..0.9)，压缩后全样本落灰区
    → 良性误升级率=1.0、Tier-1 直出召回=0 → 门必 FAIL。放松到 C=10 后置信度正常展开、
    逃出灰区（真 e5 上 Tier-1 直出召回 0.79 / 良性误升级 0.15 / 灰区率 0.18 → 门 PASS），
    又不到 C≥100 的饱和（那会把训练集背成 0/1、掩盖泛化差距）。

    校准强度与真实 e5 几何强相关，合成小样本难忠实复现（改用直接锁默认值这一确定性守卫）。
    真实端到端校准由 build-baseline-model.sh 的 bench 门权威把关（不过线不出模型）。"""
    import inspect

    sig = inspect.signature(train_head)
    default_C = sig.parameters["C"].default
    assert default_C >= 10.0, (
        f"默认 C={default_C} 过小：L2 归一句向量上会把概率压进灰区 → bench 门 FAIL；"
        f"须放松正则（≥10）让置信度展开逃出灰区"
    )
