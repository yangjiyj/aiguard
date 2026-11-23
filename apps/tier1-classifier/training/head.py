"""LogisticRegression 分类头训练（D5：秒级可重训，契合飞轮）。

固定 LABEL_ORDER=[benign,attack] → 整数标签 0/1 → 融合 ONNX id2label={0:benign,1:attack}。
输入 X=embedder 编码后的句向量(n,d)，y=字符串标签列表。
"""
from __future__ import annotations

from typing import List

import numpy as np
from sklearn.linear_model import LogisticRegression

LABEL_ORDER = ["benign", "attack"]
_LABEL_TO_INT = {name: i for i, name in enumerate(LABEL_ORDER)}


def train_head(X: np.ndarray, y: List[str], *, C: float = 10.0, max_iter: int = 1000) -> LogisticRegression:
    # 默认 C=10（非 sklearn 默认 1.0）：句向量经 L2 归一后是单位向量，类间余弦间隔虽足以
    # 线性可分，但 C=1.0 的 L2 正则会把概率压缩进 [0.4,0.6] 窄带——bench 门用固定阈值网格
    # (low∈[0.1,0.3], high∈[0.7,0.9])，压缩后全样本落灰区 → 良性误升级率=1.0、Tier-1 直出召回=0
    # → 门必 FAIL（尽管 0.5 阈处已近完美分离）。适度放松正则(C=10)让置信度在单位向量上正常展开、
    # 逃出灰区，同时不到 C≥100 的饱和(那会把训练集背成 0/1，掩盖泛化差距)。这是校准修复，非凑门。
    if X.ndim != 2 or X.shape[0] == 0:
        raise ValueError(f"X 必须是非空 2D 数组，得到 shape={getattr(X, 'shape', None)}")
    y_int = np.array([_LABEL_TO_INT[v] for v in y], dtype=np.int64)
    if len(set(y_int.tolist())) < 2:
        raise ValueError("训练数据须同时含 benign 与 attack 两类")
    clf = LogisticRegression(C=C, max_iter=max_iter)
    clf.fit(X.astype(np.float32), y_int)
    return clf
