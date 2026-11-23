"""冻结多语 embedder 文本编码（D3：中英混；默认 intfloat/multilingual-e5-small=Apache-2.0）。

编码路径：transformers 加载冻结 embedder → last_hidden_state 做 attention-mask
加权 mean-pooling → L2 归一化 → (n,d) 句向量。embedder 全程不更新（仅前向）。
许可白名单经 training.license_gate 校验（T-5），本模块只负责编码。
"""
from __future__ import annotations

from typing import List

import numpy as np

DEFAULT_EMBEDDER = "intfloat/multilingual-e5-small"


def _mean_pool(last_hidden: np.ndarray, attention_mask: np.ndarray) -> np.ndarray:
    mask = attention_mask[..., None].astype(np.float32)
    summed = (last_hidden * mask).sum(axis=1)
    counts = np.clip(mask.sum(axis=1), 1e-9, None)
    return summed / counts


class TextEncoder:
    """transformers 冻结 embedder 编码器（v1 训练用；ONNX 导出在 retrain CLI）。"""

    def __init__(self, model_id: str = DEFAULT_EMBEDDER, max_len: int = 256) -> None:
        self.model_id = model_id
        self.max_len = max_len
        self._tok = None
        self._model = None

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        from transformers import AutoTokenizer, AutoModel  # 懒导入
        self._tok = AutoTokenizer.from_pretrained(self.model_id, local_files_only=True)
        self._model = AutoModel.from_pretrained(self.model_id, local_files_only=True)
        self._model.eval()

    def encode(self, texts: List[str]) -> np.ndarray:
        import torch  # 懒导入
        self._ensure_loaded()
        enc = self._tok(
            texts, padding=True, truncation=True,
            max_length=self.max_len, return_tensors="pt",
        )
        with torch.no_grad():
            out = self._model(**enc)
        last_hidden = out.last_hidden_state.numpy()
        mask = enc["attention_mask"].numpy()
        vecs = _mean_pool(last_hidden, mask)
        norms = np.clip(np.linalg.norm(vecs, axis=1, keepdims=True), 1e-9, None)
        return (vecs / norms).astype(np.float32)
