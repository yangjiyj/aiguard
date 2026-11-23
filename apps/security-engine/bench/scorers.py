"""bench 打分适配层：统一 score_texts(texts) -> list[float]（攻击概率，失败=NaN）。

- LiveSidecarScorer：httpx 调 Tier-1 sidecar POST /classify（与 security-engine 同契约）。
- OnnxScorer：本地 onnx 直跑（懒导入 onnxruntime，venv 无依赖时只在运行期报错）。
"""
from __future__ import annotations

import math
import time
from typing import TYPE_CHECKING, List, Optional, Tuple

if TYPE_CHECKING:
    import httpx

from app.header_compat import INTERNAL_TOKEN_HEADER


def drop_failopen(y_true: List[int], scores: List[float]) -> Tuple[List[int], List[float], int]:
    """剔除 NaN（fail-open）样本，单列丢弃计数，避免污染召回/精度。"""
    yy, ss, dropped = [], [], 0
    for y, s in zip(y_true, scores):
        if isinstance(s, float) and math.isnan(s):
            dropped += 1
            continue
        yy.append(y)
        ss.append(s)
    return yy, ss, dropped


class LiveSidecarScorer:
    """直调运行中的 Tier-1 sidecar。契约：POST {url} 头 X-JJDGuard-Internal-Token
    体 {"text": str} → {"score": float, "label": str}。失败返回 NaN（fail-open）。"""

    def __init__(self, *, url: str, token: str, timeout: float = 5.0,
                 transport: Optional[httpx.BaseTransport] = None) -> None:
        try:
            import httpx
        except ModuleNotFoundError as exc:
            raise RuntimeError("LiveSidecarScorer requires httpx") from exc
        self._url = url
        self._token = token
        self._timeout = timeout
        self._client = httpx.Client(timeout=timeout, transport=transport)
        self.latencies_ms: List[float] = []

    def score_texts(self, texts: List[str]) -> List[float]:
        out: List[float] = []
        for t in texts:
            t0 = time.perf_counter()
            try:
                resp = self._client.post(
                    self._url,
                    headers={INTERNAL_TOKEN_HEADER: self._token},
                    json={"text": t},
                )
                self.latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                if resp.status_code != 200:
                    out.append(math.nan)
                    continue
                out.append(float(resp.json()["score"]))
            except Exception:  # noqa: BLE001 fail-open
                self.latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                out.append(math.nan)
        return out


class OnnxScorer:
    """本地 Prompt-Guard-2 86M ONNX 直跑。onnxruntime/transformers 懒导入：
    venv 无依赖时构造不炸，仅 score_texts 报清晰错误（bench 在装了依赖的机器上跑）。"""

    def __init__(self, *, model_path: str, tokenizer_path: Optional[str] = None,
                 num_threads: int = 1) -> None:
        self.model_path = model_path
        self.tokenizer_path = tokenizer_path or model_path
        self.num_threads = num_threads
        self._session = None
        self._tokenizer = None
        self.latencies_ms: List[float] = []

    def _ensure_loaded(self) -> None:
        if self._session is not None:
            return
        try:
            import onnxruntime as ort  # noqa: PLC0415 懒导入
            from transformers import AutoTokenizer  # noqa: PLC0415
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"OnnxScorer 需要 onnxruntime + transformers（当前环境缺失）：{exc}"
            ) from exc
        import os
        if not os.path.exists(self.model_path):
            raise RuntimeError(f"模型文件不存在：{self.model_path}")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = self.num_threads
        self._session = ort.InferenceSession(self.model_path, sess_options=opts)
        self._tokenizer = AutoTokenizer.from_pretrained(self.tokenizer_path)

    def score_texts(self, texts: List[str]) -> List[float]:
        self._ensure_loaded()
        out: List[float] = []
        for t in texts:
            t0 = time.perf_counter()
            enc = self._tokenizer(t, return_tensors="np", truncation=True, max_length=512)
            logits = self._session.run(None, {k: v for k, v in enc.items()})[0][0]
            # 二分类 softmax 取「攻击」类概率（Prompt-Guard-2：index 1 = 攻击/越狱）
            ex = [math.exp(float(x)) for x in logits]
            z = sum(ex)
            p_attack = ex[1] / z if len(ex) > 1 and z else 0.0
            self.latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            out.append(p_attack)
        return out


class FusedOnnxScorer:
    """自训「融合 ONNX」直跑（真实契约，以 tier1-classifier/training/verify_onnx.py 为准）：

    输入 = input_ids(int64) + attention_mask(int64)（token id，图内无 tokenizer，自带分词/池化在图内）；
    输出 = [label(int64,(n,)), probabilities(float,(n,2))]（skl2onnx zipmap=False）。
    攻击概率 = probabilities[:,1]（列1=attack，id2label={0:benign,1:attack}）——**已是概率，绝不再 softmax**。

    session/tokenizer 依赖注入：venv 仅装 onnxruntime（无 onnx 构图包）即可单测概率抽取；
    未注入则懒加载真模型 + 真 tokenizer（缺 onnxruntime/transformers/模型文件 → 仅 score_texts 报清晰错误）。
    tokenizer 默认从模型同目录加载（retrain 把 tokenizer 与 model.onnx 写在一起）。"""

    def __init__(self, *, model_path: str, session=None, tokenizer=None,
                 tokenizer_path: Optional[str] = None, num_threads: int = 1,
                 max_len: int = 256) -> None:
        self.model_path = model_path
        self.num_threads = num_threads
        self.max_len = max_len
        self._session = session
        self._tokenizer = tokenizer
        import os
        # tokenizer 默认取模型所在目录（融合模型与 tokenizer 同目录）
        self.tokenizer_path = tokenizer_path or os.path.dirname(model_path) or model_path
        self.latencies_ms: List[float] = []

    def _ensure_loaded(self) -> None:
        if self._session is not None and self._tokenizer is not None:
            return
        import os
        if self._session is None:
            try:
                import onnxruntime as ort  # noqa: PLC0415 懒导入
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(
                    f"FusedOnnxScorer 需要 onnxruntime（当前环境缺失）：{exc}"
                ) from exc
            if not os.path.exists(self.model_path):
                raise RuntimeError(f"融合模型文件不存在：{self.model_path}")
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = self.num_threads
            self._session = ort.InferenceSession(self.model_path, sess_options=opts)
        if self._tokenizer is None:
            try:
                from transformers import AutoTokenizer  # noqa: PLC0415 懒导入
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(
                    f"FusedOnnxScorer 需要 transformers 分词（当前环境缺失）：{exc}"
                ) from exc
            self._tokenizer = AutoTokenizer.from_pretrained(self.tokenizer_path)

    def _find_probabilities(self, outputs):
        """从融合图输出里定位 (n,2) float 概率张量（跳过 (n,) 的 label），与 verify_onnx.py 同口径。"""
        import numpy as np

        for o in outputs:
            arr = np.asarray(o)
            if arr.ndim == 2 and arr.shape[1] == 2:
                return arr
        raise RuntimeError("融合 ONNX 输出未找到 (n,2) 概率张量")

    def score_texts(self, texts: List[str]) -> List[float]:
        import numpy as np

        self._ensure_loaded()
        input_names = {i.name for i in self._session.get_inputs()}
        out: List[float] = []
        for t in texts:
            t0 = time.perf_counter()
            enc = self._tokenizer(
                [t], truncation=True, max_length=self.max_len, return_tensors="np"
            )
            feed = {k: v for k, v in enc.items() if k in input_names}
            outputs = self._session.run(None, feed)
            proba = self._find_probabilities(outputs)
            # 攻击概率 = 列 1（id2label={0:benign,1:attack}），已是概率，绝不 softmax
            p_attack = float(np.asarray(proba)[0][1])
            self.latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            out.append(p_attack)
        return out
