"""自训融合 ONNX 推理打分器（CPU/CUDA）。

懒加载：依赖（onnxruntime/transformers/numpy）或模型目录缺失 → load_model_scorer()
返回 None（服务报 model_loaded=False，/classify 返 503，调用方 fail-open）。绝不假阳。
模型目录由 env TIER1_MODEL_DIR 指定（镜像内 /models/prompt-guard-2 或灌命名卷）。

融合图契约（以 training/verify_onnx.py 为准）：
  输入 = input_ids(int64) + attention_mask(int64)（token id，图内无 tokenizer）；
  输出 = [label(int64,(n,)), probabilities(float,(n,2))]（skl2onnx zipmap=False）。
  攻击概率 = probabilities[:,1]（列1=attack，id2label={0:benign,1:attack}）——**已是概率，绝不再 softmax**。
输出：取概率张量攻击类（列1）为 score；label 取 argmax 的标签名。
"""
from __future__ import annotations

import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Prompt-Guard-2 标签 / 自训模型标签 → 契约 label 的映射（id2label 缺失时的兜底；以模型 config 为准）。
# 自训融合 ONNX id2label={0:benign,1:attack} → 需含 "attack"。
_ATTACK_LABELS = {"attack", "jailbreak", "injection", "malicious", "label_1", "1"}

# ONNX intra-op 线程数默认（多核客户机可经 env TIER1_THREADS 调高提吞吐）。
_DEFAULT_THREADS = 2
_CPU_PROVIDER = "CPUExecutionProvider"
_CUDA_PROVIDER = "CUDAExecutionProvider"


def _resolve_threads() -> int:
    """Resolve ONNX intra_op_num_threads, defaulting to the P1 resource tier.

    Precedence: explicit TIER1_THREADS -> ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS
    (written by engine-resource-autotune.sh from the CPU tier) -> default 2.
    A blank value means "not configured" (compose passes ${VAR:-}); invalid
    values are logged and skipped; values <1 are clamped to 1 because
    onnxruntime requires >=1. Never raises: the load path is fail-safe.
    """
    for name in ("TIER1_THREADS", "ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS"):
        raw = os.getenv(name)
        if raw is None or not str(raw).strip():
            continue
        try:
            n = int(str(raw).strip())
        except (TypeError, ValueError):
            logger.warning("%s=%r 非整数 → 跳过该来源", name, raw)
            continue
        return n if n >= 1 else 1
    return _DEFAULT_THREADS


def _select_execution_providers(available_providers) -> tuple[str, list[str]]:
    """Resolve the requested ONNX backend without silently changing explicit modes."""
    available = set(available_providers)
    requested = os.getenv("TIER1_EXECUTION_PROVIDER", "cpu").strip().lower()
    if requested not in {"auto", "cpu", "cuda"}:
        raise ValueError("TIER1_EXECUTION_PROVIDER must be auto, cpu or cuda")
    if requested == "cuda":
        if _CUDA_PROVIDER not in available:
            raise RuntimeError("CUDAExecutionProvider is unavailable")
        providers = [_CUDA_PROVIDER]
        if _CPU_PROVIDER in available:
            providers.append(_CPU_PROVIDER)
        return "cuda", providers
    if requested == "auto" and _CUDA_PROVIDER in available:
        providers = [_CUDA_PROVIDER]
        if _CPU_PROVIDER in available:
            providers.append(_CPU_PROVIDER)
        return "cuda", providers
    if _CPU_PROVIDER not in available:
        raise RuntimeError("CPUExecutionProvider is unavailable")
    return "cpu", [_CPU_PROVIDER]


class ModelScorer:
    def __init__(self, session, tokenizer, id2label: dict, max_len: int = 512,
                 configured_provider: str = "cpu", threads: int = _DEFAULT_THREADS) -> None:
        self._session = session
        self._tokenizer = tokenizer
        self._id2label = id2label
        self._max_len = max_len
        self._configured_provider = configured_provider
        self._threads = threads
        try:
            self._max_token_windows = max(1, min(32, int(os.getenv("TIER1_MAX_TOKEN_WINDOWS", "16"))))
        except ValueError:
            self._max_token_windows = 16

    def _batch_windows(self) -> int:
        """Max sliding windows per session.run (memory knob).

        Default is the whole window budget, so a long text costs exactly one
        graph execution -- which is what it always cost; this knob only caps how
        many windows one run takes, to bound peak memory.
        """
        raw = os.getenv("TIER1_BATCH_WINDOWS")
        if raw is None or not str(raw).strip():
            return self._max_token_windows
        try:
            value = int(str(raw).strip())
        except (TypeError, ValueError):
            logger.warning("TIER1_BATCH_WINDOWS=%r 非整数 → 回落 %d",
                           raw, self._max_token_windows)
            return self._max_token_windows
        return max(1, min(self._max_token_windows, value))

    def runtime_info(self) -> dict:
        providers = list(self._session.get_providers())
        active = providers[0] if providers else "unknown"
        return {
            "configured_provider": self._configured_provider,
            "execution_provider": "cuda" if active == _CUDA_PROVIDER else "cpu" if active == _CPU_PROVIDER else "unknown",
            "onnx_provider": active,
            "threads": self._threads,
            "batch_windows": self._batch_windows(),
        }

    def score(self, text: str) -> Tuple[float, str]:
        import numpy as np

        if len(text) > 4096:
            raise ValueError("Tier-1 coverage input budget exceeded")
        enc = self._tokenizer(
            text,
            truncation=True,
            max_length=self._max_len,
            return_tensors="np",
            return_overflowing_tokens=True,
            stride=min(64, max(1, self._max_len // 4)),
            padding=True,
        )
        if len(enc["input_ids"]) > self._max_token_windows:
            raise ValueError("Tier-1 coverage token window budget exceeded")
        # Fused graph inputs = input_ids + attention_mask (int64 token ids; no tokenizer in the graph).
        input_names = {n.name for n in self._session.get_inputs()}
        inputs = {k: v for k, v in enc.items() if k in input_names}
        # All windows of one text go through a single session.run (the ONNX dynamic
        # batch axis). That was already the behaviour before TIER1_BATCH_WINDOWS
        # existed; the knob only caps how many windows one run takes, to bound peak
        # memory. It defaults to the whole window budget, so nothing changes by
        # default and it is not a throughput feature.
        rows = len(inputs["input_ids"])
        batch = self._batch_windows()
        rows_out = []
        for start in range(0, rows, batch):
            chunk = {k: v[start:start + batch] for k, v in inputs.items()}
            # Fused outputs = [label int64 (n,), probabilities float (n,2)] with
            # skl2onnx zipmap=False. Grab the (n,2) probability tensor by shape,
            # same contract as training/verify_onnx.py: it is already a
            # probability, so it must never be softmaxed again.
            rows_out.extend(np.asarray(
                self._find_probabilities(self._session.run(None, chunk))))
        probabilities = np.asarray(rows_out)
        if probabilities.shape[0] != rows or not np.isfinite(probabilities).all():
            raise ValueError("Tier-1 coverage output rows invalid")
        attack_columns = [idx for idx in range(probabilities.shape[1])
                          if str(self._id2label.get(idx, idx)).lower() in _ATTACK_LABELS]
        if not attack_columns:
            raise ValueError("Tier-1 attack label missing")
        # Preserve the riskiest token window, including middle and tail content.
        scores = probabilities[:, attack_columns].max(axis=1)
        best_window = int(np.argmax(scores))
        best_idx = int(np.argmax(probabilities[best_window]))
        return float(scores[best_window]), str(self._id2label.get(best_idx, best_idx))

    def _find_probabilities(self, outputs):
        """从融合图输出里定位 (n,2) float 概率张量。

        真实签名有两个输出（label int64 (n,) + probabilities float (n,2)）。
        按 ndim==2 且 shape[1]==2 定位概率张量（与 training/verify_onnx.py 同口径），
        跳过 (n,) 的 label 输出，避免把 label 当 logits 误 softmax。
        """
        import numpy as np

        for o in outputs:
            arr = np.asarray(o)
            if arr.ndim == 2 and arr.shape[1] == 2:
                return arr
        # 兜底：单输出且是 (n,2) 的场景已被上面命中；到这里说明签名异常 → 抛错，
        # 由 main.py /classify 兜成 503（fail-open），绝不假阳/假阴静默。
        raise ValueError("融合 ONNX 输出未找到 (n,2) 概率张量")


def load_model_scorer() -> Optional[ModelScorer]:
    model_dir = os.getenv("TIER1_MODEL_DIR", "/models/prompt-guard-2")
    onnx_path = os.path.join(model_dir, "model.onnx")
    if not os.path.isdir(model_dir) or not os.path.isfile(onnx_path):
        logger.warning("Tier-1 模型目录/ONNX 缺失（%s）→ 打分器禁用，服务 fail-open", model_dir)
        return None
    try:
        import json
        import onnxruntime as ort
        from transformers import AutoTokenizer

        threads = _resolve_threads()
        so = ort.SessionOptions()
        so.intra_op_num_threads = threads
        so.inter_op_num_threads = 1
        configured_provider, providers = _select_execution_providers(ort.get_available_providers())
        session = ort.InferenceSession(onnx_path, sess_options=so, providers=providers)
        tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
        # 自训模型的 config.json 是极简 config（只有 id2label/label2id，无 model_type），
        # 直接读；不用 AutoConfig（它要求 model_type，对自训模型报 Unrecognized model）。
        with open(os.path.join(model_dir, "config.json"), encoding="utf-8") as _f:
            _cfg = json.load(_f)
        id2label = {int(k): v for k, v in (_cfg.get("id2label") or {}).items()}
        scorer = ModelScorer(
            session, tokenizer, id2label,
            configured_provider=configured_provider, threads=threads,
        )
        runtime = scorer.runtime_info()
        logger.info(
            "Tier-1 模型加载成功：%s（provider=%s, threads=%d, labels=%s）",
            model_dir, runtime["onnx_provider"], threads, id2label,
        )
        return scorer
    except Exception:  # noqa: BLE001 加载任何环节失败 → 禁用打分器，绝不让服务崩
        logger.warning("Tier-1 模型加载失败 → 打分器禁用，服务 fail-open", exc_info=True)
        return None
