"""Tier-1 /classify 滚动延迟统计:定长环形缓冲 + 累计计数。

红线:record() 在热路径调用,必须廉价且绝不抛异常(非法值静默忽略);
锁保护读写(uvicorn 多 worker 内单进程线程安全即可)。仅统计,不影响打分。
"""
from __future__ import annotations

import threading
from collections import deque


class LatencyStats:
    def __init__(self, capacity: int = 512) -> None:
        self._buf: deque[float] = deque(maxlen=max(1, int(capacity)))
        self._count = 0
        self._lock = threading.Lock()

    def record(self, elapsed_ms: float) -> None:
        """记录一次**成功打分**耗时(毫秒)。

        语义澄清(SFIX-2b):record() 仅在 /classify 打分成功后被调用,累计计数
        因此只统计成功打分次数——空/空白输入短路、模型未加载 503、打分器异常 503
        等路径都不进 record,故不计入。非法/负值静默忽略,绝不抛(热路径守卫)。
        """
        try:
            v = float(elapsed_ms)
        except (TypeError, ValueError):
            return
        if v != v or v < 0:  # NaN 或负值:丢弃
            return
        with self._lock:
            self._buf.append(v)
            self._count += 1

    def snapshot(self) -> dict:
        with self._lock:
            data = sorted(self._buf)
            count = self._count
        return {
            # scored_count 是自文档字段名:只统计成功打分次数(record() 调用数),
            # 排除空输入短路与 503(模型未加载/打分器异常)等未打分请求(SFIX-2b)。
            "scored_count": count,
            # classify_count 为向后兼容别名,与 scored_count 恒同值;语义同上(不是收到的
            # /classify 请求总数,只是成功打分数)。历史消费者继续可用,勿单独漂移。
            "classify_count": count,
            "latency_p50_ms": self._pct(data, 50),
            "latency_p95_ms": self._pct(data, 95),
        }

    @staticmethod
    def _pct(sorted_vals: list[float], p: int) -> float:
        if not sorted_vals:
            return 0.0
        # 最近邻(nearest-rank)百分位:第 ceil(p/100 * n) 个(1-based)
        import math
        rank = max(1, math.ceil(p / 100.0 * len(sorted_vals)))
        return round(float(sorted_vals[rank - 1]), 2)
