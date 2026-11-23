"""正则预算按本线程 CPU 时间记账的公共工具。

security-engine 单进程多线程共享 GIL，等 GIL 的时间不应消耗正则预算。
注意：第三方 regex 库的 timeout 既不是墙钟也不是本线程 CPU，而是 libc clock()，
即**整进程 CPU 时间**——同进程其它线程并行消耗的 CPU（OCR、哈希、其它请求的扫描）
都会计入，多核机器上并行线程越多，这个 timeout 走得越快。因此：首次调用 timeout
仍等于 CPU 预算（空闲时行为与原先一致）；超时后若本线程实际 CPU 消耗远低于预算
（主要在等锁或被其它线程的 CPU 计入），用剩余 CPU 预算重试一次，重试 timeout 按
本次实测的「进程 CPU / 本线程 CPU」倍率换算（不低于 SLACK），且不超过 WALL_MAX。
真慢（本线程 CPU 达到预算的 SLOW_CPU_RATIO）不重试，照常掐断。
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# CPU 消耗达到预算该比例视为"真慢"，不再重试。
SLOW_CPU_RATIO = 0.8
# 计算进程/线程 CPU 倍率时本线程 CPU 的下限，避免本线程几乎没跑时除零。
_MIN_THREAD_CPU_SAMPLE = 1e-4


def env_float(name: str, default: float, lower: float, upper: float) -> float:
    """读取浮点环境变量；缺省/非法/越界回落默认值并告警。"""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("invalid %s=%r, fallback to default %s", name, raw, default)
        return default
    if value != value or not (lower <= value <= upper):
        logger.warning(
            "%s=%r out of range [%s, %s], fallback to default %s",
            name, raw, lower, upper, default,
        )
        return default
    return value


def wall_slack() -> float:
    return env_float("SECURITY_REGEX_WALL_SLACK", 10.0, 1.0, 100.0)


def wall_max_seconds() -> float:
    return env_float("SECURITY_REGEX_WALL_MAX_SECONDS", 2.0, 0.01, 30.0)


@dataclass
class AttemptStats:
    cpu_seconds: float = 0.0
    wall_seconds: float = 0.0
    retried: bool = False


def run_with_cpu_budget(
    fn: Callable[[float, float], T],
    cpu_budget: float,
    stats: AttemptStats,
    allow_retry: bool = True,
) -> T:
    """执行 fn(cpu_budget, wall_timeout)；TimeoutError 时按本线程 CPU 消耗决定是否重试一次。

    首次 wall_timeout == cpu_budget（空闲时与旧行为一致）。超时后若 CPU 消耗
    < 预算的 80%，以剩余 CPU 预算重试，wall_timeout = min(剩余 x SLACK, WALL_MAX)。
    fn 必须可重复执行（无外部副作用），且在 CPU 预算耗尽时自行抛 TimeoutError。
    stats 记录整个过程的 CPU/墙钟耗时，成功或失败都会更新。
    """
    cpu0 = time.thread_time()
    proc0 = time.process_time()
    wall0 = time.monotonic()
    try:
        try:
            return fn(cpu_budget, cpu_budget)
        except TimeoutError:
            used = time.thread_time() - cpu0  # 只取一次，两个判断共用同一时刻
            proc_used = time.process_time() - proc0
            remaining = cpu_budget - used
            slow = used >= SLOW_CPU_RATIO * cpu_budget
            if not allow_retry or cpu_budget <= 0 or slow or remaining <= 0:
                raise
            stats.retried = True
            # regex 的 timeout 按整进程 CPU 计；把剩余的本线程预算换算成进程 CPU 口径，
            # 让本线程在争用持续时仍能拿到约 remaining 的 CPU。WALL_MAX 仍是硬顶。
            contention = proc_used / max(used, _MIN_THREAD_CPU_SAMPLE)
            retry_wall = min(remaining * max(wall_slack(), contention), wall_max_seconds())
        return fn(remaining, retry_wall)
    finally:
        stats.cpu_seconds = time.thread_time() - cpu0
        stats.wall_seconds = time.monotonic() - wall0
