"""Tier-1 攻击概率打分器。

红线对齐：模型缺失/加载失败 → get_scorer() 返回 None，服务仍起（/health 报
model_loaded=False）；security-engine 侧把非 200/不可达视为 None=fail-open 跳过语义，
故本服务对"模型没就绪"返回 503，让调用方走既有 fail-open 路径，绝不假阳。
"""
from __future__ import annotations

import logging
from typing import Optional, Protocol, Tuple

logger = logging.getLogger(__name__)


class Scorer(Protocol):
    def score(self, text: str) -> Tuple[float, str]:
        """返回 (攻击概率[0..1], label)。"""
        ...


# 进程级单例（懒加载，B-2 用 onnxruntime 实现并赋值）。
_SCORER: Optional[Scorer] = None
_LOAD_ATTEMPTED = False


def set_scorer(scorer: Optional[Scorer]) -> None:
    """测试/装配注入打分器（单测注入 stub，main 启动注入真实 ModelScorer）。"""
    global _SCORER, _LOAD_ATTEMPTED
    _SCORER = scorer
    _LOAD_ATTEMPTED = True


def get_scorer() -> Optional[Scorer]:
    return _SCORER
