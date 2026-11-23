"""embedder 许可白名单闸（spec §5E / §3 红线）。

只允许 MIT/Apache/BSD 系开源许可——零 gated、零 Llama 许可传导到客户。
非白名单或 license 字段缺失（不可证明合规）→ 抛 LicenseNotAllowedError，
retrain 在编码前调用 assert_model_license_allowed 阻断训练。

纯 stdlib，零 HF 依赖：可在任意 venv 单测（与 sidecar 运行时/训练依赖解耦）。

兼容说明：本模块同时提供 T-5 旧契约与 B-1 新契约，两者共存不破级联——
- 新契约（B-1）：assert_license_allowed(raw_license, *, model_id=...)、
  license_from_hf_config、assert_model_license_allowed、异常 LicenseNotAllowedError。
- 旧契约（T-5，retrain 依赖）：assert_license_allowed(model_id, license_str) 双位置参、
  normalize_license（含常见别名归一）、异常 LicenseError。
  LicenseNotAllowedError 即 LicenseError（同一异常，别名），因此 `except LicenseError`
  仍能捕获新契约抛出的错误，retrain/其测试无需改动。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# 许可白名单（契约固定；新增许可须显式扩此集合，杜绝默认放行）。
ALLOWED_LICENSES = {
    "apache-2.0",
    "mit",
    "bsd-3-clause",
    "bsd-2-clause",
}

# 常见别名 → 规范化 SPDX 风格 key（T-5 契约，retrain 侧沿用）。
_ALIASES = {
    "apache 2.0": "apache-2.0",
    "apache2.0": "apache-2.0",
    "apache-2": "apache-2.0",
    "bsd 3-clause": "bsd-3-clause",
    "bsd-3": "bsd-3-clause",
    "bsd 2-clause": "bsd-2-clause",
    "bsd-2": "bsd-2-clause",
}


class LicenseError(RuntimeError):
    """embedder 许可不在白名单（或缺失）→ 训练阻断。"""


# B-1 契约异常名：与 LicenseError 是同一异常（别名），保证
# `except LicenseError`（retrain/test_retrain）也能捕获 B-1 路径抛出的错误。
LicenseNotAllowedError = LicenseError


def normalize_license(license_str: Optional[str]) -> str:
    """归一化 license 字符串：小写 + 去首尾空白 + 常见别名归一。
    None/非字符串 → 空串（=不可证明合规）。"""
    if not isinstance(license_str, str):
        return ""
    key = license_str.strip().lower()
    return _ALIASES.get(key, key)


def license_from_hf_config(config: Dict[str, Any]) -> Optional[str]:
    """从 HF config/model-info dict 抽 license：优先顶层 license，
    退 cardData.license；都无则 None（=不可证明合规）。"""
    top = config.get("license")
    if top:
        return str(top)
    card = config.get("cardData")
    if isinstance(card, dict) and card.get("license"):
        return str(card["license"])
    return None


def assert_license_allowed(
    first: Optional[str] = None,
    second: Optional[str] = None,
    *,
    model_id: Optional[str] = None,
) -> None:
    """检查 license 是否在白名单。非白名单/缺失 → 抛 LicenseNotAllowedError。

    支持两种调用约定（共存不破级联）：
    - 新契约（B-1）：assert_license_allowed(raw_license, model_id="...")
      —— model_id 以关键字传入，first 即待检 license。
    - 旧契约（T-5）：assert_license_allowed(model_id, license_str)
      —— 两个位置参，first=model_id、second=license_str。
    """
    if model_id is not None:
        raw_license = first
        mid = model_id
    else:
        # 旧位置约定：(model_id, license_str)
        mid = first if first is not None else "<unknown>"
        raw_license = second

    norm = normalize_license(raw_license)
    allowed = ", ".join(sorted(ALLOWED_LICENSES))
    if not norm:
        raise LicenseNotAllowedError(
            f"embedder {mid} 的 license 字段缺失（missing），"
            f"不可证明合规 → 训练阻断。仅允许：{allowed}"
        )
    if norm not in ALLOWED_LICENSES:
        raise LicenseNotAllowedError(
            f"embedder {mid} 的 license={raw_license!r}（归一={norm!r}）"
            f"不在白名单 → 训练阻断。仅允许：{allowed}"
        )


def assert_model_license_allowed(config: Dict[str, Any], *, model_id: str) -> None:
    """闸入口：从 HF config 抽 license → 检查。retrain 在编码前调用。"""
    assert_license_allowed(license_from_hf_config(config), model_id=model_id)
