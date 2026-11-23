"""retrain 的 embedder 许可预检（编码前强制前置，spec §5E 红线）。

retrain 主流程在「下载/编码 embedder」之前调用 precheck_embedder_license：
加载操作者提供的本地 embedder 快照 config（含 license 字段）→ 过 license_gate 白名单闸。
非白名单 / license 缺失 / config 取不到（不可证明合规）→ 抛 LicenseNotAllowedError，
训练在产生任何工件前阻断，绝不引入 gated/Llama 许可传导。

config_loader 依赖注入（默认走 transformers AutoConfig），便于离线单测。
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from training.license_gate import (
    LicenseNotAllowedError,
    assert_model_license_allowed,
    license_from_hf_config,
)

ConfigLoader = Callable[[str], Dict[str, Any]]


def _default_config_loader(model_id: str) -> Dict[str, Any]:
    """默认本地快照加载器：transformers AutoConfig → dict（含 license）。
    仅在真正调用时导入 transformers，单测走注入 loader 不触发。"""
    from transformers import AutoConfig  # noqa: PLC0415 懒导入

    return AutoConfig.from_pretrained(model_id, local_files_only=True).to_dict()


def precheck_embedder_license(
    model_id: str, *, config_loader: Optional[ConfigLoader] = None
) -> str:
    """编码前许可预检。返回归一化白名单 license（供审计日志）；否则抛。"""
    loader = config_loader or _default_config_loader
    try:
        config = loader(model_id)
    except Exception as exc:  # noqa: BLE001 取不到 config = 不可证明合规
        raise LicenseNotAllowedError(
            f"无法获取 embedder {model_id} 的本地快照 config（{exc}）→ "
            f"许可不可证明，训练阻断（fail-closed）。"
        ) from exc
    # 抽出再校验（与 license_gate 同口径）；非白名单/缺失在此抛
    assert_model_license_allowed(config, model_id=model_id)
    raw = license_from_hf_config(config)
    return str(raw).strip().lower()
