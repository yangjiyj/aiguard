"""
代答生成器 - 阻断请求时返回预设安全回复
"""
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, List, Mapping

MAX_REPLY_TEMPLATE_CHARS = 1000
REPLY_TEMPLATE_KEYS = (
    "default",
    "prompt_injection",
    "content_safety",
    "data_leak",
)

DEFAULT_REPLIES: Dict[str, str] = {
    "prompt_injection": "抱歉，您的输入包含异常指令，已记录本次操作。",
    "content_safety": "无法处理含有违规内容的请求。",
    "data_leak": "无法处理含有敏感信息的内容。",
    "agent_abnormal": "当前服务暂时不可用，请稍后再试。",
    "default": "请求已被安全策略拦截。",
}


@dataclass(frozen=True)
class ReplyPolicy:
    enabled: bool
    templates: Mapping[str, str]


def normalize_reply_policy(payload: dict) -> ReplyPolicy:
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "enabled",
        "templates",
    }:
        raise ValueError("reply policy must contain schema_version, enabled and templates")
    if payload.get("schema_version") != 1 or not isinstance(payload.get("enabled"), bool):
        raise ValueError("reply policy schema or enabled flag is invalid")
    templates = payload.get("templates")
    if not isinstance(templates, dict) or set(templates) != set(REPLY_TEMPLATE_KEYS):
        raise ValueError("reply policy templates are incomplete")
    normalized: Dict[str, str] = {}
    for key in REPLY_TEMPLATE_KEYS:
        value = templates.get(key)
        if not isinstance(value, str):
            raise ValueError("reply template must be a string")
        value = value.strip()
        if not value or len(value) > MAX_REPLY_TEMPLATE_CHARS:
            raise ValueError("reply template length is invalid")
        normalized[key] = value
    return ReplyPolicy(enabled=payload["enabled"], templates=MappingProxyType(normalized))


def default_reply_policy() -> ReplyPolicy:
    return ReplyPolicy(
        enabled=False,
        templates=MappingProxyType(
            {key: DEFAULT_REPLIES[key] for key in REPLY_TEMPLATE_KEYS}
        ),
    )


class ReplyGenerator:
    """根据检测到的违规类型生成代答回复"""

    @staticmethod
    def generate(finding_types: List[str], policy: ReplyPolicy) -> str:
        for ftype in finding_types:
            if ftype in policy.templates:
                return policy.templates[ftype]
        return policy.templates["default"]
