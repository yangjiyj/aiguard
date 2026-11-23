"""security-engine 分层检测能力的集中开关。

所有新能力默认关闭，保证开关不开时行为与改造前一致。
读取在 SecurityEngine.__init__ 完成一次，运行期不重读。
"""
from __future__ import annotations

import os

# —— 环境变量名 ——
ENV_NORMALIZE = "SECURITY_NORMALIZE_ENABLED"
ENV_DECODE_RESCAN = "SECURITY_DECODE_RESCAN_ENABLED"
ENV_PII_CHECKSUM = "SECURITY_PII_CHECKSUM_ENABLED"
# 校验位失败即丢弃（默认开，用 is_enabled_default_on 读取）：
# 仅在 ENV_PII_CHECKSUM 主开关开启时生效，主开关关闭时行为与改造前一致。
ENV_PII_CHECKSUM_DROP_INVALID = "SECURITY_PII_CHECKSUM_DROP_INVALID"
ENV_CONFIDENCE_GATING = "SECURITY_CONFIDENCE_GATING_ENABLED"
ENV_CONFIDENCE_THRESHOLD = "SECURITY_CONFIDENCE_THRESHOLD"
ENV_LOWRESOURCE = "SECURITY_LOWRESOURCE_ENABLED"
ENV_AGENT_GUARD = "SECURITY_AGENT_GUARD_ENABLED"
# MCP 描述投毒 llm-judge 语义复核层（默认关；仅在开时由 engine 附加调用，
# 正则初筛 scan_mcp_description 不受影响。observe-only，绝不 ）。
ENV_MCP_POISON_JUDGE = "SECURITY_MCP_POISON_JUDGE_ENABLED"
ENV_LLM_JUDGE_MODE = "SECURITY_LLM_JUDGE_MODE"  # off | shadow
ENV_LLM_JUDGE_URL = "SECURITY_LLM_JUDGE_URL"
ENV_LLM_JUDGE_BACKEND = "SECURITY_LLM_JUDGE_BACKEND"
ENV_LLM_JUDGE_ALLOW_PRIVATE_EGRESS = "SECURITY_LLM_JUDGE_ALLOW_PRIVATE_EGRESS"
ENV_LLM_JUDGE_MODEL = "SECURITY_LLM_JUDGE_MODEL"
ENV_LLM_JUDGE_TIMEOUT = "SECURITY_LLM_JUDGE_TIMEOUT"
ENV_LLM_JUDGE_API_KEY = "SECURITY_LLM_JUDGE_API_KEY"
# 语义攻击检测（默认全关，开关不开即与改造前行为一致）
ENV_AUDIT_ONLY = "SECURITY_AUDIT_ONLY"
ENV_SEMANTIC_ENABLED = "SECURITY_SEMANTIC_ENABLED"
ENV_SEMANTIC_INPUT_ENABLED = "SECURITY_SEMANTIC_INPUT_ENABLED"
ENV_SEMANTIC_AGENT_ENABLED = "SECURITY_SEMANTIC_AGENT_ENABLED"
ENV_SEMANTIC_BLOCK_MIN_CONFIDENCE = "SECURITY_SEMANTIC_BLOCK_MIN_CONFIDENCE"  # 语义拦截最低置信度
# 2.9.22 控制台可配：智能分析拦截阶段（JSON 数组，取 input/agent/output，缺省只输入）；
# Claude Code 安全监视请求、模型输出密级标记的处置（observe 只留证 / follow_policy 按策略，缺省只留证）。
ENV_SEMANTIC_BLOCK_STAGES = "SECURITY_SEMANTIC_BLOCK_STAGES"
ENV_AGENT_SECURITY_MONITOR_DISPOSITION = "SECURITY_AGENT_SECURITY_MONITOR_DISPOSITION"
ENV_MODEL_OUTPUT_CLASSIFIED_DISPOSITION = "SECURITY_MODEL_OUTPUT_CLASSIFIED_DISPOSITION"
SEMANTIC_BLOCK_STAGE_NAMES = ("input", "agent", "output")
DEFAULT_SEMANTIC_BLOCK_STAGES = frozenset({"input"})
OBSERVATION_DISPOSITIONS = ("observe", "follow_policy")
DEFAULT_OBSERVATION_DISPOSITION = "observe"
ENV_SEMANTIC_TOTAL_TIMEOUT = "SECURITY_SEMANTIC_TOTAL_TIMEOUT"  # ②(+③) 总时长硬限
ENV_SEMANTIC_SAMPLE_RATE = "SECURITY_SEMANTIC_SAMPLE_RATE"
ENV_SEMANTIC_OUTPUT_ENABLED = "SECURITY_SEMANTIC_OUTPUT_ENABLED"
ENV_SEMANTIC_REVIEW_ENABLED = "SECURITY_SEMANTIC_REVIEW_ENABLED"
ENV_SEMANTIC_REVIEW_URL = "SECURITY_SEMANTIC_REVIEW_URL"
ENV_SEMANTIC_REVIEW_MODEL = "SECURITY_SEMANTIC_REVIEW_MODEL"
ENV_SEMANTIC_REVIEW_API_KEY = "SECURITY_SEMANTIC_REVIEW_API_KEY"
# Tier-1 分类器级联（默认关，开关不开即与改造前行为一致）
ENV_TIER1_ENABLED = "SECURITY_TIER1_ENABLED"
ENV_TIER1_URL = "SECURITY_TIER1_URL"
ENV_TIER1_API_TOKEN = "SECURITY_TIER1_API_TOKEN"
ENV_TIER1_TIMEOUT = "SECURITY_TIER1_TIMEOUT"
ENV_TIER1_LOW_THRESHOLD = "SECURITY_TIER1_LOW_THRESHOLD"
ENV_TIER1_HIGH_THRESHOLD = "SECURITY_TIER1_HIGH_THRESHOLD"
# legacy：原级联（Tier-1 低分即跳过裁判、间接恶意仅认旧指令语法/高分旁证）。
# coverage_v2：低分窗口有高风险线索仍送裁判；旁证须为目标文本中未被引用/否定的指令片段。
ENV_SEMANTIC_CASCADE_POLICY = "SECURITY_SEMANTIC_CASCADE_POLICY"
SEMANTIC_CASCADE_POLICIES = ("legacy", "coverage_v2")
# 误报压制（gateway-core 也读它决定是否调 /check-triage）
ENV_FP_SUPPRESSION_ENABLED = "SECURITY_FP_SUPPRESSION_ENABLED"
# 误报压制 judge 总预算（秒）：一次 /check-triage 内从入口起算（含 Tier-1 打分）的总时长上限，
# 超预算即停止后续 judge——未判的 finding 无 triage（fail-open 不压制，不藏证）。
# 纯性能修复默认生效（8s，卡在网关 10s ctx 之内）；≤0 视为不限（运维退路，恢复无预算旧行为）。
ENV_TRIAGE_TOTAL_BUDGET_SECONDS = "SECURITY_TRIAGE_TOTAL_BUDGET_SECONDS"
# 编码流量降级层（默认关）：AI IDE / 编码 agent 流量按降级表就地降 finding 严重度
ENV_CODING_TRAFFIC_DOWNGRADE = "SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED"
# source 感知检测档位（默认关）：已知编码 agent 的 system_prompt/tool_def 只跑密钥/凭据类 + 自定义规则
ENV_SOURCE_AWARE = "SECURITY_SOURCE_AWARE_ENABLED"
# All-layer scope. Unmanaged engines keep broad coverage until the signed
# control-plane defaults arrive; missing configuration never silently exempts data.
ENV_INSPECT_USER_INPUT = "SECURITY_INSPECT_USER_INPUT"
ENV_INSPECT_MODEL_OUTPUT = "SECURITY_INSPECT_MODEL_OUTPUT"
ENV_INSPECT_BUILTIN_CONTEXT = "SECURITY_INSPECT_BUILTIN_CONTEXT"
ENV_INSPECT_HISTORY = "SECURITY_INSPECT_HISTORY"
ENV_INSPECT_TOOL_RESULTS = "SECURITY_INSPECT_TOOL_RESULTS"
# 文件内容 DLP（默认关）：开启后对文本类附件(docx/pptx/xlsx/pdf/txt/csv/json)提取正文并复用现有检测器送检；关闭时 inspect_attachments 行为与改造前一致。
ENV_FILE_CONTENT_DLP = "SECURITY_FILE_CONTENT_DLP_ENABLED"

# —— 默认值 ——
CONFIDENCE_DOWNGRADE_THRESHOLD = 0.55
DEFAULT_LLM_JUDGE_URL = "http://127.0.0.1:8091/v1/chat/completions"
DEFAULT_LLM_JUDGE_MODEL = "qwen2.5-7b-instruct-local"
DEFAULT_LLM_JUDGE_TIMEOUT = 8.0
DEFAULT_LLM_JUDGE_API_KEY = "local-test-key"
DEFAULT_SEMANTIC_TOTAL_TIMEOUT = 8.0
DEFAULT_SEMANTIC_SAMPLE_RATE = 1.0
DEFAULT_TIER1_URL = "http://tier1-classifier:8000/classify"
DEFAULT_TIER1_TIMEOUT = 1.0
DEFAULT_TIER1_LOW_THRESHOLD = 0.2
DEFAULT_TIER1_HIGH_THRESHOLD = 0.8
DEFAULT_TRIAGE_TOTAL_BUDGET_SECONDS = 8.0

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}

_OVERRIDES: dict[str, str] = {}


def apply_overrides(values: dict[str, str]) -> None:
    """loader 周期注入 DB 配置（env 名→值）。空值键不覆盖（视为未设）。"""
    global _OVERRIDES
    _OVERRIDES = {k: v for k, v in (values or {}).items() if str(v).strip() != ""}


def snapshot_overrides() -> dict[str, str]:
    """返回当前 override 的隔离副本，供热重配失败时完整回滚。"""
    return dict(_OVERRIDES)


def _raw(env_name: str) -> str:
    if env_name in _OVERRIDES:
        return str(_OVERRIDES[env_name]).strip()
    return os.getenv(env_name, "").strip()


def is_enabled(env_name: str) -> bool:
    return _raw(env_name).lower() in _TRUTHY


def is_enabled_default_on(env_name: str) -> bool:
    """默认开的开关：未设/空值视为开，仅显式设为 falsy 值时关闭。

    与 is_enabled（默认关）相对，用于"关闭需显式声明"的治理类子开关；
    此类开关必须挂在某个默认关的主开关之下，保证主开关不开时行为不变。
    """
    return _raw(env_name).lower() not in _FALSY


def get_str(env_name: str, default: str) -> str:
    value = _raw(env_name)
    return value if value else default


def get_float(env_name: str, default: float) -> float:
    raw = _raw(env_name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def llm_judge_mode() -> str:
    """只返回 off 或 shadow；任何其它值（含 enforce）一律视为 off，

    保证本地裁判永远进不了 allow/block 决策。
    """
    mode = os.getenv(ENV_LLM_JUDGE_MODE, "").strip().lower()
    return "shadow" if mode == "shadow" else "off"


def parse_semantic_block_stages(raw) -> frozenset | None:
    """解析智能分析拦截阶段：非空 JSON 字符串数组、元素取 input/agent/output 且不重复；否则 None。"""
    import json

    if not isinstance(raw, str):
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) or item not in SEMANTIC_BLOCK_STAGE_NAMES for item in value)
            or len(set(value)) != len(value)):
        return None
    return frozenset(value)


def semantic_block_stages() -> frozenset:
    """运行态取值：未配置或非法时回到缺省“只输入”（2.9.21 现状），不因配置错放宽或收紧。"""
    return parse_semantic_block_stages(_raw(ENV_SEMANTIC_BLOCK_STAGES)) or DEFAULT_SEMANTIC_BLOCK_STAGES


def observation_disposition(env_name: str) -> str:
    """留证类处置：只认 observe / follow_policy，未配置或非法时取缺省 observe（2.9.21 现状）。"""
    value = _raw(env_name)
    return value if value in OBSERVATION_DISPOSITIONS else DEFAULT_OBSERVATION_DISPOSITION
