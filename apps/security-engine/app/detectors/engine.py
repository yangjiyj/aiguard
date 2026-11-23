"""
Security detection engine - Regex-based implementation.

This service uses deterministic regex-based detection for PII, secrets, and code/config patterns.
No external NLP dependencies required - runs purely on regex patterns.
"""

from __future__ import annotations

import math
import hashlib
import logging
import os
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional

from app.detectors.encoded_content import binary_regions, lexical_text, semantic_text
from app.detectors.agent_context import split_agent_context
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.content_safety import ContentSafetyDetector
from app.detectors.evidence_context import observation
from app.detectors.agent_detect import AgentDetector
from app.detectors.data_leak import DataLeakDetector
from app.detectors.hit_display import (annotate_hit_display, credential_evidence_text, credential_explanation,
                                       evidence_context_for, is_credential_format_match)
from app.detectors.policy_catalog import PolicyCatalogDetector
from app.detectors.numeric_context import (non_pii_numeric_spans, is_complete_pii_token, is_git_remote_reference,
                                          is_url_userinfo, is_escaped_sequence_local_part)
from app.detectors.config_evidence import has_literal_sensitive_config
from app.detectors.sensitive_data import SensitiveDataDetector, SENSITIVE_DATA_CATEGORIES, is_public_service_email, is_non_mailbox_at_reference
from app.detectors.prompt_stego import PromptStegoDetector
from app.reply_generator import ReplyGenerator, ReplyPolicy, default_reply_policy
from app.feature_flags import (
    CONFIDENCE_DOWNGRADE_THRESHOLD,
    DEFAULT_LLM_JUDGE_API_KEY,
    DEFAULT_LLM_JUDGE_MODEL,
    DEFAULT_LLM_JUDGE_TIMEOUT,
    DEFAULT_LLM_JUDGE_URL,
    ENV_AGENT_GUARD,
    ENV_AUDIT_ONLY,
    ENV_MCP_POISON_JUDGE,
    ENV_CODING_TRAFFIC_DOWNGRADE,
    ENV_SOURCE_AWARE,
    ENV_INSPECT_USER_INPUT,
    ENV_INSPECT_MODEL_OUTPUT,
    ENV_INSPECT_BUILTIN_CONTEXT,
    ENV_INSPECT_HISTORY,
    ENV_INSPECT_TOOL_RESULTS,
    ENV_CONFIDENCE_GATING,
    ENV_CONFIDENCE_THRESHOLD,
    ENV_DECODE_RESCAN,
    ENV_LLM_JUDGE_API_KEY,
    ENV_LLM_JUDGE_BACKEND,
    ENV_LLM_JUDGE_ALLOW_PRIVATE_EGRESS,
    ENV_LLM_JUDGE_MODEL,
    ENV_LLM_JUDGE_TIMEOUT,
    ENV_LLM_JUDGE_URL,
    ENV_LOWRESOURCE,
    ENV_NORMALIZE,
    ENV_PII_CHECKSUM,
    ENV_PII_CHECKSUM_DROP_INVALID,
    ENV_SEMANTIC_ENABLED,
    ENV_SEMANTIC_INPUT_ENABLED,
    ENV_SEMANTIC_AGENT_ENABLED,
    ENV_SEMANTIC_TOTAL_TIMEOUT,
    ENV_SEMANTIC_BLOCK_MIN_CONFIDENCE,
    ENV_AGENT_SECURITY_MONITOR_DISPOSITION,
    ENV_MODEL_OUTPUT_CLASSIFIED_DISPOSITION,
    DEFAULT_SEMANTIC_BLOCK_STAGES,
    DEFAULT_OBSERVATION_DISPOSITION,
    observation_disposition,
    semantic_block_stages as configured_semantic_block_stages,
    DEFAULT_SEMANTIC_TOTAL_TIMEOUT,
    ENV_SEMANTIC_SAMPLE_RATE,
    DEFAULT_SEMANTIC_SAMPLE_RATE,
    ENV_SEMANTIC_OUTPUT_ENABLED,
    ENV_SEMANTIC_REVIEW_ENABLED,
    ENV_SEMANTIC_REVIEW_URL,
    ENV_SEMANTIC_REVIEW_MODEL,
    ENV_SEMANTIC_REVIEW_API_KEY,
    ENV_TIER1_ENABLED,
    ENV_TIER1_URL,
    ENV_TIER1_TIMEOUT,
    ENV_TIER1_LOW_THRESHOLD,
    ENV_TIER1_HIGH_THRESHOLD,
    ENV_SEMANTIC_CASCADE_POLICY,
    DEFAULT_TIER1_URL,
    DEFAULT_TIER1_TIMEOUT,
    DEFAULT_TIER1_LOW_THRESHOLD,
    DEFAULT_TIER1_HIGH_THRESHOLD,
    ENV_FP_SUPPRESSION_ENABLED,
    ENV_TRIAGE_TOTAL_BUDGET_SECONDS,
    DEFAULT_TRIAGE_TOTAL_BUDGET_SECONDS,
    get_float,
    get_str,
    is_enabled,
    is_enabled_default_on,
    llm_judge_mode,
)
from app.detectors.pii_checksum import validate_bank_card, validate_id_card_cn, validate_phone_cn_segment
from app.detectors.normalize import decode_payloads, normalize_text
from app.detectors.pii_variants import NUMERIC_PII_CATEGORIES, find_numeric_pii, find_numeric_values
from app.text_normalize import compact_digits, normalize_view
from app.detectors.lowresource import detect_low_resource
from app.detectors.agent_guard import (
    AgentFinding,
    ToolDefinitionPinner,
    audit_action,
    judge_mcp_description_poison,
    scan_mcp_description,
)
from app.detectors.llm_judge import judge as llm_judge
from app.detectors.llm_judge import judge_triage as llm_triage_judge
from app.detectors.llm_judge import judge_contextual_candidate as llm_candidate_judge
from app.detectors.triage import build_triage_payload
from app.detectors.severity_downgrade import (
    AI_REVIEW_ELIGIBLE_MARK, annotate_key_only_findings, apply_evidence_downgrades, severity_for_action,
)
from app.semantic_enforcement import (DEFAULT_SEMANTIC_BLOCK_MIN_CONFIDENCE,
                                      apply_semantic_enforcement,
                                      normalize_block_min_confidence,
                                      stamp_semantic_run_status)
from app.detectors.semantic import (SemanticDetector, UNTRUSTED_CONTENT_SOURCES,
                                    cascade_trace, summarize_cascade)
from app.detectors.tier1_client import Tier1Client
from app import triage_service
from app.bounded_work import execution_budget
from app.principal_context import PrincipalContext

from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)

ORCHESTRATOR_NOTICE_ACTOR = "orchestrator_notice_candidate"
ORCHESTRATOR_NOTICE_PATTERN = re.compile(
    r"^\s*\[SYSTEM\s+NOTIFICATION\s+-\s+NOT\s+USER\s+INPUT\]\s+"
    r"This\s+is\s+an\s+automated\s+background-task\s+event,\s+"
    r"NOT\s+a\s+message\s+from\s+the\s+user\.\s+"
    r"Do\s+NOT\s+interpret\s+this\s+as\s+user\s+acknowledgement,\s+"
    r"confirmation,\s+or\s+response\s+to\s+any\s+pending\s+question\.\s+"
    r"No\s+human\s+input\s+has\s+been\s+received\s+since\s+the\s+last\s+"
    r"genuine\s+user\s+message\.\s*",
    re.IGNORECASE,
)

AWS_SECRET_KEY_CONTEXT = re.compile(
    r"(?:aws[_\-\s]*secret[_\-\s]*access[_\-\s]*key|"
    r"aws[_\-\s]*secret[_\-\s]*key|secret[_\-\s]*access[_\-\s]*key)",
    re.IGNORECASE,
)
AWS_SECRET_CONTEXT_WINDOW = 80
AWS_OFFICIAL_EXAMPLE_ACCESS_KEYS = frozenset({
    "AKIAIOSFODNN7EXAMPLE",
})

# Require a sensitive field assignment, not words such as "token count"
# inside an ordinary tool log or descriptive configuration value.
CONFIG_FILE_SENSITIVE_KEY = re.compile(
    r"\b(?:[A-Za-z][A-Za-z0-9]*[_-]){0,8}"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|database[_-]?url|db[_-]?url|connection|dsn|credential|"
    r"authorization|client[_-]?secret)\b"
    r"""[ \t]*["']?[ \t]*[:=]""",
    re.IGNORECASE,
)
CONFIG_FILE_SENSITIVE_VALUE = re.compile(
    r"(?:postgres|postgresql|mysql|mongodb|redis)://",
    re.IGNORECASE,
)
SECRET_FIXTURE_CONTEXT_RE = re.compile(
    r"(tests?/|test[_-]|\.(?:test|spec)\.(?:[cm]?[jt]sx?|py)|_test\.go|"
    r"def\s+test_|pytest|unittest|fixture|fixtures?|"
    r"mock|fake|dummy|examples?|samples?|evals?/|red[-_ ]?team|packs?/|"
    r"allowlist\s+secret|nosemgrep)",
    re.IGNORECASE,
)
SECRET_FIXTURE_STRUCTURE_RE = re.compile(
    r"(?im)^\s*(?:(?:async\s+)?def\s+test_[A-Za-z0-9_]*\s*\(|"
    r"(?:it|test|describe)\s*\(|func\s+Test[A-Za-z0-9_]*\s*\()"
)
SECRET_FIXTURE_ASSERTION_RE = re.compile(
    r"(?im)^\s*(?:assert\b|expect\s*\(|(?:self\.)?assert[A-Za-z0-9_]*\s*\()"
)
SECRET_FIXTURE_ID_RE = re.compile(
    r"""(?ix)["']?(?:id|case_id|sample_id)["']?\s*[:=]\s*["']
    [^"'\n]*(?:key|secret|token|fixture|sample)[^"'\n]*["']"""
)
SECRET_FIXTURE_KIND_RE = re.compile(
    r"""(?ix)["']?(?:kind|label)["']?\s*[:=]\s*["']
    (?:benign|threat|fixture|sample|example|synthetic)["']"""
)

# 示例/占位密钥识别：去掉 sk-/sk-ant- 前缀后，正文各段（按 - _ 切）都是"低信号"
# 才算占位。低信号 = 纯填充符（x/./-/*）、去重后 <=2 种字符、或已知占位词。
# 反规避关键：任何"字母+数字混合且去重 >=6 种字符"的段是真钥体片段，一票否决占位判定，
# 防止 sk-占位前缀-<真钥体> / sk-xxx<真钥体> 之类前缀伪装绕过外泄检测。
SK_STRIP_PREFIX = re.compile(r'^sk-(?:ant-)?', re.IGNORECASE)
SK_ALL_FILLER = re.compile(r'^[x.\-*_]+$', re.IGNORECASE)
SK_PLACEHOLDER_WORD = re.compile(
    r'^(?:x+|your|api|apikey|key|here|placeholder|examples?|test|sample|samples?|'
    r'dummy|fake|redacted|changeme|todo|secret|token|value|name|my|the|proj|live|ant)$',
    re.IGNORECASE,
)
SK_FIXTURE_SECRET_BODY = re.compile(
    r'^(?:live|test|fake|sample|example|dummy)[-_]'
    r'(?:abcdef|abc123|example|sample|dummy|fake|test)[A-Za-z0-9_-]*$',
    re.IGNORECASE,
)
# Codex/IDE 示例中常见的固定值 sk-live1234567890ABCDEF。它不是通用的
# "live" 前缀豁免，而是只识别连续数字后接固定十六进制样式的确定性 fixture。
SK_SEQUENTIAL_LIVE_FIXTURE = re.compile(r'^live\d{8,}[a-f]{4,}$', re.IGNORECASE)
# 合成凭据前缀只用于识别后续的可证明序列（连续字母/数字），不能单独作为
# 放行依据。这样能覆盖 teststream/sample/example 等验收数据，同时不会让
# ``sk-test-<高熵真钥体>`` 借“测试”字样绕过检测。
SK_SYNTHETIC_SEQUENCE_PREFIX = re.compile(
    r'^(?:teststream|test|sample|example|dummy|fake)[-_]?', re.IGNORECASE
)
SK_BARE_SYNTHETIC_SEQUENCE = re.compile(
    r'^(?:abcdefghijklmnopqrstuvwxyz(?P<trailing_digits>\d*)|'
    r'(?P<leading_digits>\d+)abcdefghijklmnopqrstuvwxyz)$',
    re.IGNORECASE,
)

AGENT_INVENTORY_CATEGORIES = frozenset({
    "agent_direct_api_call",
    "agent_long_session",
})

GENERIC_SECRET_PLACEHOLDERS = frozenset({
    "changeme",
    "exampleapikey",
    "placeholder",
    "replace_me",
    "sampleapikey",
    "testapikey",
    "yourapikey",
})

# Gateway marker for Claude Code's auto-mode security monitor request.
AGENT_SECURITY_MONITOR_KIND = "claude_code_security_monitor"
# 2.9.21：网关原生路径声明的模型输出里，密级标记只留证（_observe_model_output_classified_markers）。
MODEL_OUTPUT_CLASSIFIED_CATEGORIES = frozenset({"classified_classified_cn", "classified_classified_en"})
MODEL_OUTPUT_CLASSIFIED_RULE_IDS = frozenset({"data_leak_classified_cn", "data_leak_classified_en"})
MODEL_OUTPUT_CLASSIFIED_REASON = "model_output_classified_marker"
MODEL_OUTPUT_CLASSIFIED_LABEL = "模型输出里的密级字样，内容由模型生成，不是本单位文件外发"
# 可放宽的内置密级策略只认控制面内置「涉密文件标记检测」这一条的编码（客户现场核实过）。租户把别的内置
# 策略覆写成只绑密级能力、或 system. 开头的同构策略，都照 2.9.20 生效。
MODEL_OUTPUT_CLASSIFIED_POLICY_CODE = "builtin.data_leak.17723b156cfa7533"
# 网关原生路径的入口；反代、正代的身份来源不认声明。
MODEL_OUTPUT_NATIVE_ENTRY_POINT = "gateway_api"
MODEL_OUTPUT_PROXY_IDENTITY_SOURCES = frozenset({"reverse_proxy", "forward_proxy"})


def _is_model_output_classified_observation(finding) -> bool:
    return (
        finding.counts_as_security_finding is False
        and finding.triage.get("disposition_reason") == MODEL_OUTPUT_CLASSIFIED_REASON
    )


# 严重度等级序：编码流量降级层"只降不升"的比较基准
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# 编码流量降级表（rule_id → 目标 severity）：AI IDE / 编码 agent 的机器流量里，
# 这些规则的典型命中是遥测字段、示例代码、工程配置，风险远低于人类对话流量；
# 按表就地降档留痕，非编码流量不受影响。 finding 永不降级。
CODING_TRAFFIC_DOWNGRADE_MAP: Dict[str, str] = {
    "content_safety_illegal_system_command_instructions": "low",
    "content_safety_ssrf_metadata_instruction": "medium",
    "code_env_file": "low",
    "code_config_file": "low",
    "secret_generic_api_key": "medium",
    # 扩充：编码 agent 流量里下列规则的典型命中是代码/密钥变量名/代码结构/工程内容，
    # 远低于人类对话风险；只降不升、留 severity_original 证据、 永不降。
    # 真提示注入由独立的语义检测(semantic_attack)兜底，不依赖这些关键词/结构规则。
    "secret_openai_key": "medium",
    "data_leak_api_key_leak": "medium",
    "prompt_injection_unicode_escape": "low",
    "prompt_injection_html_comment": "low",
    "prompt_injection_template_injection": "low",
    "prompt_injection_classic_injection": "medium",
    "prompt_injection_bypass_restriction": "medium",
    "prompt_injection_dev_mode": "medium",
    "prompt_injection_roleplay": "medium",
    # 英文注入关键词层：与上述中文同类规则对称降级（编码 agent 流量里的命中多为注入示例/
    # 红队样本/文档，风险远低于人类对话）；真提示注入仍由 semantic_attack 兜底。
    "prompt_injection_classic_injection_en": "medium",
    "prompt_injection_roleplay_en": "medium",
    "prompt_injection_system_prompt_leak_en": "medium",
    "prompt_injection_dev_mode_en": "medium",
    "regex_email": "low",
    # 代码/密钥类：编码流量里 JWT/GitHub/AWS token、代码内密码、token 泄露模式的典型命中
    # 是示例/测试数据/密钥变量名，non-;真凭据( 格式)永不降、照常告警。
    # 注意：customer_data/hr_data/internal_doc 等数据合规类故意不降；classified 单词类已按设计 2c 纳入降级（见下）。
    "secret_jwt_token": "medium",
    "secret_github_token": "medium",
    "secret_aws_access_key": "medium",
    "data_leak_token_leak": "medium",
    "data_leak_password_in_code": "medium",
    # P1-A（设计 2c）：涉密标记单词在编码流量里典型是代码注释/文案里的"机密/confidential"字样，
    # 降至 medium 留证；带文档/数据佐证的真外泄基础 severity 已是 high，降后仍 audit 级留痕、不漏检。
    "data_leak_classified_cn": "medium",
    "data_leak_classified_en": "medium",
}

# 编码类 agent 规范值：对齐 packages/shared-go/aiadapters agent-registry 的编码类条目，
# 统一归一化为小写连字符形式（引擎侧 AgentDetector 的下划线形式归一化后同样命中）。
CODING_AGENT_TYPES = frozenset({
    "claude-code", "openai-codex", "cursor", "windsurf", "github-copilot",
    "cline", "roo-code", "kilo-code", "continue", "continue-dev", "aider",
    "opencode", "openclaw", "devin", "amp", "goose", "gemini-cli", "qwen-code",
    "jetbrains-junie", "tabnine", "qodo", "sourcegraph-cody", "amazon-kiro",
    "google-antigravity", "replit-agent", "bolt", "lovable", "v0", "codebuddy",
    "tongyi-lingma", "qoder", "codearts-snap", "deveco-codegenie", "trae",
    "marscode", "baidu-comate", "iflycode", "codegeex", "codefuse",
    "workbuddy", "deepseek-harness", "vscode",
})

# 协议位置比具体客户端品牌更稳定。开启 source-aware 后，这些位置中的
# PII/代码配置候选是上下文资产或检测信号，不等同于用户攻击或已发生泄露。
# agent_internal_task is deliberately excluded: a title template is caller-controlled
# and cannot attest that its embedded user text was previously inspected.
# 已知编程智能体的 user 消息里，客户端注入的上下文只做确定性扫描（见 agent_context）。
AGENT_CONTEXT_SCOPED_SOURCES = frozenset({"user", "user_history"})

# 已知编程智能体的工具结果（读文件、命令输出）是数据：只保留固定格式的确定性检出，
# 其余检测（语义判官、关键词/意图、提示注入、内容安全、普通 PII 等）不跑。
CODING_TOOL_RESULT_PII = frozenset({"id_card_cn", "bank_card_cn"})
SERIAL_NUMBER_LABEL_BEFORE = re.compile(
    r"(?:订单号?|流水号?|运单号?|快递单号?|单号|交易号|工单号?|序列号|批次号?|发票号码?"
    r"|(?<![A-Za-z])(?:order|tracking|serial|invoice|ticket|trace|request|transaction|txn)[ _-]?(?:id|no|number|num)?)"
    r"[ \t]*[:：=#]?[ \t]*$",
    re.I,
)
CODING_TOOL_RESULT_CODE_CONFIG = frozenset({
    "ssh_private_key", "openssh_private_key",
    # env_file/config_file 只在含真实敏感值时才命中（has_literal_sensitive_config）。
    "env_file", "config_file",
})
CODING_TOOL_RESULT_SENSITIVE_DATA = frozenset({
    "passport_cn", "hk_macao_taiwan_id", "officer_id_cn", "driver_license_cn",
    "plain_password", "cloud_credential",
})
CODING_TOOL_RESULT_DATA_LEAK = frozenset({"code_leak_database_url"})

NON_USER_CONTENT_SOURCES = frozenset({
    "system_prompt",
    "agent_runtime_context",
    "agent_analysis_context",
    "tool_def",
    "assistant_history",
    "tool_result",
})

SEMANTIC_ATTACK_ANCHOR_RE = re.compile(
    r"(?i)("
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|system|developer)?\s*instructions?|"
    r"override\s+(?:the\s+)?(?:system|developer|previous|prior)?\s*instructions?|"
    r"bypass|jailbreak|DAN|developer\s*mode|unrestricted|no\s+restrictions?|"
    r"reveal|print|show\s+me|leak|exfiltrate|system\s+prompt|hidden\s+(?:prompt|context)|"
    r"忽略.{0,12}(之前|以上|所有|系统|开发者)?.{0,8}(指令|规则|要求)|"
    r"无视.{0,12}(之前|以上|所有|系统|开发者)?.{0,8}(指令|规则|要求)|"
    r"覆盖.{0,12}(之前|以上|系统|开发者)?.{0,8}(指令|规则|要求)|"
    r"绕过|越狱|开发者模式|无限制|不受限制|不要遵守|不用遵守|"
    r"系统提示词|隐藏上下文|打印.{0,8}(系统提示|系统提示词)|"
    r"泄露|外发|导出|发送.{0,16}(密钥|令牌|密码|凭据|系统提示)"
    r")"
)

SEMANTIC_ATTACK_META_DISCUSSION_RE = re.compile(
    r"(?i)(用户越狱|语义指令篡改|prompt\s*注入|提示注入|安全告警|误报|false\s*positive)"
)

AGENT_TOOL_SSRF_METADATA_RE = re.compile(
    r"(?is)\bhttp_get\b.{0,180}"
    r"(169\.254\.169\.254|latest/meta-data|metadata/instance|IMDS|"
    r"云实例元数据|实例元数据服务|security-credentials)"
)

AGENT_TOOL_RISKY_COMMAND_RE = re.compile(
    r"(?is)\b(?:run_shell|shell_exec|exec_command|run_command)\b.{0,180}"
    r"(chmod\s+-R\s+(?:777|[0-7]{3})|curl\b[^\n|]{0,160}\|\s*(?:bash|sh)\b|"
    r"rm\s+-rf\b|mkfs(?:\.\w+)?\b|dd\s+if=|EncodedCommand)"
)

SEMANTIC_ATTACK_STRONG_ANCHOR_RE = re.compile(
    r"(?i)("
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|system|developer)?\s*instructions?|"
    r"override\s+(?:the\s+)?(?:system|developer|previous|prior)?\s*instructions?|"
    r"reveal.{0,40}system\s+prompt|system\s+prompt.{0,40}(?:reveal|print|show|leak)|"
    r"exfiltrate.{0,40}(?:secret|credential|token|key|system\s+prompt)|"
    r"忽略.{0,16}(之前|以上|所有|系统|开发者)?.{0,12}(指令|规则|要求)|"
    r"无视.{0,16}(之前|以上|所有|系统|开发者)?.{0,12}(指令|规则|要求)|"
    r"覆盖.{0,16}(之前|以上|系统|开发者)?.{0,12}(指令|规则|要求)|"
    r"不要遵守|不用遵守|"
    r"系统提示词|隐藏上下文|打印.{0,12}(系统提示|系统提示词)|"
    r"泄露.{0,24}(系统提示|系统提示词|密钥|令牌|密码|凭据)|"
    r"发送.{0,24}(系统提示|系统提示词|密钥|令牌|密码|凭据)"
    r")"
)

SEMANTIC_ATTACK_DIRECTIVE_ANCHOR_RE = re.compile(
    r"(?is)("
    r"(?:please|help\s+me|can\s+you|try\s+to|must|immediately|now|"
    r"i\s+want\s+you\s+to|you\s+(?:must|should|need\s+to))"
    r".{0,48}\b(?:bypass|jailbreak|enable\s+(?:developer\s+mode|unrestricted)|"
    r"disable\s+(?:safety|guardrails?))\b|"
    r"\b(?:bypass|jailbreak)\b.{0,48}"
    r"\b(?:safety|security|policy|guardrails?|restrictions?|instructions?)\b|"
    r"(?:\u8bf7|\u5e2e\u6211|\u7acb\u5373|\u9a6c\u4e0a|\u52a1\u5fc5|"
    r"\u5fc5\u987b|\u8bbe\u6cd5|\u5c1d\u8bd5)"
    r"[^\u3002\uff01\uff1f;\r\n]{0,32}(?:\u7ed5\u8fc7|\u8d8a\u72f1|"
    r"\u5f00\u53d1\u8005\u6a21\u5f0f|\u65e0\u9650\u5236|\u4e0d\u53d7\u9650\u5236)|"
    r"(?:\u7ed5\u8fc7|\u89c4\u907f|\u9003\u907f)"
    r"[^\u3002\uff01\uff1f;\r\n]{0,32}"
    r"(?:\u5b89\u5168\u7b56\u7565|\u5b89\u5168\u9650\u5236|"
    r"\u7cfb\u7edf\u7b56\u7565|\u7cfb\u7edf\u9650\u5236|"
    r"\u89c4\u5219|\u68c0\u6d4b|\u544a\u8b66|\u9650\u5236)"
    r")"
)

BUILTIN_PII_RULE_IDS = frozenset({
    "rule_g_bankcard", "rule_g_email", "rule_g_idcard", "rule_g_passport", "rule_g_phone",
})

# Credentials and legally identifying numbers are never relaxed by the engine's
# automatic downgrades (coding traffic heuristics, AI review, evidence
# downgrades). Administrator-created content exceptions and the fixed reply
# still apply to them (2.9.22). Both native detector categories and the
# shipped generic-regex categories are included.
NON_DOWNGRADABLE_CATEGORIES = frozenset({
    "anthropic_key",
    "aws_access_key",
    "aws_secret_key",
    "bank_card_cn",
    "generic_api_key",
    "github_token",
    "id_card_cn",
    "jwt_token",
    "openai_key",
    "openssh_private_key",
    "pii_bankcard",
    "pii_idcard",
    "pii_passport",
    "private_key",
    "ssh_private_key",
})


class SecurityFinding(BaseModel):
    type: str  # pii, secret, code_config, custom
    category: str
    severity: str  # low, medium, high, critical
    matched_text_preview: str
    rule_id: str
    confidence: float = 0.0
    # P2-1 统一结果模型扩展（默认值保证向后兼容，内置检测器无需改动）
    rule_name: str = ""
    rule_type: str = "builtin"  # builtin | regex | keyword | field_name | secret | edm | file_fingerprint
    action: str = ""            # allow | audit | alert | block | quarantine
    counts_as_security_finding: bool = True  # 引擎运行异常留审计，但不计作内容风险命中
    matched_location: str = ""  # 命中位置（不含原文，如 content[7:17] 或 field:xxx）
    redacted_evidence: str = ""  # 脱敏后的命中证据
    exception_id: str = ""       # 命中的例外 ID（已豁免标注；为空表示未豁免）
    policy_code: str = ""
    policy_scene: str = ""
    source_rule_id: str = ""
    matched_capabilities: List[str] = Field(default_factory=list)
    severity_original: Optional[str] = None  # 编码流量候选标记：降级层处理前的级别；非候选为 None
    triage: Dict[str, Any] = Field(default_factory=dict)  # AI 复核结论，仅用于解释，不参与决策
    raw_evidence: str = ""  # 管理员告警详情使用的完整命中片段
    evidence_context: str = ""  # 命中点前后未脱敏上下文；独立于常规内容留存
    secret_text: str = ""  # 需要隐藏的秘密本体，只在内存里随检测响应传给网关用于打码前后文；绝不落库、不写日志、不进 raw_findings
    evidence_kind: str = ""  # literal | semantic | contextual | runtime
    content_source: str = ""  # user | system_prompt | tool_def | model_output ...
    evidence_reason: str = ""  # 规则触发条件或语义裁判理由
    message_index: Optional[int] = None  # 当前会话消息序号；None 表示无消息锚点，0 是有效值
    message_role: str = ""  # 当前会话消息角色，来自可信内部 context
    attachment_index: Optional[int] = None  # 附件在当前消息中的序号；0 是有效值
    # raw_evidence 仅用于已鉴权的管理员告警详情，不替代 redacted_evidence。

    def cannot_downgrade(self) -> bool:
        return (
            self.triage.get("cannot_downgrade") is True
            or self.category in NON_DOWNGRADABLE_CATEGORIES
        )


class FileBindingToken(BaseModel):
    token: str
    sha256: str


def _copy_without_secret_text(findings: List["SecurityFinding"]) -> List["SecurityFinding"]:
    """raw_findings 会被网关原样存进指纹缓存，副本里不能带秘密本体。"""
    copies = [f.model_copy(deep=True) for f in findings]
    for copy in copies:
        copy.secret_text = ""
    return copies


class SecurityCheckResult(BaseModel):
    request_id: str
    findings: List[SecurityFinding]
    action: str  # allow, mask, block, audit
    masked_content: Optional[str] = None
    redaction_mapping: Dict[str, str] = Field(default_factory=dict)
    original_hash: Optional[str] = None
    # P1-A：降档/例外之前的原始 findings（供指纹缓存 Plan B 与 /apply-context/ 重放）
    raw_findings: List[SecurityFinding] = Field(default_factory=list)
    # 本次检测实际使用的规则包版本；不能在检测结束后再读 live 版本，否则热更新
    # 可能让“旧规则判定 + 新版本号”出现在同一响应。
    rule_pack_version: str = ""
    # 本次请求抓取的语义运行配置版本；与规则包版本分别留证。
    semantic_config_revision: str = ""
    # 语义裁判完成度独立于风险 finding；未完成不得伪装成“未发现风险”。
    semantic_status: str = "not_requested"
    semantic_reason: str = ""
    # What the CPU+judge cascade actually did (counts only, no text). None when
    # the semantic block did not run.
    semantic_trace: Optional[Dict[str, Any]] = None
    file_bindings: List[FileBindingToken] = Field(default_factory=list)


@dataclass(frozen=True)
class SemanticRuntimeSnapshot:
    """单指针热切换的不可变运行快照；一个请求只使用抓取到的这一份。"""

    revision: str
    audit_only: bool
    llm_judge_mode: str
    mcp_poison_judge_enabled: bool
    semantic_master_enabled: bool
    semantic_input_enabled: bool
    semantic_agent_enabled: bool
    semantic_output_enabled: bool
    semantic_detector: SemanticDetector
    judge_backend: str
    judge_allow_private_egress: bool
    judge_url: str
    judge_model: str
    judge_api_key: str
    judge_timeout: float
    semantic_total_timeout: float
    semantic_sample_rate: float
    tier1_enabled: bool
    tier1_url: str
    tier1_timeout: float
    tier1_low: float
    tier1_high: float
    tier1_client: Any
    fp_suppression_enabled: bool
    triage_total_budget: float
    source_aware_enabled: bool
    confidence_gating_enabled: bool
    confidence_downgrade_threshold: float
    coding_traffic_downgrade_enabled: bool
    inspect_user_input: bool
    inspect_model_output: bool
    inspect_builtin_context: bool
    inspect_history: bool
    inspect_tool_results: bool
    # 控制台语义设置：策略选「拦截」时，裁判置信度达到它才真拦截。
    semantic_block_min_confidence: float = DEFAULT_SEMANTIC_BLOCK_MIN_CONFIDENCE
    # 2.9.22 控制台可配：智能分析拦截阶段；监视请求与模型输出密级的处置。
    semantic_block_stages: frozenset = DEFAULT_SEMANTIC_BLOCK_STAGES
    agent_security_monitor_disposition: str = DEFAULT_OBSERVATION_DISPOSITION
    model_output_classified_disposition: str = DEFAULT_OBSERVATION_DISPOSITION


class SecurityEngine:
    """Regex-based detector for PII, secrets, and code/config patterns."""

    def __init__(self) -> None:
        logger.info("SecurityEngine initialized with regex-based detection")

        # 规则包写侧仅在热替换/回滚的极短窗口持锁；读侧只在请求开头抓取
        # 规则、例外、文件策略和版本快照，检测全过程不持锁。
        self._rule_pack_lock = threading.RLock()
        self._semantic_config_lock = threading.RLock()

        self.prompt_injection = PromptInjectionDetector()
        self.content_safety = ContentSafetyDetector()
        self.agent_detect = AgentDetector()
        self.data_leak = DataLeakDetector()
        self.prompt_stego = PromptStegoDetector()
        self.reply_gen = ReplyGenerator()
        self.reply_policy = default_reply_policy()
        # P1-A：镜像构建期注入的版本号（供 check-input 响应回带，网关据此做指纹缓存键）
        self.engine_build = os.getenv("SECURITY_ENGINE_BUILD", "").strip()
        # 当前生效规则包版本，由 rule_pack_loader 加载成功后写入（响应回带给网关）
        self.rule_pack_version = ""
        # —— 分层检测能力开关（默认全关，保证不影响生产中转）——
        self.normalize_enabled = is_enabled(ENV_NORMALIZE)
        self.decode_rescan_enabled = is_enabled(ENV_DECODE_RESCAN)
        self.pii_checksum_enabled = is_enabled(ENV_PII_CHECKSUM)
        # 校验位失败即丢弃（默认开）：仅在 pii_checksum_enabled 下生效
        self.pii_checksum_drop_invalid = is_enabled_default_on(ENV_PII_CHECKSUM_DROP_INVALID)
        self.lowresource_enabled = is_enabled(ENV_LOWRESOURCE)
        self.agent_guard_enabled = is_enabled(ENV_AGENT_GUARD)
        self._tool_pinner = ToolDefinitionPinner()
        # —— 语义/裁判配置：抽成 reconfigure_semantic 供热重配复用（B1）——
        # __init__ 与 loader 后台线程共用同一段读取逻辑，保证「免重启生效」。
        self.reconfigure_semantic()

        self.secret_patterns: Dict[str, re.Pattern[str]] = {
            "aws_access_key": re.compile(
                r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
            ),
            "aws_secret_key": re.compile(
                r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
            ),
            "github_token": re.compile(
                r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,255}", re.IGNORECASE
            ),
            "generic_api_key": re.compile(
                r"(?:api[_-]?key|apikey|api[_-]?secret)[\s:=]+"
                r"(?P<generic_value>[A-Za-z0-9_\-]{8,128})",
                re.IGNORECASE,
            ),
            "jwt_token": re.compile(
                r"eyJ[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"
            ),
            "openai_key": re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}", re.IGNORECASE),
            "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}", re.IGNORECASE),
        }

        # 常见厂商令牌的固定前缀格式：GitLab、Slack、Stripe 正式密钥、Google API key、npm、
        # HuggingFace、阿里云 AccessKey ID。按 generic_api_key 上报（沿用“API Key 检测”策略），
        # 正文必须同时含字母和数字且够随机，占位符（xxxx、your-token-here）不算。
        # 每条带一个字面前缀：内容里没有这个前缀就不跑正则，超长输入上不增加扫描开销。
        self.vendor_token_patterns = (
            ("glpat-", re.compile(r"(?<![A-Za-z0-9_-])glpat-(?P<body>[A-Za-z0-9_-]{20,64})")),
            ("xox", re.compile(r"(?<![A-Za-z0-9_-])xox[abprs]-(?P<body>[A-Za-z0-9-]{20,255})")),
            ("k_live_", re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_live_(?P<body>[A-Za-z0-9]{20,255})")),
            ("AIza", re.compile(r"(?<![A-Za-z0-9_-])AIza(?P<body>[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])")),
            ("npm_", re.compile(r"(?<![A-Za-z0-9_])npm_(?P<body>[A-Za-z0-9]{36})(?![A-Za-z0-9_])")),
            ("hf_", re.compile(r"(?<![A-Za-z0-9_])hf_(?P<body>[A-Za-z0-9]{30,64})(?![A-Za-z0-9_])")),
            ("LTAI", re.compile(r"(?<![A-Za-z0-9])LTAI(?P<body>[A-Za-z0-9]{12,20})(?![A-Za-z0-9])")),
        )

        self.code_patterns: Dict[str, re.Pattern[str]] = {
            # One KEY=value per real line (optionally "export "). A single long
            # HTML/minified line with two "KEY=" fragments is not a .env file.
            "env_file": re.compile(
                r"(?:^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]{1,}=[^\r\n]+(?:\r?\n|$)){2,}",
                re.MULTILINE,
            ),
            "ssh_private_key": re.compile(
                r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
            ),
            "openssh_private_key": re.compile(
                r"-----BEGIN OPENSSH PRIVATE KEY-----"
            ),
            # Each record occupies a real line; value backtracking must not
            # invent a second key from words later in the same log line.
            "config_file": re.compile(
                r"""(?:^[ \t]*["']?[A-Za-z_][A-Za-z0-9_.-]*["']?[ \t]*[:=]"""
                r"""[ \t]*[^\r\n]*(?:\r?\n|$)){2,}""",
                re.MULTILINE,
            ),
        }

        self.chinese_patterns: Dict[str, re.Pattern[str]] = {
            "phone_cn": re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
            "id_card_cn": re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"),
            "bank_card_cn": re.compile(r"(?<!\d)\d{16,19}(?!\d)"),
            # 本地部分/域名按 RFC 上限（64/253）有界：无界的 "[...]+@" 在没有 @ 的长串里
            # 每个起点都吃到串尾再回溯，100KB 数字串要几十秒。
            "email": re.compile(
                r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}", re.IGNORECASE
            ),
        }
        self.sensitive_data = SensitiveDataDetector()
        self.policy_catalog = PolicyCatalogDetector()

        # P2-1：自定义规则集（方案A 引擎消费侧）。默认空，由规则包加载器注入。
        from app.custom_rules import CustomRuleSet, ExceptionSet
        self.custom_rules = CustomRuleSet([])
        from app.policy_bindings import PolicySet
        self.policies = PolicySet([])
        # P2-3：内容例外集（误报豁免）。默认空，由规则包加载器注入。
        self.content_exceptions = ExceptionSet([])

    def snapshot_semantic_runtime(self) -> SemanticRuntimeSnapshot:
        """抓取当前单一运行配置指针；调用方在整个请求内持有该对象。"""
        with self._semantic_config_lock:
            return self._semantic_runtime

    def _replace_semantic_runtime(self, **changes: Any) -> None:
        with self._semantic_config_lock:
            self._semantic_runtime = replace(self._semantic_runtime, **changes)

    @property
    def semantic_config_revision(self) -> str:
        return self.snapshot_semantic_runtime().revision

    @property
    def audit_only(self) -> bool:
        return self.snapshot_semantic_runtime().audit_only

    @audit_only.setter
    def audit_only(self, value: bool) -> None:
        # 仅保留给启动自检/旧测试的兼容入口；仍是不可变快照单指针交换。
        self._replace_semantic_runtime(audit_only=bool(value))

    @property
    def llm_judge_mode(self) -> str:
        return self.snapshot_semantic_runtime().llm_judge_mode

    @property
    def mcp_poison_judge_enabled(self) -> bool:
        return self.snapshot_semantic_runtime().mcp_poison_judge_enabled

    @property
    def semantic_enabled(self) -> bool:
        runtime = self.snapshot_semantic_runtime()
        return runtime.semantic_master_enabled and runtime.semantic_input_enabled

    @property
    def semantic_agent_enabled(self) -> bool:
        runtime = self.snapshot_semantic_runtime()
        return runtime.semantic_master_enabled and runtime.semantic_agent_enabled

    @property
    def semantic_output_enabled(self) -> bool:
        runtime = self.snapshot_semantic_runtime()
        return runtime.semantic_master_enabled and runtime.semantic_output_enabled

    @property
    def semantic(self) -> SemanticDetector:
        return self.snapshot_semantic_runtime().semantic_detector

    @property
    def _judge_url(self) -> str:
        return self.snapshot_semantic_runtime().judge_url

    @property
    def _judge_model(self) -> str:
        return self.snapshot_semantic_runtime().judge_model

    @property
    def _judge_api_key(self) -> str:
        return self.snapshot_semantic_runtime().judge_api_key

    @property
    def _judge_timeout(self) -> float:
        return self.snapshot_semantic_runtime().judge_timeout

    @property
    def _semantic_total_timeout(self) -> float:
        return self.snapshot_semantic_runtime().semantic_total_timeout

    @property
    def _semantic_sample_rate(self) -> float:
        return self.snapshot_semantic_runtime().semantic_sample_rate

    @property
    def _tier1_enabled(self) -> bool:
        return self.snapshot_semantic_runtime().tier1_enabled

    @property
    def _tier1_url(self) -> str:
        return self.snapshot_semantic_runtime().tier1_url

    @property
    def _tier1_timeout(self) -> float:
        return self.snapshot_semantic_runtime().tier1_timeout

    @property
    def _tier1_low(self) -> float:
        return self.snapshot_semantic_runtime().tier1_low

    @property
    def _tier1_high(self) -> float:
        return self.snapshot_semantic_runtime().tier1_high

    @property
    def _tier1_client(self):
        return self.snapshot_semantic_runtime().tier1_client

    @property
    def fp_suppression_enabled(self) -> bool:
        return self.snapshot_semantic_runtime().fp_suppression_enabled

    @property
    def _triage_total_budget(self) -> float:
        return self.snapshot_semantic_runtime().triage_total_budget

    @property
    def source_aware_enabled(self) -> bool:
        return self.snapshot_semantic_runtime().source_aware_enabled

    @property
    def confidence_gating_enabled(self) -> bool:
        return self.snapshot_semantic_runtime().confidence_gating_enabled

    @property
    def confidence_downgrade_threshold(self) -> float:
        return self.snapshot_semantic_runtime().confidence_downgrade_threshold

    @property
    def coding_traffic_downgrade_enabled(self) -> bool:
        return self.snapshot_semantic_runtime().coding_traffic_downgrade_enabled

    def reconfigure_semantic(self, revision: Optional[str] = None) -> None:
        """先构造完整不可变候选，再用单指针交换；失败时上一版完全不动。"""
        judge_backend = get_str(ENV_LLM_JUDGE_BACKEND, "")
        judge_allow_private_egress = is_enabled(
            ENV_LLM_JUDGE_ALLOW_PRIVATE_EGRESS
        )
        judge_url = get_str(ENV_LLM_JUDGE_URL, DEFAULT_LLM_JUDGE_URL)
        judge_model = get_str(ENV_LLM_JUDGE_MODEL, DEFAULT_LLM_JUDGE_MODEL)
        judge_api_key = get_str(ENV_LLM_JUDGE_API_KEY, DEFAULT_LLM_JUDGE_API_KEY)
        judge_timeout = get_float(ENV_LLM_JUDGE_TIMEOUT, DEFAULT_LLM_JUDGE_TIMEOUT)
        audit_only = is_enabled(ENV_AUDIT_ONLY)
        mcp_poison_judge_enabled = is_enabled(ENV_MCP_POISON_JUDGE)
        semantic_master_enabled = is_enabled(ENV_SEMANTIC_ENABLED)
        semantic_input_enabled = is_enabled(ENV_SEMANTIC_INPUT_ENABLED)
        semantic_agent_enabled = is_enabled(ENV_SEMANTIC_AGENT_ENABLED)
        semantic_output_enabled = is_enabled(ENV_SEMANTIC_OUTPUT_ENABLED)
        semantic_total_timeout = get_float(
            ENV_SEMANTIC_TOTAL_TIMEOUT, DEFAULT_SEMANTIC_TOTAL_TIMEOUT
        )
        semantic_sample_rate = get_float(
            ENV_SEMANTIC_SAMPLE_RATE, DEFAULT_SEMANTIC_SAMPLE_RATE
        )
        tier1_enabled = is_enabled(ENV_TIER1_ENABLED)
        tier1_url = get_str(ENV_TIER1_URL, DEFAULT_TIER1_URL)
        tier1_timeout = get_float(ENV_TIER1_TIMEOUT, DEFAULT_TIER1_TIMEOUT)
        tier1_low = get_float(ENV_TIER1_LOW_THRESHOLD, DEFAULT_TIER1_LOW_THRESHOLD)
        tier1_high = get_float(ENV_TIER1_HIGH_THRESHOLD, DEFAULT_TIER1_HIGH_THRESHOLD)
        fp_suppression_enabled = is_enabled(ENV_FP_SUPPRESSION_ENABLED)
        triage_total_budget = get_float(
            ENV_TRIAGE_TOTAL_BUDGET_SECONDS, DEFAULT_TRIAGE_TOTAL_BUDGET_SECONDS
        )
        # Tier-1 专用令牌优先；旧部署未注入专用变量时回退服务内部令牌。
        # 两者只用于服务间鉴权，不进入检测结果或日志。
        tier1_token = (
            os.getenv("SECURITY_TIER1_API_TOKEN", "").strip()
            or os.getenv("JJD_INTERNAL_API_SECRET", "").strip()
        )
        tier1_client = (
            Tier1Client(url=tier1_url, token=tier1_token, timeout=tier1_timeout)
            if tier1_enabled
            else None
        )
        source_aware_enabled = is_enabled(ENV_SOURCE_AWARE)
        confidence_gating_enabled = is_enabled(ENV_CONFIDENCE_GATING)
        confidence_downgrade_threshold = get_float(
            ENV_CONFIDENCE_THRESHOLD, CONFIDENCE_DOWNGRADE_THRESHOLD
        )
        coding_traffic_downgrade_enabled = is_enabled(ENV_CODING_TRAFFIC_DOWNGRADE)

        semantic_detector = SemanticDetector(
            url=judge_url,
            model=judge_model,
            api_key=judge_api_key,
            op_timeout=judge_timeout,
            total_timeout=semantic_total_timeout,
            sample_rate=semantic_sample_rate,
            judge_backend=judge_backend,
            allow_private_egress=judge_allow_private_egress,
            review_enabled=is_enabled(ENV_SEMANTIC_REVIEW_ENABLED),
            review_url=get_str(ENV_SEMANTIC_REVIEW_URL, judge_url),
            review_model=get_str(ENV_SEMANTIC_REVIEW_MODEL, judge_model),
            review_api_key=get_str(ENV_SEMANTIC_REVIEW_API_KEY, judge_api_key),
            tier1_enabled=tier1_enabled,
            tier1_client=tier1_client,
            tier1_low_threshold=tier1_low,
            tier1_high_threshold=tier1_high,
            # 分类分数只用于分流；审计模式同样必须由上下文裁判确认风险。
            tier1_high_direct=False,
            source_context_enabled=source_aware_enabled,
            decode_inputs=is_enabled(ENV_DECODE_RESCAN),
            cascade_policy=get_str(ENV_SEMANTIC_CASCADE_POLICY, "legacy").strip().lower(),
        )
        current = getattr(self, "_semantic_runtime", None)
        candidate = SemanticRuntimeSnapshot(
            revision=revision if revision is not None else (
                current.revision if current is not None else "environment"
            ),
            audit_only=audit_only,
            llm_judge_mode=llm_judge_mode(),
            mcp_poison_judge_enabled=mcp_poison_judge_enabled,
            semantic_master_enabled=semantic_master_enabled,
            semantic_input_enabled=semantic_input_enabled,
            semantic_agent_enabled=semantic_agent_enabled,
            semantic_output_enabled=semantic_output_enabled,
            semantic_detector=semantic_detector,
            judge_backend=judge_backend,
            judge_allow_private_egress=judge_allow_private_egress,
            judge_url=judge_url,
            judge_model=judge_model,
            judge_api_key=judge_api_key,
            judge_timeout=judge_timeout,
            semantic_total_timeout=semantic_total_timeout,
            semantic_sample_rate=semantic_sample_rate,
            tier1_enabled=tier1_enabled,
            tier1_url=tier1_url,
            tier1_timeout=tier1_timeout,
            tier1_low=tier1_low,
            tier1_high=tier1_high,
            tier1_client=tier1_client,
            fp_suppression_enabled=fp_suppression_enabled,
            triage_total_budget=triage_total_budget,
            source_aware_enabled=source_aware_enabled,
            confidence_gating_enabled=confidence_gating_enabled,
            confidence_downgrade_threshold=confidence_downgrade_threshold,
            coding_traffic_downgrade_enabled=coding_traffic_downgrade_enabled,
            inspect_user_input=is_enabled_default_on(ENV_INSPECT_USER_INPUT),
            inspect_model_output=is_enabled_default_on(ENV_INSPECT_MODEL_OUTPUT),
            inspect_builtin_context=is_enabled_default_on(ENV_INSPECT_BUILTIN_CONTEXT),
            inspect_history=is_enabled_default_on(ENV_INSPECT_HISTORY),
            inspect_tool_results=is_enabled_default_on(ENV_INSPECT_TOOL_RESULTS),
            semantic_block_min_confidence=normalize_block_min_confidence(
                get_str(ENV_SEMANTIC_BLOCK_MIN_CONFIDENCE, "")
            ),
            semantic_block_stages=configured_semantic_block_stages(),
            agent_security_monitor_disposition=observation_disposition(
                ENV_AGENT_SECURITY_MONITOR_DISPOSITION
            ),
            model_output_classified_disposition=observation_disposition(
                ENV_MODEL_OUTPUT_CLASSIFIED_DISPOSITION
            ),
        )
        with self._semantic_config_lock:
            self._semantic_runtime = candidate

    def load_custom_rules(self, rules) -> None:
        """加载/替换编译后的自定义规则包（方案A：规则编译下发 —— 引擎消费侧）。

        rules: List[CompiledRule]。重建 CustomRuleSet（含 ReDoS 跳过逻辑）。
        引擎保持无状态：规则由 control-plane 编译下发，引擎只消费。
        """
        from app.custom_rules import CustomRuleSet
        with self._rule_pack_lock:
            self.custom_rules = (
                rules if isinstance(rules, CustomRuleSet) else CustomRuleSet(rules)
            )

    def load_policies(self, policies) -> None:
        from app.policy_bindings import PolicySet
        if not isinstance(policies, PolicySet):
            raise ValueError("policy set is invalid")
        with self._rule_pack_lock:
            self.policies = policies

    def load_file_policy(self, policy) -> None:
        """加载文件格式管控策略。"""
        from app.file_inspector import load_file_policy
        with self._rule_pack_lock:
            load_file_policy(policy)

    def load_content_audit_exceptions(self, exceptions) -> None:
        """加载/替换编译后的内容例外（误报豁免）。

        exceptions: List[CompiledException]。规则包随规则一并下发，引擎只消费。
        例外一律生效（2.9.22），包括凭据、证件号等不可自动降级的命中（见 ExceptionSet.apply）。
        """
        from app.custom_rules import ExceptionSet
        with self._rule_pack_lock:
            self.content_exceptions = (
                exceptions
                if isinstance(exceptions, ExceptionSet)
                else ExceptionSet(exceptions)
            )

    def load_reply_policy(self, policy: ReplyPolicy) -> None:
        if not isinstance(policy, ReplyPolicy):
            raise ValueError("reply policy is invalid")
        with self._rule_pack_lock:
            self.reply_policy = policy

    def snapshot_rule_pack_state(self):
        """Atomically capture one complete runtime pack for a request."""
        from app.file_inspector import snapshot_file_policy

        with self._rule_pack_lock:
            return (
                self.custom_rules,
                self.policies,
                self.content_exceptions,
                snapshot_file_policy(),
                self.reply_policy,
                self.rule_pack_version,
            )

    @staticmethod
    def _extract_file_content_with_admission(context: Optional[dict], file_policy):
        """Input/output share file extraction, tenant admission and coverage reporting."""
        from app import feature_flags as flags
        from app.file_content_dlp_bridge import _parse_failure_finding, extract_textual_attachment_content
        from app.scan_admission import AdmissionError
        from app.scan_service import scan_service

        tenant = (context or {}).get("tenant_id") or ""
        attachments = (context or {}).get("attachments") or []
        enabled = flags.is_enabled(flags.ENV_FILE_CONTENT_DLP) and bool(attachments)
        slot = None
        try:
            if enabled:
                slot = scan_service.admission.acquire(tenant or "__internal__", timeout=0.5)
            return extract_textual_attachment_content(context, file_policy, tenant)
        except AdmissionError:
            first = attachments[0] if attachments and isinstance(attachments[0], dict) else {}
            return "", [_parse_failure_finding(first, 0, "capacity", "file-content-capacity-unavailable")]
        finally:
            if slot is not None:
                slot.release()

    @staticmethod
    def _inspection_in_scope(runtime, content_source, context=None, *, output=False):
        if output:
            return runtime.inspect_model_output
        source = str(content_source or "").strip().lower()
        # These fields come from the internal protocol parser, never from text
        # claiming to be a system message. Unknown provenance remains inspected.
        history = (context or {}).get("inspection_is_history") is True
        if source in {"assistant_history", "user_history"} or (source == "user" and history):
            return runtime.inspect_history
        if source in {"system_prompt", "system", "developer", "developer_instruction", "tool_def",
                      "agent_runtime_context", "agent_analysis_context"}:
            return runtime.inspect_builtin_context
        if source in UNTRUSTED_CONTENT_SOURCES:
            return runtime.inspect_tool_results and (not history or runtime.inspect_history)
        if source in {"user", "verified_user_input"}:
            return runtime.inspect_user_input
        return True

    def _scope_excluded(self, request_id, content, runtime, pack_version):
        return SecurityCheckResult(
            request_id=request_id, findings=[], raw_findings=[], action="allow",
            original_hash=self._hash_content(content or ""), rule_pack_version=pack_version,
            semantic_config_revision=runtime.revision, semantic_status="skipped",
            semantic_reason="inspection_scope_excluded",
        )

    def check_input(
        self,
        request_id: str,
        content: Optional[str],
        context: Optional[dict] = None,
        skip_semantic: bool = False,
        semantic_only: bool = False,
        semantic_stage: str = "input",
        agent_type: Optional[str] = None,
        content_source: Optional[str] = None,
        principal=None,
    ) -> SecurityCheckResult:
        """输入侧安全检查。

        异步旁路门控（默认两者 False = 现行为，逐字节零回归）：
        - skip_semantic=True：跑快层（含 llm_judge_opinion / 上下文 / 自定义 / 文件），
          但跳过语义块（语义检测交由异步旁路另行处理）。
        - semantic_only=True：只跑语义块，跳过所有快层 + llm_judge_opinion +
          上下文 / agent / 自定义规则 / 文件检视，仅返回语义 findings。
          仅改变检测层选择，仍严格服从 master 与 semantic_stage 阶段开关。
        - 两者皆 False：全跑。

        无论走哪条路，末尾的去重 / 内容例外 / triage / 决策链都串行执行。
        """
        if semantic_stage not in {"input", "agent"}:
            raise ValueError("semantic_stage must be input or agent")
        runtime = self.snapshot_semantic_runtime()
        custom_rules, policies, content_exceptions, file_policy, reply_policy, runtime_pack_version = (
            self.snapshot_rule_pack_state()
        )
        if not self._inspection_in_scope(runtime, content_source, context):
            return self._scope_excluded(request_id, content, runtime, runtime_pack_version)
        semantic_stage_enabled = (
            runtime.semantic_master_enabled
            and (
                runtime.semantic_input_enabled
                if semantic_stage == "input"
                else runtime.semantic_agent_enabled
            )
        )
        semantic_detector = runtime.semantic_detector
        findings: List[SecurityFinding] = []
        has_text = content is not None and content != ""
        limited_non_user_source = (
            runtime.source_aware_enabled
            and content_source in NON_USER_CONTENT_SOURCES
        )

        # Protocol source is not a trust assertion: retrieved/tool bodies may contain
        # indirect injection. Retain precision handling for framework templates/history.
        indirect_source = content_source in UNTRUSTED_CONTENT_SOURCES
        # 编程智能体的工具结果：不跑语义，状态记为“未请求”，不能产生“检测未完成”。
        coding_tool_result = (
            runtime.source_aware_enabled
            and content_source == "tool_result"
            and self._is_coding_traffic(context, agent_type)
        )
        skip_source_semantic = (
            (limited_non_user_source and not indirect_source) or coding_tool_result
        )

        # P2-2：文件/图片附件检视（懒加载，规避与 engine 的循环依赖）。
        # 红线：即使无文本（仅上送图片/文件）也必须执行，故先于文本空值早退。
        # semantic_only 路径只关心语义文本检测，不做附件检视。
        from app.file_inspector import inspect_attachments
        file_findings = (
            [] if semantic_only else inspect_attachments(context, policy=file_policy)
        )

        file_content_start = None
        file_content_end = None
        _file_text, _file_parse_failures = (
            ("", []) if semantic_only else self._extract_file_content_with_admission(context, file_policy)
        )
        file_findings.extend(_file_parse_failures)
        if _file_text:
            original_content = content or ""
            content = original_content + "\n" + _file_text
            file_content_start = len(original_content) + 1
            file_content_end = len(content)
            has_text = content is not None and content != ""

        # actor_type is only a hint derived from caller-controlled metadata.
        # Natural-language detectors use an offset-preserving text view;
        # encoded binary attachments are not words. Custom matchers and file
        # inspection retain the original content and configured actions.
        intent_content = content or ""
        scan_content = lexical_text(content or "")
        intent_base_offset = 0
        if self._is_orchestrator_notice_candidate(
            content, context, agent_type, content_source, runtime
        ):
            intent_content, intent_base_offset = (
                self._strip_orchestrator_notice_with_offset(content or "")
            )
        # 编程智能体塞进 user 消息的上下文（system-reminder、续接摘要、本地命令输出等）
        # 不是员工请求：意图类检测只看员工输入，智能体区段只做确定性检测和提示注入检测。
        # 识别只在已知编程智能体流量上生效；普通聊天发来同样的标签照常全文检测。
        agent_split = None
        if (
            runtime.source_aware_enabled
            and not limited_non_user_source
            and content_source in AGENT_CONTEXT_SCOPED_SOURCES
            and intent_content
            and self._is_coding_traffic(context, agent_type)
        ):
            limit = None
            if file_content_start is not None:
                limit = max(0, file_content_start - 1 - intent_base_offset)
            split = split_agent_context(intent_content, limit)
            if split.spans:
                agent_split = split
        employee_content = intent_content
        agent_context_content = ""
        semantic_view = None
        semantic_intent = intent_content
        if agent_split is not None:
            employee_content = agent_split.employee_view
            agent_context_content = agent_split.agent_view
            semantic_view = agent_split.compact()
            # 附件正文不参与识别（limit），紧凑视图只含员工输入；附件仍走下方语义附件分支。
            semantic_intent = semantic_view.text

        semantic_status = "not_requested"
        semantic_reason = "disabled"
        semantic_trace = None
        if coding_tool_result:
            semantic_status, semantic_reason = "not_requested", "coding_agent_tool_result"
        elif skip_source_semantic:
            semantic_status, semantic_reason = "skipped", "non_user_source"
        elif skip_semantic:
            semantic_status, semantic_reason = "skipped", "deferred"
        elif semantic_stage_enabled and has_text and not (semantic_intent or _file_text):
            semantic_status, semantic_reason = "skipped", "empty_intent_after_wrapper"

        # 无文本且无附件命中 → 维持原有 allow 早退（向后兼容）
        if not has_text and not file_findings:
            return SecurityCheckResult(
                request_id=request_id,
                findings=[],
                action="allow",
                masked_content=None,
                original_hash=self._hash_content(content or ""),
                raw_findings=[],
                rule_pack_version=runtime_pack_version,
                semantic_config_revision=runtime.revision,
                semantic_status=semantic_status,
                semantic_reason=semantic_reason,
                file_bindings=self._issue_file_binding_tokens(
                    context, "allow", [], runtime_pack_version
                ),
            )

        # —— 快层区（semantic_only 时整段跳过）——
        lexical_intent_content = lexical_text(intent_content)
        if not semantic_only:
            if has_text:
                # 已知智能体的非用户上下文只做确定性敏感信息扫描。
                # Framework contexts keep precision-oriented deterministic checks.
                # Tool results also run the independent indirect semantic block below.
                # 其余 source、未知客户端、开关关 → 全量（防伪装绕过）。
                if coding_tool_result:
                    findings.extend(self._coding_tool_result_findings(scan_content))
                elif limited_non_user_source:
                    findings.extend(self._detect_regex_pii(scan_content))
                    findings.extend(self._detect_secrets(scan_content))
                    findings.extend(self._detect_code_config(scan_content))
                    findings.extend(self._dict_findings_to_objects(self.sensitive_data.detect(scan_content)))
                    if indirect_source and intent_content:
                        # Tool and retrieved text is data, not trusted instruction.
                        # Keep the high-precision deterministic injection layer even
                        # when semantic review is disabled, saturated, or unavailable.
                        intent_findings = self._dict_findings_to_objects(
                            self.prompt_injection.detect(lexical_intent_content, **({"indirect_source": True} if indirect_source else {}))
                        )
                        findings.extend(self._rebase_intent_findings(
                            intent_findings, intent_base_offset, content or ""
                        ))
                    if content_source == "tool_result":
                        credential_findings = [
                            item
                            for item in self.content_safety.detect(lexical_intent_content)
                            if item.get("rule_id")
                            == "content_safety_debug_secret_template"
                        ]
                        findings.extend(
                            self._dict_findings_to_objects(credential_findings)
                        )
                else:
                    findings.extend(self._detect_regex_pii(scan_content))
                    findings.extend(self._detect_secrets(scan_content))
                    findings.extend(self._detect_code_config(scan_content))
                    findings.extend(self._dict_findings_to_objects(self.sensitive_data.detect(scan_content)))
                    if intent_content:
                        lexical_employee_content = (
                            lexical_intent_content if agent_split is None
                            else lexical_text(employee_content)
                        )
                        intent_findings = self._dict_findings_to_objects(
                            self.prompt_injection.detect(lexical_employee_content, **({"indirect_source": True} if indirect_source else {}))
                        )
                        if agent_split is not None:
                            # 智能体区段（@ 引用的文件、记忆等）可能夹带注入：保留与改动前
                            # 相同的确定性注入层，不新增间接外传规则，避免引入新的误报面。
                            lexical_agent_content = lexical_text(agent_context_content)
                            intent_findings.extend(self._dict_findings_to_objects(
                                self.prompt_injection.detect(lexical_agent_content)
                            ))
                            intent_findings.extend(self._dict_findings_to_objects([
                                item
                                for item in self.content_safety.detect(lexical_agent_content)
                                if item.get("rule_id") == "content_safety_debug_secret_template"
                            ]))
                        catalog_findings = self.policy_catalog.detect(lexical_employee_content, semantic_stage)
                        if (runtime.agent_security_monitor_disposition == "observe"
                                and self._is_agent_security_monitor(context, agent_type)):
                            for catalog_finding in catalog_findings:
                                if catalog_finding.get("type") == "catalog_policy":
                                    observation(catalog_finding, "agent_security_monitor_transcript",
                                                "Claude Code 安全监视器转发的会话记录")
                        intent_findings.extend(self._dict_findings_to_objects(catalog_findings))
                        intent_findings.extend(self._dict_findings_to_objects(
                            self.content_safety.detect(lexical_employee_content)
                        ))
                        # 涉密标记、隐写属于确定性检测，覆盖全文。
                        intent_findings.extend(self._dict_findings_to_objects(
                            self.data_leak.detect(lexical_intent_content)
                        ))
                        intent_findings.extend(self._dict_findings_to_objects(
                            self.prompt_stego.detect(lexical_intent_content)
                        ))
                        if agent_split is None:
                            intent_findings.extend(self._scan_transformed(intent_content))
                        else:
                            intent_findings.extend(self._scan_transformed(employee_content))
                            intent_findings.extend(
                                self._scan_transformed(agent_context_content, agent_context=True)
                            )
                        if semantic_intent:
                            intent_findings.extend(self._detect_low_resource(semantic_intent))
                            intent_findings.extend(self._llm_judge_opinion(
                                semantic_text(semantic_intent).text, findings + intent_findings, runtime
                            ))
                        findings.extend(self._rebase_intent_findings(
                            intent_findings, intent_base_offset, content or "",
                            refresh_evidence=agent_split is not None,
                        ))

        # —— 语义块 ——
        # Attachments remain data from files, even when carried by a user turn.
        # Deterministic DLP above still scans the complete combined content.
        if (
            has_text
            and semantic_stage_enabled
            and not skip_semantic
            and (not skip_source_semantic or bool(_file_text))
            and bool(semantic_intent or _file_text)
        ):
            semantic_status, semantic_reason = "completed", ""
            semantic_inputs = [(semantic_intent, content_source, context, intent_base_offset)]
            if _file_text:
                assert file_content_start is not None
                user_intent = (
                    semantic_intent if semantic_view is not None
                    else (content or "")[intent_base_offset:file_content_start - 1]
                )
                semantic_inputs = []
                if user_intent and not skip_source_semantic:
                    semantic_inputs.append((user_intent, content_source, context, intent_base_offset))
                file_context = dict(context or {})
                if content_source in {"user", "verified_user_input"} and user_intent:
                    task_bytes = user_intent.encode("utf-8")
                    task_complete = len(task_bytes) <= 8192
                    file_context.update({
                        "user_task": user_intent if task_complete else "",
                        "user_task_complete": task_complete,
                        "user_task_status": "complete" if task_complete else "too_large",
                        "user_task_sha256": hashlib.sha256(task_bytes).hexdigest(),
                    })
                semantic_inputs.append((_file_text, "file_attachment", file_context, file_content_start))

            # All semantic sources share the request's original execution budget.
            semantic_findings = []
            with cascade_trace(getattr(semantic_detector, "cascade_policy", "legacy")) as trace, \
                    execution_budget(time.monotonic() + runtime.semantic_total_timeout):
                for part_text, part_source, part_context, base_offset in semantic_inputs:
                    semantic_options = {}
                    if (isinstance(semantic_detector, SemanticDetector)
                            or part_source in UNTRUSTED_CONTENT_SOURCES
                            or getattr(semantic_detector, "uses_context_contract", False)
                            or (part_context and (part_context.get("user_task") or part_context.get("proposed_action") or part_context.get("judgment_context")))):
                        semantic_options = {"content_source": part_source, "task_context": part_context}
                    part_findings = self._dict_findings_to_objects(
                        semantic_detector.detect(part_text, semantic_stage, **semantic_options)
                    )
                    offset_map = (
                        semantic_view.original_offset
                        if semantic_view is not None and part_source != "file_attachment" else None
                    )
                    part_findings = self._rebase_intent_findings(
                        part_findings, base_offset, content or "", offset_map=offset_map
                    )
                    for finding in part_findings:
                        if part_source:
                            finding.content_source = part_source
                        if finding.type == "semantic_telemetry":
                            semantic_status = "incomplete"
                            if not semantic_reason:
                                semantic_reason = str(finding.triage.get("semantic_reason") or finding.category)
                    findings.extend(part_findings)
                    semantic_findings.extend(part_findings)
            semantic_trace = summarize_cascade(trace, semantic_findings)
            # 整次请求的完成度写进语义 finding（含 raw_findings），缓存重放据此判断能否拦截。
            stamp_semantic_run_status(semantic_findings, semantic_status, semantic_reason)

        # —— 上下文 / agent / 自定义规则 / 文件检视（semantic_only 时整段跳过）——
        if not semantic_only:
            # Agent identity is authenticated and normalized by gateway-core before
            # it reaches this internal API. Raw headers are only a compatibility
            # fallback for proxy paths that have not populated agent_type yet.
            agent_info = self.agent_detect.identify_type(
                agent_type or (context or {}).get("agent_type"),
                (context or {}).get("agent_detection_confidence", 1.0),
            )
            if agent_info is None and context and 'headers' in context:
                agent_info = self.agent_detect.identify(context.get('headers'), context)
            if agent_info:
                findings.append(SecurityFinding(
                    type="agent",
                    category=f"agent_{agent_info['agent_type']}",
                    severity="low",
                    matched_text_preview=agent_info['agent_type'],
                    rule_id=f"agent_{agent_info['agent_type']}",
                    confidence=agent_info['confidence'],
                ))
            findings.extend(self._detect_policy_context(context))
            findings.extend(self._detect_agent_layer(context, runtime))
            # P2-1：合并客户自定义规则命中（统一结果模型）
            if has_text:
                findings.extend(
                    self._filter_invalid_builtin_rule_pii(custom_rules.match(content), content)
                )
            # P2-2：合并文件检视命中（type="file"，显式 action 由 _determine_action 纳入决策）
            for finding in file_findings:
                finding.content_source = "file_attachment"
            findings.extend(file_findings)

        self._annotate_file_content_provenance(
            findings, content or "", file_content_start, file_content_end
        )
        self._annotate_message_anchor(findings, context)
        self._annotate_admin_evidence(
            findings, content or "", content_source or "unknown", semantic_stage
        )
        annotate_hit_display(findings, content or "")
        findings = self._dedupe_findings(findings)
        # P1-A：在降档/例外之前深拷一份原始 findings（证据不减量的技术参考 + 指纹缓存值）
        self._annotate_credential_assessment(findings, runtime)
        annotate_key_only_findings(findings, content or "")
        raw_findings = _copy_without_secret_text(findings)
        findings = policies.apply(findings, stage=semantic_stage, principal=principal)
        # 编码流量降级层：去重之后、决策之前按降级表就地降档（只降不升，不动）
        findings = self._apply_coding_traffic_downgrade(
            findings, context, agent_type, runtime, content=content or ""
        )
        findings = self._apply_signal_disposition(
            findings, content or "", content_source, context, agent_type, runtime
        )
        # P2-3：应用内容例外（误报豁免）—— 在去重之后、决策之前；永不降级
        # 直连路径与 /apply-context/ 共用完整例外上下文；旧 user 仍来自
        # context.user_id，新版本化 scope 只读取 PrincipalContext。
        findings = content_exceptions.apply(
            findings,
            project_id=(context or {}).get("project_id"),
            user_id=(context or {}).get("user_id"),
            principal=principal,
            tenant_id=(context or {}).get("tenant_id"),
        )
        findings = self._apply_finding_triage(content or "", findings, "input", runtime,
                                             content_source=content_source or "", task_context=context)
        findings = self._mark_ai_review_eligible(findings, runtime)
        findings = apply_evidence_downgrades(findings)
        # 语义拦截闸门：只降不升，策略选拦截也须 completed+达阈值+防护模式。
        findings = apply_semantic_enforcement(findings, policies=policies, principal=principal,
                                              stage=semantic_stage, runtime=runtime)

        action = self._determine_action(findings, runtime, context=context, principal=principal, policies=policies)
        # 文件正文命中无法整文件脱敏。策略配置的是"脱敏"而不是"阻断"：
        # 原文件照常外发，按"无法脱敏"告警（2026-09-23 定案：只有控制台配置为阻断才阻断）。
        # 消息文本自身的脱敏命中照常改写：masked_content 只覆盖消息文本，
        # 只有附件正文里的命中标记为"无法脱敏"（2.9.11 实测 N03/N10/N12/N13）。
        mask_view = content
        if action == "mask" and _file_text:
            mask_view = original_content
            if not self._split_attachment_masks(
                findings, content, _file_text, file_content_start, file_content_end,
                policies, custom_rules,
            ):
                action = self._mask_unavailable(findings)
        if action == "block" and self._should_reply(findings, reply_policy):
            reply = self.reply_gen.generate(
                self._reply_template_keys(findings), reply_policy
            )
            return SecurityCheckResult(
                request_id=request_id,
                findings=findings,
                action="reply",
                masked_content=reply,
                original_hash=self._hash_content(content or ""),
                raw_findings=raw_findings,
                rule_pack_version=runtime_pack_version,
                semantic_config_revision=runtime.revision,
                semantic_status=semantic_status,
                semantic_reason=semantic_reason,
                semantic_trace=semantic_trace,
            )
        # 文件内容 DLP 两阶段 file_id 协议（设计§10）：检测完成后，为实际读取过
        # 字节的附件签发一次性 binding token。只有网关验证上游 object=file 后，
        # 才能消费 token，把真实上游 file_id 写入 registry。
        redaction_mapping = {}
        masked_content = self._mask_content(mask_view, findings, redaction_mapping, policies, custom_rules) if action == "mask" else None
        if action == "mask" and masked_content == mask_view:
            action = self._mask_unavailable(findings)
            masked_content = None
        elif action == "mask":
            self._flag_unmaskable(findings)

        return SecurityCheckResult(
            request_id=request_id,
            findings=findings,
            action=action,
            masked_content=masked_content,
            redaction_mapping=redaction_mapping if masked_content is not None else {},
            original_hash=self._hash_content(content or ""),
            raw_findings=raw_findings,
            rule_pack_version=runtime_pack_version,
            semantic_config_revision=runtime.revision,
            semantic_status=semantic_status,
            semantic_reason=semantic_reason,
            semantic_trace=semantic_trace,
            file_bindings=self._issue_file_binding_tokens(
                context, action, findings, runtime_pack_version
            ),
        )

    def check_output(
        self,
        request_id: str,
        content: Optional[str],
        context: Optional[dict] = None,
        skip_semantic: bool = False,
        principal=None,
    ) -> SecurityCheckResult:
        """输出侧独立检测：聚焦数据外泄，不复用输入侧语义判定。

        刻意不跑 prompt_injection / 智能体识别 / 应答生成 ——
        那些是输入侧概念。输出侧只关心"回包里是否带出了不该带的东西"。
        """
        runtime = self.snapshot_semantic_runtime()
        custom_rules, policies, content_exceptions, file_policy, _reply_policy, runtime_pack_version = (
            self.snapshot_rule_pack_state()
        )
        if not self._inspection_in_scope(runtime, "model_output", context, output=True):
            return self._scope_excluded(request_id, content, runtime, runtime_pack_version)
        from app.file_inspector import inspect_attachments
        file_findings = inspect_attachments(context, policy=file_policy)
        original_content = content or ""
        file_content_start = file_content_end = None
        file_text, parse_failures = self._extract_file_content_with_admission(context, file_policy)
        file_findings.extend(parse_failures)
        if file_text:
            content = original_content + "\n" + file_text
            file_content_start = len(original_content) + 1
            file_content_end = len(content)
        for finding in file_findings:
            finding.content_source = "file_attachment"

        if not content and not file_findings:
            return SecurityCheckResult(
                request_id=request_id,
                findings=[],
                action="allow",
                masked_content=None,
                original_hash=self._hash_content(content or ""),
                raw_findings=[],
                rule_pack_version=runtime_pack_version,
            semantic_config_revision=runtime.revision,
            )

        findings: List[SecurityFinding] = []
        if content:
            scan_content = lexical_text(content)
            findings.extend(self._detect_regex_pii(scan_content))
            findings.extend(self._detect_secrets(scan_content))
            findings.extend(self._detect_code_config(scan_content))
            findings.extend(self._dict_findings_to_objects(self.sensitive_data.detect(scan_content)))
            findings.extend(self._dict_findings_to_objects(self.content_safety.detect(scan_content)))
            findings.extend(self._dict_findings_to_objects(self.data_leak.detect(scan_content)))
            findings.extend(self._dict_findings_to_objects(self.prompt_stego.detect(scan_content)))
            findings.extend(self._scan_transformed(content))
            findings.extend(
                self._filter_invalid_builtin_rule_pii(custom_rules.match(content), content)
            )
        findings.extend(file_findings)
        findings = self._narrow_output_system_command(findings, content or "")

        self._annotate_file_content_provenance(
            findings, content or "", file_content_start, file_content_end
        )
        self._annotate_message_anchor(findings, context)
        self._annotate_admin_evidence(findings, content or "", "model_output", "output")
        annotate_hit_display(findings, content or "")
        findings = self._dedupe_findings(findings)
        # P1-A：在降档/例外之前深拷一份原始 findings（证据不减量的技术参考 + 指纹缓存值）
        self._annotate_credential_assessment(findings, runtime)
        annotate_key_only_findings(findings, content or "")
        raw_findings = _copy_without_secret_text(findings)
        findings = policies.apply(findings, stage="output", principal=principal)
        findings = self._apply_coding_traffic_downgrade(
            findings, context, None, runtime, content=content or ""
        )
        findings = self._apply_signal_disposition(
            findings, content or "", "model_output", context, None, runtime
        )
        if runtime.model_output_classified_disposition == "observe":
            self._observe_model_output_classified_markers(findings, policies, principal, context)
        # 输出侧同样携带旧 scope 字段与可信 PrincipalContext。
        findings = content_exceptions.apply(
            findings,
            project_id=(context or {}).get("project_id"),
            user_id=(context or {}).get("user_id"),
            principal=principal,
            tenant_id=(context or {}).get("tenant_id"),
        )
        findings = self._apply_finding_triage(content or "", findings, "output", runtime,
                                             content_source="model_output", task_context=context)
        findings = self._mark_ai_review_eligible(findings, runtime)
        findings = apply_evidence_downgrades(findings)
        action = self._determine_action(findings, runtime, context=context, principal=principal, policies=policies)
        if action == "mask" and file_text:
            # Rewriting response text cannot sanitize attached bytes; the
            # configured action is "mask", not "block": forward and alert.
            action = self._mask_unavailable(findings)

        masked_content = None
        if action == "mask":
            masked_content = self._mask_content(content, findings, policies=policies, custom_rules=custom_rules)
            if masked_content == content:
                action = self._mask_unavailable(findings)
                masked_content = None
            else:
                self._flag_unmaskable(findings)

        return SecurityCheckResult(
            request_id=request_id,
            findings=findings,
            action=action,
            masked_content=masked_content,
            original_hash=self._hash_content(original_content),
            raw_findings=raw_findings,
            rule_pack_version=runtime_pack_version,
            semantic_config_revision=runtime.revision,
        )

    def _detect_regex_pii(self, content: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        # 手机号/身份证/银行卡在归一化视图上识别（全角、零宽、分组分隔符、+86 前缀），
        # matched_location 是原文坐标（脱敏覆盖插入的分隔符/零宽字符），raw_evidence
        # 是去分隔符后的规范值。变体写法已在 find_numeric_pii 内强制校验位。
        for candidate in find_numeric_pii(content):
            pattern_name, matched_text = candidate.category, candidate.value
            if not candidate.variant and self._should_drop_invalid_pii(pattern_name, matched_text):
                continue
            # 前面紧挨着“订单号/流水号/order id”这类标签的长数字是单号，碰巧过了校验位也不是银行卡。
            # 只在校验位校验开启时生效；校验关闭的旧模式保持原样。
            if (pattern_name == "bank_card_cn" and self.pii_checksum_enabled and self.pii_checksum_drop_invalid
                    and SERIAL_NUMBER_LABEL_BEFORE.search(content[max(0, candidate.start - 24):candidate.start])):
                continue
            findings.append(self._regex_pii_finding(
                pattern_name, matched_text, candidate.start, candidate.end
            ))
        for found in self.chinese_patterns["email"].finditer(content) if "@" in content else ():
            matched_text = found.group(0)
            if is_public_service_email(matched_text) or is_non_mailbox_at_reference(matched_text):
                continue
            if is_git_remote_reference(content, *found.span()):
                continue
            if (is_url_userinfo(content, *found.span())
                    or is_escaped_sequence_local_part(content, *found.span())):
                continue
            findings.append(self._regex_pii_finding("email", matched_text, *found.span()))
        return findings

    def _regex_pii_finding(self, pattern_name: str, matched_text: str, start: int, end: int) -> SecurityFinding:
        return SecurityFinding(
            type="pii",
            category=pattern_name,
            severity=self._get_regex_pii_severity(pattern_name),
            matched_text_preview=self._mask_preview(matched_text),
            raw_evidence=matched_text,
            matched_location=f"content[{start}:{end}]",
            evidence_kind="literal",
            rule_id=f"regex_{pattern_name}",
            confidence=self._regex_pii_confidence(pattern_name, matched_text),
        )

    def _should_drop_invalid_pii(self, pattern_name: str, match: str) -> bool:
        """校验位失败即丢弃：Luhn/GB11643 不过的纯数字串几乎必是流水号/时间戳/遥测 ID。

        仅在 pii_checksum_enabled 且 drop_invalid（默认开）下生效；
        drop_invalid 显式关闭时回退旧行为（保留 finding、置信度降 0.3）。
        """
        if not (self.pii_checksum_enabled and self.pii_checksum_drop_invalid):
            return False
        if pattern_name == "id_card_cn":
            return not validate_id_card_cn(match)
        if pattern_name == "bank_card_cn":
            return not validate_bank_card(match)
        return False

    def _filter_invalid_builtin_rule_pii(
        self, findings: List[SecurityFinding], content: str = ""
    ) -> List[SecurityFinding]:
        """让规则包中的系统内置 PII 与原生检测器服从同一确定性校验。"""
        regions = binary_regions(content) if content else []
        if regions:
            kept = []
            for finding in findings:
                span = re.fullmatch(r"content\[(\d+):(\d+)\]", finding.matched_location or "")
                if (finding.rule_id in {"rule_g_phone", "rule_g_bankcard", "rule_g_idcard", "rule_g_email", "rule_g_passport"}
                        and span and any(region.start <= int(span[1]) <= int(span[2]) <= region.end for region in regions)):
                    continue
                kept.append(finding)
            findings = kept
        numeric_metadata = non_pii_numeric_spans(content) if content else set()
        if numeric_metadata:
            checked = []
            for finding in findings:
                match = re.fullmatch(r"content\[(\d+):(\d+)\]", finding.matched_location or "")
                if (finding.rule_id in {"rule_g_phone", "rule_g_bankcard"} and match
                        and (int(match[1]), int(match[2])) in numeric_metadata):
                    continue
                checked.append(finding)
            findings = checked
        # Structural validity is independent of the checksum switch: an
        # unallocated mobile segment, URL userinfo or an escape sequence is
        # not PII whichever rule pack produced the span.
        structural = []
        for finding in findings:
            raw = finding.raw_evidence.strip()
            match = re.fullmatch(r"content\[(\d+):(\d+)\]", finding.matched_location or "")
            if finding.rule_id == "rule_g_phone" and raw and not validate_phone_cn_segment(raw):
                continue
            if (finding.rule_id == "rule_g_email" and content and match
                    and (is_url_userinfo(content, int(match[1]), int(match[2]))
                         or is_escaped_sequence_local_part(content, int(match[1]), int(match[2])))):
                continue
            structural.append(finding)
        findings = structural
        if not (self.pii_checksum_enabled and self.pii_checksum_drop_invalid):
            return findings

        numeric_containers = [
            finding.raw_evidence.strip()
            for finding in findings
            if finding.rule_id in {"rule_g_bankcard", "rule_g_idcard"}
            and finding.raw_evidence.strip()
        ]
        kept: List[SecurityFinding] = []
        for finding in findings:
            raw = finding.raw_evidence.strip()
            if (
                finding.rule_id == "rule_g_bankcard"
                and raw
                and not validate_bank_card(raw)
            ):
                continue
            if (
                finding.rule_id == "rule_g_idcard"
                and raw
                and not validate_id_card_cn(raw)
            ):
                continue
            if finding.rule_id == "rule_g_phone" and raw and any(
                raw != container and raw in container
                for container in numeric_containers
            ):
                continue
            kept.append(finding)
        return kept

    def _regex_pii_confidence(self, pattern_name: str, match: str) -> float:
        """按校验位给正则 PII 命中赋真实置信度；开关关时维持 0.95（旧行为）。"""
        if not self.pii_checksum_enabled:
            return 0.95
        if pattern_name == "id_card_cn":
            return 0.95 if validate_id_card_cn(match) else 0.3
        if pattern_name == "bank_card_cn":
            return 0.95 if validate_bank_card(match) else 0.3
        return 0.95

    def _coding_tool_result_findings(self, scan_content: str) -> List[SecurityFinding]:
        """编程智能体工具结果的确定性检出白名单：

        私钥、云密钥/API key/令牌、带真实值的明文密码与数据库连接串、证件号、银行卡号。
        手机号/邮箱/IP/地址、配置文件候选、提示注入、内容安全等一律不在此列。
        """
        findings: List[SecurityFinding] = []
        findings.extend(
            f for f in self._detect_regex_pii(scan_content)
            if f.category in CODING_TOOL_RESULT_PII
        )
        findings.extend(self._detect_secrets(scan_content))
        findings.extend(
            f for f in self._detect_code_config(scan_content)
            if f.category in CODING_TOOL_RESULT_CODE_CONFIG
        )
        findings.extend(self._dict_findings_to_objects([
            item for item in self.sensitive_data.detect(scan_content)
            if item.get("category") in CODING_TOOL_RESULT_SENSITIVE_DATA
        ]))
        findings.extend(self._dict_findings_to_objects([
            item for item in self.data_leak.detect(scan_content)
            if item.get("category") in CODING_TOOL_RESULT_DATA_LEAK
        ]))
        return findings

    def _scan_regex_layers(self, text: str, *, agent_context: bool = False) -> List[SecurityFinding]:
        """对给定文本跑正则层检测器，返回 SecurityFinding 列表。

        用于对归一化文本/解码明文做重扫。不含智能体识别、文件检视、应答生成。
        agent_context=True：编程智能体注入的上下文，不跑内容安全意图层。
        """
        text = lexical_text(text)
        findings: List[SecurityFinding] = []
        findings.extend(self._detect_regex_pii(text))
        findings.extend(self._detect_secrets(text))
        findings.extend(self._detect_code_config(text))
        findings.extend(self._dict_findings_to_objects(self.sensitive_data.detect(text)))
        findings.extend(self._dict_findings_to_objects(self.prompt_injection.detect(text)))
        if agent_context:
            findings.extend(self._dict_findings_to_objects([
                item for item in self.content_safety.detect(text)
                if item.get("rule_id") == "content_safety_debug_secret_template"
            ]))
        else:
            findings.extend(self._dict_findings_to_objects(self.content_safety.detect(text)))
        findings.extend(self._dict_findings_to_objects(self.data_leak.detect(text)))
        findings.extend(self._dict_findings_to_objects(self.prompt_stego.detect(text)))
        return findings

    def _scan_transformed(self, content: str, *, agent_context: bool = False) -> List[SecurityFinding]:
        """归一化重扫 + 解码重扫。命中 category 追加 __<origin> 以避开去重。"""
        variants: list[tuple[str, str]] = []
        if self.normalize_enabled:
            normalized = normalize_text(content)
            if normalized and normalized != content:
                variants.append(("normalized", normalized))
        if self.decode_rescan_enabled:
            for payload in decode_payloads(content):
                variants.append((f"decoded_{payload.method}", payload.text))

        out: List[SecurityFinding] = []
        for origin, text in variants:
            for finding in self._scan_regex_layers(text, agent_context=agent_context):
                finding.category = f"{finding.category}__{origin}"
                finding.matched_location = origin
                out.append(finding)
        return out

    def _detect_low_resource(self, content: str) -> List[SecurityFinding]:
        if not self.lowresource_enabled:
            return []
        signal = detect_low_resource(content)
        if signal is None:
            return []
        return [SecurityFinding(
            type="content_safety",
            category=f"lowresource_{signal.script}",
            severity="low",
            matched_text_preview=signal.preview,
            rule_id=f"lowresource_{signal.script}",
            confidence=0.5,
            rule_name="lowresource_ratio",
            rule_type="builtin",
            matched_location="lowresource",
        )]

    def _agent_finding_to_security(self, af: AgentFinding) -> SecurityFinding:
        return SecurityFinding(
            type="agent_guard",
            category=af.category,
            severity=af.severity,
            matched_text_preview=af.detail[:64],
            rule_id=af.rule_id,
            confidence=af.confidence,
            rule_name=af.rule_id,
            rule_type="builtin",
            matched_location="agent_layer",
        )

    def _detect_agent_layer(
        self,
        context: Optional[Dict],
        runtime: Optional[SemanticRuntimeSnapshot] = None,
    ) -> List[SecurityFinding]:
        runtime = runtime or self.snapshot_semantic_runtime()
        if not context:
            return []
        admission_scan = context.get("mcp_admission_scan") is True
        actions = [
            action for action in (context.get("agent_actions") or [])
            if isinstance(action, dict) and action.get("tool")
        ]
        legacy_action = context.get("agent_action")
        if isinstance(legacy_action, dict) and legacy_action.get("tool"):
            actions.append(legacy_action)
        if not self.agent_guard_enabled and not admission_scan and not actions:
            return []
        out: List[SecurityFinding] = []
        # MCP admission always runs deterministic regex scanning. Runtime
        # AgentGuard still controls semantic review, pinning and actions.
        for tool in context.get("mcp_tools", []) or []:
            name = tool.get("name", "")
            description = tool.get("description", "")
            out.extend(self._agent_finding_to_security(af)
                       for af in scan_mcp_description(name, description))
            # 语义复核层：默认关，仅在开关开时对同一描述附加 llm-judge 复核（observe-only、fail-open）。
            # 正则初筛 scan_mcp_description 始终照跑，此处只是叠加，不替换、不影响决策机。
            if self.agent_guard_enabled and runtime.mcp_poison_judge_enabled:
                out.extend(self._agent_finding_to_security(af)
                           for af in judge_mcp_description_poison(
                               name,
                               description,
                               judge_backend=runtime.judge_backend,
                               allow_private_egress=runtime.judge_allow_private_egress,
                           ))
            if self.agent_guard_enabled and "definition" in tool:
                out.extend(self._agent_finding_to_security(af)
                           for af in self._tool_pinner.check(
                               name, tool["definition"],
                               scope=str(tool.get("server_id") or tool.get("server") or "")))
        # Structured actions are authenticated gateway context and use a
        # deterministic classifier. Optional AgentGuard extras may be disabled
        # without making the enabled high_risk_action catalog policy inert.
        for action in actions:
            rec = audit_action(action["tool"], action.get("args", {}))
            if rec.high_risk:
                out.append(self._agent_finding_to_security(AgentFinding(
                    category="high_risk_action",
                    severity="high",
                    detail=f"高危动作 {rec.tool} 需人审（args_digest={rec.args_digest}）",
                    rule_id="high_risk_action",
                )))
        return out

    @staticmethod
    def _detect_policy_context(context: Optional[Dict]) -> List[SecurityFinding]:
        if not isinstance(context, dict):
            return []
        findings: List[SecurityFinding] = []
        if str(context.get("client_type") or "").strip().lower() == "api":
            findings.append(SecurityFinding(
                type="request_context",
                category="agent_direct_api_call",
                severity="low",
                matched_text_preview="direct_api",
                rule_id="context_agent_direct_api_call",
                confidence=1.0,
                rule_name="直接 API 调用",
                rule_type="builtin",
                matched_location="request_context",
                evidence_kind="contextual",
            ))
        message_index = context.get("message_index")
        if isinstance(message_index, int) and not isinstance(message_index, bool) and message_index >= 100:
            findings.append(SecurityFinding(
                type="request_context",
                category="agent_long_session",
                severity="medium",
                matched_text_preview="message_index>=100",
                rule_id="context_agent_long_session",
                confidence=1.0,
                rule_name="超长会话",
                rule_type="builtin",
                matched_location="request_context",
                evidence_kind="contextual",
            ))
        return findings

    def _llm_judge_opinion(
        self,
        content: str,
        prior_findings: Optional[List["SecurityFinding"]] = None,
        runtime: Optional[SemanticRuntimeSnapshot] = None,
    ) -> List[SecurityFinding]:
        runtime = runtime or self.snapshot_semantic_runtime()
        if runtime.llm_judge_mode != "shadow" or not content:
            return []
        hit_dicts = [
            {"matched_location": f.matched_location}
            for f in (prior_findings or []) if f.matched_location
        ]
        options = {}
        if runtime.judge_backend:
            options = {
                "judge_backend": runtime.judge_backend,
                "allow_private_egress": runtime.judge_allow_private_egress,
            }
        opinion = llm_judge(
            content,
            url=runtime.judge_url,
            model=runtime.judge_model,
            api_key=runtime.judge_api_key,
            timeout=runtime.judge_timeout,
            findings=hit_dicts,
            **options,
        )
        if opinion is None or opinion.verdict == "benign":
            return []
        return [SecurityFinding(
            type="llm_judge",
            category=f"llm_{opinion.verdict}",
            severity="low",
            matched_text_preview=opinion.reason[:64],
            raw_evidence=content,
            rule_id="llm_judge_shadow",
            confidence=0.0,
            rule_name="llm_judge_shadow",
            rule_type="builtin",
            matched_location="llm_judge",
            evidence_kind="semantic",
            evidence_reason=opinion.reason,
        )]

    def _tier1_score(
        self, content: str, runtime: Optional[SemanticRuntimeSnapshot] = None
    ) -> Optional[float]:
        """复用 reconfigure_semantic 注入的同一 Tier1Client，仅取攻击概率分。

        禁用/不可达/未注入 → None（fail-open，调用方据此跳过语义/压制）。
        classify() 返回 (prob, label) 或 None；只取 prob。永不抛异常。
        """
        runtime = runtime or self.snapshot_semantic_runtime()
        if not runtime.tier1_enabled or runtime.tier1_client is None:
            return None
        if not content:
            return None
        try:
            result = runtime.tier1_client.classify(content or "")
        except Exception as exc:  # noqa: BLE001 fail-open
            logger.warning("Tier-1 打分失败，降级跳过：%s", exc)
            return None
        return result[0] if result else None

    def check_triage(
        self, request_id: str, content: Optional[str], findings: List[Dict],
        content_source: Optional[str] = None, stage: str = "input"
    ) -> List[Dict]:
        """异步误报压制入口：对意图类 finding 在 Tier-1 判良性时调 judge_triage 标注。

        红线：默认关（fp_suppression_enabled=False）即原样返回；/pii/secret/code
        永不被碰（由 triage_service._eligible 守护）；Tier-1 None → 不压制（fail-open）。
        永不抛异常。返回标注后的 findings dict 列表（调用方序列化回 security_event）。
        """
        runtime = self.snapshot_semantic_runtime()
        resolved_content_source = str(content_source or "").strip() or None
        if resolved_content_source is None:
            finding_sources = {
                str(finding.get("content_source") or "").strip()
                for finding in findings
                if isinstance(finding, dict) and str(finding.get("content_source") or "").strip()
            }
            if len(finding_sources) == 1:
                resolved_content_source = next(iter(finding_sources))
        verified_fact = (
            resolved_content_source in triage_service.VERIFIED_CONTENT_SOURCES
            and any(f.get("type", "") in triage_service.NEVER_TRIAGE_TYPES for f in findings)
        )
        if (not runtime.fp_suppression_enabled and not verified_fact) or not findings:
            return findings
        return triage_service.apply_check_triage(
            content or "",
            findings,
            tier1_score=lambda value: self._tier1_score(value, runtime),
            low_threshold=runtime.tier1_low,
            judge={
                "url": runtime.judge_url,
                "model": runtime.judge_model,
                "api_key": runtime.judge_api_key,
                "timeout": runtime.judge_timeout,
                "judge_backend": runtime.judge_backend,
                "allow_private_egress": runtime.judge_allow_private_egress,
            },
            total_budget_seconds=runtime.triage_total_budget,
            content_source=resolved_content_source,
            stage=stage,
        )

    @staticmethod
    def _is_contextual_candidate(finding: SecurityFinding) -> bool:
        return finding.counts_as_security_finding and not finding.cannot_downgrade() and (
            finding.type == "prompt_injection"
            or finding.category == "ssrf_metadata_instruction"
            or (finding.type in {"custom", "catalog_policy"}
                and finding.category.startswith(("prompt_leak_", "injection_")))
        )

    @classmethod
    def _needs_full_reinspection(cls, runtime, finding: SecurityFinding) -> bool:
        """该命中经 AI 复核后无法由缓存重放还原：/apply-context/ 对它返回 409，网关回退全量检测。"""
        return bool(
            runtime.fp_suppression_enabled and runtime.semantic_master_enabled
            and cls._is_contextual_candidate(finding)
        )

    def _mark_ai_review_eligible(self, findings: List[SecurityFinding], runtime) -> List[SecurityFinding]:
        for finding in findings:
            if self._needs_full_reinspection(runtime, finding):
                finding.triage = {**finding.triage, AI_REVIEW_ELIGIBLE_MARK: True}
        return findings

    def _apply_finding_triage(
        self,
        content: str,
        findings: List[SecurityFinding],
        stage: str,
        runtime: Optional[SemanticRuntimeSnapshot] = None,
        *, content_source: str = "", task_context: Optional[dict] = None,
    ) -> List[SecurityFinding]:
        runtime = runtime or self.snapshot_semantic_runtime()
        contextual_review = runtime.fp_suppression_enabled and runtime.semantic_master_enabled
        shadow_review = runtime.llm_judge_mode == "shadow"
        if not (shadow_review or contextual_review) or not findings:
            return findings
        deadline = time.monotonic() + max(0.0, runtime.triage_total_budget)
        for finding in findings:
            # Protected credentials and internal fail-closed findings are
            # already authoritative. Sending them to an advisory judge can
            # only overwrite their non-downgradable evidence or waste budget.
            if finding.cannot_downgrade():
                continue
            if finding.type in {"engine_runtime", "llm_judge", "semantic_telemetry"}:
                continue
            candidate = contextual_review and self._is_contextual_candidate(finding)
            if not shadow_review and not candidate:
                continue
            # Stamp the server-selected role before any early return. A shadow
            # explanation is advisory even when its budget expires; contextual
            # review must retain its separate completion/failure semantics.
            finding.triage = {
                **finding.triage,
                "review_mode": "contextual_candidate" if candidate else "shadow",
            }
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                finding.triage = {
                    **finding.triage,
                    "review_status": "incomplete",
                    "review_reason": "triage_total_budget_exhausted",
                }
                continue
            payload = build_triage_payload(content, finding, stage,
                                           content_source=content_source, task_context=task_context)
            # A missing evidence anchor cannot support an automated correction.
            if candidate and payload["context"]["anchor_status"] != "resolved":
                finding.triage = {**finding.triage, "review_status": "incomplete", "review_reason": "evidence_anchor_missing"}
                continue
            options = {}
            if runtime.judge_backend:
                options = {
                    "judge_backend": runtime.judge_backend,
                    "allow_private_egress": runtime.judge_allow_private_egress,
                }
            opinions = []
            for pass_index in range(2 if candidate else 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                review_payload = dict(payload)
                if candidate:
                    review_payload["review_pass"] = pass_index + 1
                try:
                    judge_function = llm_candidate_judge if candidate else llm_triage_judge
                    opinion = judge_function(
                        review_payload, url=runtime.judge_url, model=runtime.judge_model,
                        api_key=runtime.judge_api_key, timeout=min(runtime.judge_timeout, remaining), **options,
                    )
                except Exception:
                    opinion = None
                opinions.append(opinion)
            triage = triage_service._merge_judge_results(opinions) if candidate else (opinions[0] if opinions else None)
            if triage is None:
                finding.triage = {**finding.triage, "review_status": "incomplete", "review_reason": "contextual_judge_unavailable"}
                continue
            finding.triage = {**finding.triage, **triage, "review_status": "completed", "review_mode": "shadow"}
            if candidate:
                finding.triage["review_mode"] = "contextual_candidate"
                finding.triage["review_status"] = "completed" if len(opinions) == 2 and all(opinions) else "incomplete"
                can_withdraw = (triage.get("verdict") == "likely_false_positive"
                        and triage.get("judge_agreement") is True
                        and len(opinions) == 2
                        and all(isinstance(item, dict) and float(item.get("confidence", 0)) >= 0.8 for item in opinions))
                if can_withdraw:
                    # Only an anchored soft rule candidate can be withdrawn.
                    # Original findings/actions are retained in raw_findings.
                    finding.triage["original_action"] = finding.action
                    finding.triage["disposition"] = "false_positive"
                    finding.counts_as_security_finding = False
                    finding.action = "allow"
                elif finding.triage.get("verdict") == "likely_false_positive":
                    finding.triage.update(verdict="needs_review", review_state="needs_review",
                                          review_reason="insufficient_evidence_for_withdrawal")
                    if finding.triage.get("judge_agreement") is True:
                        # 两轮一致判为疑似误报但证据不足以撤销：保留原判定，供证据降级降一档。
                        finding.triage["advisory_verdict"] = "likely_false_positive"
            elif finding.triage.get("verdict") == "likely_false_positive":
                # Shadow opinions explain only; APIs must not hide an active
                # finding because an advisory model used an FP label.
                finding.triage.update(advisory_verdict="likely_false_positive",
                                      verdict="needs_review", review_state="needs_review")
        return findings

    def _detect_secrets(self, content: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        for pattern_name, pattern in self.secret_patterns.items():
            for found in pattern.finditer(content):
                if not self._should_report_secret_match(
                    pattern_name, content, found):
                    continue
                matched_text = found.group(0)
                if pattern_name in {"openai_key", "anthropic_key"} and self._is_placeholder_secret(matched_text):
                    continue
                severity = self._get_secret_severity(pattern_name)
                findings.append(
                    SecurityFinding(
                        type="secret",
                        category=pattern_name,
                        severity=severity,
                        matched_text_preview=self._mask_preview(matched_text),
                        raw_evidence=matched_text,
                        matched_location=f"content[{found.start()}:{found.end()}]",
                        evidence_kind="literal",
                        rule_id=f"secret_{pattern_name}",
                        confidence=0.99,
                    )
                )
        reported = None
        for prefix, pattern in self.vendor_token_patterns:
            if prefix not in content:
                continue
            if reported is None:
                reported = [
                    tuple(int(x) for x in re.findall(r"\d+", f.matched_location)[:2])
                    for f in findings if f.category == "generic_api_key"
                ]
            for found in pattern.finditer(content):
                body = found.group("body")
                if not (re.search(r"[0-9]", body) and re.search(r"[A-Za-z]", body)
                        and self._generic_secret_entropy(body) >= 3.0):
                    continue
                if any(start < found.end() and found.start() < end for start, end in reported):
                    continue
                matched_text = found.group(0)
                findings.append(
                    SecurityFinding(
                        type="secret",
                        category="generic_api_key",
                        severity=self._get_secret_severity("generic_api_key"),
                        matched_text_preview=self._mask_preview(matched_text),
                        raw_evidence=matched_text,
                        matched_location=f"content[{found.start()}:{found.end()}]",
                        evidence_kind="literal",
                        rule_id="secret_generic_api_key",
                        confidence=0.99,
                    )
                )
                reported.append((found.start(), found.end()))
        return findings

    def _should_report_secret_match(
        self, pattern_name: str, content: str, found: re.Match[str]
    ) -> bool:
        if pattern_name == "generic_api_key":
            return self._is_credible_generic_secret(found)
        if pattern_name == "aws_secret_key":
            window_start = max(0, found.start() - AWS_SECRET_CONTEXT_WINDOW)
            window_end = min(len(content), found.end() + AWS_SECRET_CONTEXT_WINDOW)
            return bool(AWS_SECRET_KEY_CONTEXT.search(content[window_start:window_end]))
        return True

    @staticmethod
    def _generic_secret_entropy(value: str) -> float:
        counts = Counter(value)
        length = len(value)
        if length == 0:
            return 0.0
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

    @classmethod
    def _is_credible_generic_secret(cls, found: re.Match[str]) -> bool:
        value = found.groupdict().get("generic_value", "")
        normalized = value.strip().lower()
        if len(value) < 16 or value.startswith("-"):
            return False
        if normalized in GENERIC_SECRET_PLACEHOLDERS:
            return False
        if normalized.startswith("sk-") and cls._is_placeholder_secret(value):
            return False
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", value):
            return False
        if re.fullmatch(r"[A-Za-z]+(?:[_-][A-Za-z]+)+", value):
            return False
        return cls._generic_secret_entropy(value) >= 3.2

    @staticmethod
    def _seg_is_low_signal(seg: str) -> bool:
        """判断 sk- 正文单段是否"低信号"（占位/示例可能），高熵真钥体片段返回 False。"""
        if seg == "":
            return True
        if len(set(seg)) <= 2:  # xxxx / 0000 / abab 之类
            return True
        has_alpha = any(c.isalpha() for c in seg)
        has_digit = any(c.isdigit() for c in seg)
        # 字母+数字混合且去重字符数多 = 随机密钥体片段，绝不算占位（反规避一票否决）
        if has_alpha and has_digit and len(set(seg)) >= 6:
            return False
        return SK_PLACEHOLDER_WORD.match(seg) is not None or len(set(seg)) <= 3

    @classmethod
    def _is_placeholder_secret(cls, matched_text: str) -> bool:
        """sk- 密钥占位符/低熵识别：示例 key（sk-xxx/sk-.../sk-your-key）不算真钥、不 。

        判定：去掉 sk-/sk-ant- 前缀后，正文按 ``-`` ``_`` 切段，**每一段都低信号**才算占位。
        只要有一段是高熵真钥体片段（字母+数字混合、去重字符多），即判为真钥，杜绝
        ``sk-占位前缀-<真钥体>`` / ``sk-xxx<真钥体>`` 之类占位词前缀伪装绕过。
        """
        body = SK_STRIP_PREFIX.sub("", matched_text)
        if (
            SK_FIXTURE_SECRET_BODY.match(body)
            or SK_SEQUENTIAL_LIVE_FIXTURE.match(body)
            or cls._is_synthetic_sequence_fixture(body)
        ):
            return True
        if SK_ALL_FILLER.match(body):  # sk-xxxx / sk-.... / sk------
            return True
        segs = [s for s in re.split(r"[-_]", body) if s != ""]
        if not segs:
            return True
        if all(cls._seg_is_low_signal(s) for s in segs):
            return True
        # README 常见占位短语：整体不含数字，且是"多段短词"英文短语（>=3 段、每段 <=12 字符）。
        # openai/anthropic 真钥体必含数字，故此放松不会掩盖被外泄的真钥体。
        if not any(c.isdigit() for c in body):
            if len(segs) >= 3 and all(len(s) <= 12 for s in segs):
                return True
        return False

    @staticmethod
    def _is_synthetic_sequence_fixture(body: str) -> bool:
        """识别带测试语义且主体为连续序列的合成凭据。

        前缀和低熵序列必须同时成立；仅写 test/sample 不会放过随机真钥。
        至少 12 位可避免把普通英文单词误当成序列。
        """
        compact_body = re.sub(r"[-_]", "", body)
        bare_sequence = SK_BARE_SYNTHETIC_SEQUENCE.fullmatch(compact_body)
        if len(compact_body) >= 16 and bare_sequence:
            digits = bare_sequence.group("trailing_digits") or bare_sequence.group("leading_digits") or ""
            if not digits:
                return True
            if len(digits) >= 4:
                positions = [int(char) for char in digits]
                if all(positions[index] == (positions[index - 1] + 1) % 10 for index in range(1, len(positions))):
                    return True

        matched = SK_SYNTHETIC_SEQUENCE_PREFIX.match(body)
        if matched is None:
            return False
        sequence = re.sub(r"[-_]", "", body[matched.end():]).lower()
        if len(sequence) < 12:
            return False

        alphabets = ("abcdefghijklmnopqrstuvwxyz", "0123456789")
        for alphabet in alphabets:
            if any(char not in alphabet for char in sequence):
                continue
            width = len(alphabet)
            positions = [alphabet.index(char) for char in sequence]
            if all(
                positions[index] == (positions[index - 1] + 1) % width
                for index in range(1, len(positions))
            ):
                return True
        return False

    @staticmethod
    def _is_coding_placeholder_secret(finding: SecurityFinding) -> bool:
        if finding.rule_id != "secret_aws_access_key":
            return False
        token = (finding.raw_evidence or "").strip().upper()
        if token in AWS_OFFICIAL_EXAMPLE_ACCESS_KEYS:
            return True
        if len(token) != 20:
            return False

        # AWS access-key IDs have a four-character type prefix. A remaining
        # 16-character body made from an exact 1-4 character cycle is an
        # unmistakable fixture placeholder, not random credential material.
        body = token[4:]
        return any(
            len(body) % width == 0
            and body == body[:width] * (len(body) // width)
            for width in range(1, 5)
        )

    def _detect_code_config(self, content: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        for pattern_name, pattern in self.code_patterns.items():
            for found in pattern.finditer(content):
                matched_text = found.group(0)
                if not self._should_report_code_config_match(pattern_name, matched_text):
                    continue
                severity = self._get_code_severity(pattern_name)
                findings.append(
                    SecurityFinding(
                        type="code_config",
                        category=pattern_name,
                        severity=severity,
                        matched_text_preview=self._mask_preview(matched_text[:50]),
                        raw_evidence=matched_text,
                        matched_location=f"content[{found.start()}:{found.end()}]",
                        evidence_kind="literal",
                        rule_id=f"code_{pattern_name}",
                        confidence=0.85,
                    )
                )
        return findings

    def _should_report_code_config_match(self, pattern_name: str, matched_text: str) -> bool:
        if pattern_name not in {"config_file", "env_file"}:
            return True
        return has_literal_sensitive_config(matched_text)

    def _dedupe_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        seen = set()
        deduped: List[SecurityFinding] = []
        for finding in findings:
            if finding.type == "semantic_attack":
                # Different windows can contain different verdicts for the same
                # category. An earlier observation must not erase a later attack.
                key = (
                    finding.type, finding.category, finding.matched_text_preview,
                    finding.matched_location, finding.counts_as_security_finding,
                    finding.message_index, finding.attachment_index,
                )
            elif (
                finding.type == "custom"
                and finding.action == "mask"
                and finding.matched_location
            ):
                # Equal sensitive values at different offsets need distinct
                # spans; otherwise later occurrences escape masking.
                key = (
                    finding.type,
                    finding.category,
                    finding.matched_text_preview,
                    finding.source_rule_id or finding.rule_id,
                    finding.matched_location,
                )
            else:
                key = (
                    finding.type,
                    finding.category,
                    finding.matched_text_preview,
                )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    @staticmethod
    def _model_output_natively_declared(context: Optional[dict], principal) -> bool:
        """网关原生路径声明的模型生成文字（契约 a、b）；拿不准一律不认，照 2.9.20。

        只认网关送来的可信 PrincipalContext：入口是 gateway_api，身份来源不是反代、正代；context.source
        不带 proxy。声明只有两种：output_projection=model_text（模型回答正文、思考文字），或
        model_tool_arguments 且 tool_may_egress 是布尔 False（网关只对本地文件工具判 False，shell 命令一律 True）。
        上下文带附件时附件文字（含旧 OCR 拼接）没有可靠的来源标注，整条不认。
        """
        if not isinstance(principal, PrincipalContext):
            return False
        if principal.entry_point != MODEL_OUTPUT_NATIVE_ENTRY_POINT:
            return False
        if principal.identity_source in MODEL_OUTPUT_PROXY_IDENTITY_SOURCES:
            return False
        if not isinstance(context, dict):
            return False
        source = context.get("source")
        if source is not None and (not isinstance(source, str) or "proxy" in source.lower()):
            return False
        if context.get("attachments"):
            return False
        projection = context.get("output_projection")
        if projection == "model_text":
            return True
        return projection == "model_tool_arguments" and context.get("tool_may_egress") is False

    @staticmethod
    def _relaxable_classified_policy(policy) -> bool:
        """可放宽的内置密级策略：编码就是 MODEL_OUTPUT_CLASSIFIED_POLICY_CODE、无匹配规则、能力只有中英文密级两项。"""
        return (
            policy is not None
            and policy.policy_code == MODEL_OUTPUT_CLASSIFIED_POLICY_CODE
            and not policy.matcher_rule_id
            and bool(policy.capabilities)
            and all(cap.category in MODEL_OUTPUT_CLASSIFIED_CATEGORIES for cap in policy.capabilities)
        )

    def _observe_model_output_classified_markers(
        self,
        findings: List[SecurityFinding],
        policies,
        principal,
        context: Optional[dict],
    ) -> None:
        """2.9.21：网关原生路径声明的模型输出里，中英文密级标记只留证，不拦截、不计入告警。

        现场拦下的是模型回答、本地写文件的工具参数里模型生成的“CONFIDENTIAL”“机密”，不是本单位文件往外走。
        反代、正代会把文件内容、知识库、会话历史送进输出检查，客户策略要照常生效，所以只在下列条件全满足时留证：
        - 网关原生路径的声明（_model_output_natively_declared）；
        - 内置检测器的中英文密级命中，正文来自模型输出（附件正文除外）；
        - 在套策略、编码画像降级、信号处置之后按每份策略副本判断：可放宽的内置密级策略的副本留证，客户策略
          副本照常；没有策略命中的，当前主体可见、启用中的客户策略在输出阶段都没声明该类别时才留证（客户 all
          组合没凑齐留下的证据照 2.9.20 记 audit）；
        - 同一次输出里没有其他计入的脱敏（mask）命中：有的话密级照 2.9.20 拦。否则身份证号等改由各自的 mask
          策略处置，回答正文变成脱敏放行，Messages 原生 tool_use 参数脱敏回写不了还会原样转发。其他命中是 block
          的本来就拦、只是 audit 的不改正文，密级照旧留证。
        输入方向（含客户端提供的历史助手消息）不经过这里。
        """
        if not findings or not self._model_output_natively_declared(context, principal):
            return
        if any(
            finding.category not in MODEL_OUTPUT_CLASSIFIED_CATEGORIES
            and finding.counts_as_security_finding is not False
            and finding.action == "mask"
            for finding in findings
        ):
            return
        all_policies = tuple(getattr(policies, "policies", ()) or ())
        by_code = {policy.policy_code: policy for policy in all_policies}
        customer_categories: set = set()
        customer_rule_ids: set = set()
        for policy in all_policies:
            if not policy.enabled or self._relaxable_classified_policy(policy):
                continue
            if policy.subject_binding is not None and not policy.subject_binding.matches(principal):
                continue
            if policy.matcher_rule_id:
                customer_rule_ids.add(policy.matcher_rule_id)
                continue
            customer_categories.update(cap.category for cap in policy.stage_capabilities("output"))
        for finding in findings:
            detector_rule_id = finding.source_rule_id or finding.rule_id
            if (
                finding.category not in MODEL_OUTPUT_CLASSIFIED_CATEGORIES
                or finding.type != "data_leak"
                or detector_rule_id not in MODEL_OUTPUT_CLASSIFIED_RULE_IDS
                or finding.content_source != "model_output"
            ):
                continue
            if finding.policy_code:
                if not self._relaxable_classified_policy(by_code.get(finding.policy_code)):
                    continue
            elif finding.category in customer_categories or detector_rule_id in customer_rule_ids:
                continue
            finding.counts_as_security_finding = False
            finding.action = "allow"
            finding.evidence_reason = "留证原因：" + MODEL_OUTPUT_CLASSIFIED_LABEL
            triage = {key: value for key, value in finding.triage.items() if key != "severity_explanation"}
            triage["disposition"] = "observation"
            triage["disposition_reason"] = MODEL_OUTPUT_CLASSIFIED_REASON
            finding.triage = triage

    def _apply_coding_traffic_downgrade(
        self,
        findings: List[SecurityFinding],
        context: Optional[dict],
        agent_type: Optional[str] = None,
        runtime: Optional[SemanticRuntimeSnapshot] = None,
        content: Optional[str] = None,
    ) -> List[SecurityFinding]:
        """编码流量降级层：命中降级表的 finding 就地降 severity（只降不升）。

        原始严重度记入 severity_original 留证； finding 永不降级。
        开关（默认关）不开、或流量画像不是编码流量时原样返回。
        """
        runtime = runtime or self.snapshot_semantic_runtime()
        if not runtime.coding_traffic_downgrade_enabled or not findings:
            return findings
        if not self._is_coding_traffic(context, agent_type):
            return findings
        for finding in findings:
            if finding.cannot_downgrade():
                continue
            detector_rule_id = finding.source_rule_id or finding.rule_id
            if self._is_agent_tool_attack_signal(detector_rule_id, content or ""):
                triage = dict(finding.triage)
                triage["cannot_downgrade"] = True
                triage["cannot_downgrade_reason"] = "agent_tool_attack_signal"
                finding.triage = triage
                continue
            target = CODING_TRAFFIC_DOWNGRADE_MAP.get(detector_rule_id)
            if target is None:
                continue
            # 候选判断以检测器级别为准：告警级别已取策略级别，不能再据此判断是否编码候选。
            detector_level = finding.triage.get("detector_severity", finding.severity)
            if SEVERITY_RANK.get(target, 0) >= SEVERITY_RANK.get(detector_level, 0):
                continue
            finding.severity_original = finding.severity
            if SEVERITY_RANK.get(target, 0) < SEVERITY_RANK.get(finding.severity, 0):
                before = finding.severity
                finding.severity = target
                if not finding.triage.get("severity_downgrade_reason"):
                    # 与任务 5 的约定一致：级别被压低过就写原因与降级前级别，证据降级据此跳过。
                    finding.triage = {**finding.triage,
                                      "severity_downgrade_reason": "编码助手流量，告警级别按编码场景下调",
                                      "severity_before_downgrade": before}
        return findings

    def _apply_signal_disposition(
        self,
        findings: List[SecurityFinding],
        content: Optional[str],
        content_source: Optional[str],
        context: Optional[dict],
        agent_type: Optional[str] = None,
        runtime: Optional[SemanticRuntimeSnapshot] = None,
    ) -> List[SecurityFinding]:
        """把没有行为或影响证据的候选标成 observation。

        finding 仍原样返回并进入请求级技术留证；`counts_as_security_finding`
        是事件边界，动作决策和安全告警持久化必须忽略显式 false 的 finding。
        真密钥、文件风险和未被编码画像降档的用户侧证据保持原语义。
        """
        runtime = runtime or self.snapshot_semantic_runtime()
        non_user_context = (
            runtime.source_aware_enabled
            and content_source in NON_USER_CONTENT_SOURCES
        )
        coding_context = (
            runtime.coding_traffic_downgrade_enabled
            and self._is_coding_traffic(context, agent_type)
        )

        for finding in findings:
            # File findings must not inherit the enclosing user turn's exceptions.
            semantic_source = finding.content_source or content_source
            if semantic_source == "verified_user_input":
                semantic_source = "user"
            reason = ""
            detector_rule_id = finding.source_rule_id or finding.rule_id

            configured_action = str(finding.action or "").strip().lower()
            if configured_action in {"block", "mask", "reply"}:
                # Source metadata may reduce unsupported detector candidates, but
                # it cannot override an enforcing customer decision.
                # raw_findings already retains the pre-policy evidence.
                continue
            inventory_only = (
                finding.type == "agent"
                or finding.category in AGENT_INVENTORY_CATEGORIES
            )
            if inventory_only and configured_action not in {"block", "mask", "reply"}:
                reason = "agent_inventory_metadata"
            elif (
                coding_context
                and finding.type == "secret"
                and self._is_coding_placeholder_secret(finding)
            ):
                reason = "coding_context_placeholder_secret"
            elif finding.severity_original is not None:
                # 只有命中显式降档表的编码候选才进入此分支；真密钥等
                # cannot_downgrade finding 不会产生 severity_original。
                reason = "coding_context_candidate"
            elif (
                coding_context
                and semantic_source != "user"
                and semantic_source not in UNTRUSTED_CONTENT_SOURCES
                and finding.type == "semantic_attack"
                and not finding.cannot_downgrade()
            ):
                reason = "coding_context_semantic_candidate"
            elif (
                coding_context
                and semantic_source == "user"
                and finding.type == "semantic_attack"
                and not finding.cannot_downgrade()
                and not self._has_explicit_semantic_attack_anchor(content or "")
            ):
                reason = "coding_user_semantic_unanchored"
            elif finding.cannot_downgrade():
                if (
                    non_user_context
                    and self._is_verified_fixture_secret(finding)
                    and self._is_non_user_fixture_secret(finding, content or "")
                ):
                    reason = "non_user_fixture_secret"
                else:
                    continue
            elif non_user_context and self._is_non_user_fixture_secret(
                finding, content or ""
            ):
                reason = "non_user_fixture_secret"
            elif non_user_context and self._is_non_user_secret_observation(finding):
                # system/tool/assistant-history 中出现一个真实格式的凭据，只能证明
                # 智能体内部上下文接触过该值，不能证明已经向用户或外部目标泄露。
                # 真正的敏感文件读取、外发、越权调用由独立行为规则继续告警。
                reason = "non_user_secret_without_exfiltration"
            elif non_user_context and (
                finding.type in {"pii", "code_config"}
                or finding.category.startswith("pii_")
                or detector_rule_id in BUILTIN_PII_RULE_IDS
            ):
                reason = "non_user_context"

            if not reason:
                continue

            finding.counts_as_security_finding = False
            finding.action = "allow"
            triage = dict(finding.triage)
            triage["disposition"] = "observation"
            triage["disposition_reason"] = reason
            finding.triage = triage

        return findings

    def _is_non_user_fixture_secret(self, finding: SecurityFinding, content: str) -> bool:
        detector_rule_id = finding.source_rule_id or finding.rule_id
        is_secret = (
            finding.type == "secret"
            or detector_rule_id.startswith("secret_")
            or detector_rule_id == "content_safety_debug_secret_template"
            or finding.category in self.secret_patterns
        )
        if not is_secret or not content:
            return False
        window = self._finding_context_window(content, finding, 120)
        raw_evidence = finding.raw_evidence or ""
        context_only = (
            window.replace(raw_evidence, " ") if raw_evidence else window
        )
        if SECRET_FIXTURE_CONTEXT_RE.search(context_only) is not None:
            return True

        # Structured evaluation samples may place the id/kind declaration
        # farther from the matched value than the local context window.
        structured_window = self._finding_context_window(content, finding, 512)
        structured_only = (
            structured_window.replace(raw_evidence, " ")
            if raw_evidence
            else structured_window
        )
        if (
            SECRET_FIXTURE_STRUCTURE_RE.search(structured_only) is not None
            and SECRET_FIXTURE_ASSERTION_RE.search(structured_only) is not None
        ):
            return True
        return (
            SECRET_FIXTURE_ID_RE.search(structured_only) is not None
            and SECRET_FIXTURE_KIND_RE.search(structured_only) is not None
        )

    def _is_non_user_secret_observation(self, finding: SecurityFinding) -> bool:
        """凭据字面值不是泄露行为；非用户上下文缺少外发证据时仅留行为记录。"""
        detector_rule_id = finding.source_rule_id or finding.rule_id
        return (
            finding.type == "secret"
            or detector_rule_id.startswith("secret_")
            or finding.category in self.secret_patterns
        )

    @classmethod
    def _is_verified_fixture_secret(cls, finding: SecurityFinding) -> bool:
        """Allow only deterministic official or short-cycle placeholder values."""
        if cls._is_coding_placeholder_secret(finding):
            return True
        token = (finding.raw_evidence or "").strip()
        match = re.fullmatch(r"gh[pousr]_([A-Za-z0-9]{12,})", token, re.I)
        if match is None:
            return False
        body = match.group(1).lower()
        return any(
            len(body) % width == 0
            and body == body[:width] * (len(body) // width)
            for width in range(1, 5)
        )

    def _finding_context_window(
        self, content: str, finding: SecurityFinding, radius: int
    ) -> str:
        location_match = re.match(r"^content\[(\d+):(\d+)\]$", finding.matched_location or "")
        if not location_match:
            return content[: min(len(content), radius * 2)]
        start, end = map(int, location_match.groups())
        if not (0 <= start <= end <= len(content)):
            return content[: min(len(content), radius * 2)]
        window_start = max(0, start - radius)
        window_end = min(len(content), end + radius)
        return content[window_start:window_end]

    def _narrow_output_system_command(
        self, findings: List[SecurityFinding], content: str
    ) -> List[SecurityFinding]:
        """模型输出里的操作指导（以管理员身份运行、sudo 安装、打开终端执行普通命令）不算
        系统命令攻击指令：按输出侧判定重估，非危险操作整条去掉，削弱防护的部署写法降为 medium。
        员工输入侧不经过这里，判定不变。"""
        rule_id = "content_safety_illegal_system_command_instructions"
        if not any(f.rule_id == rule_id for f in findings):
            return findings
        assessment = self.content_safety.output_system_command_assessment(lexical_text(content))
        if assessment is None:
            return [f for f in findings if f.rule_id != rule_id]
        severity = assessment[1]
        for finding in findings:
            if finding.rule_id == rule_id and SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK[severity]:
                finding.triage = {**(finding.triage or {}), "output_ops_guidance_severity_original": finding.severity,
                                  "downgrade_reason": "model_output_ops_guidance"}
                finding.severity = severity
        return findings

    @staticmethod
    def _is_agent_tool_attack_signal(rule_id: str, content: str) -> bool:
        if rule_id == "content_safety_ssrf_metadata_instruction":
            return bool(AGENT_TOOL_SSRF_METADATA_RE.search(content or ""))
        if rule_id == "content_safety_illegal_system_command_instructions":
            return bool(AGENT_TOOL_RISKY_COMMAND_RE.search(content or ""))
        return False

    def _is_agent_security_monitor(self, context: Optional[dict], agent_type: Optional[str]) -> bool:
        """Claude Code's auto-mode security monitor replays the session transcript.

        The gateway marks it (agent_request_kind); the engine also requires the
        authenticated client type to be claude-code. Only keyword-combination
        findings change disposition; every detector still runs.
        """
        ctx = context or {}
        if str(ctx.get("agent_request_kind") or "") != AGENT_SECURITY_MONITOR_KIND:
            return False
        return any(self._normalize_agent_type(candidate) == "claude-code"
                   for candidate in (agent_type, ctx.get("agent_type")))

    def _is_coding_traffic(self, context: Optional[dict], agent_type: Optional[str]) -> bool:
        """流量画像判定，三路互补：
        C 路正向代理 endpoint_kind=coding / 反向代理 access_type=ai_ide /
        A 路 chat 请求体顶层 agent_type 属于编码 agent 集合。
        """
        ctx = context or {}
        if str(ctx.get("endpoint_kind") or "").strip().lower() == "coding":
            return True
        if str(ctx.get("access_type") or "").strip().lower() == "ai_ide":
            return True
        for candidate in (agent_type, ctx.get("agent_type")):
            if self._normalize_agent_type(candidate) in CODING_AGENT_TYPES:
                return True
        return False

    @staticmethod
    def _has_explicit_semantic_attack_anchor(content: str) -> bool:
        text = content or ""
        if SEMANTIC_ATTACK_STRONG_ANCHOR_RE.search(text):
            return True
        if SEMANTIC_ATTACK_META_DISCUSSION_RE.search(text):
            return False
        if not SEMANTIC_ATTACK_ANCHOR_RE.search(text):
            return False
        return bool(SEMANTIC_ATTACK_DIRECTIVE_ANCHOR_RE.search(text))

    def _is_known_agent(self, agent_type: Optional[str], context: Optional[dict]) -> bool:
        """已知编码 agent 判定：agent_type（或 context.agent_type）归一化后命中 CODING_AGENT_TYPES。

        契约第 11 条：已知 agent 判定即 context.agent_type 命中引擎 CODING_AGENT_TYPES。
        """
        ctx = context or {}
        for candidate in (agent_type, ctx.get("agent_type")):
            if self._normalize_agent_type(candidate) in CODING_AGENT_TYPES:
                return True
        return False

    def _is_orchestrator_notice_candidate(
        self,
        content: Optional[str],
        context: Optional[dict],
        agent_type: Optional[str],
        content_source: Optional[str],
        runtime: SemanticRuntimeSnapshot,
    ) -> bool:
        if not runtime.source_aware_enabled or content_source != "user":
            return False
        if not self._is_known_agent(agent_type, context):
            return False
        if str((context or {}).get("actor_type") or "") != ORCHESTRATOR_NOTICE_ACTOR:
            return False
        return ORCHESTRATOR_NOTICE_PATTERN.match(content or "") is not None

    @staticmethod
    def _strip_orchestrator_notice(content: str) -> str:
        """Remove only the exact harmless wrapper and return the remainder.

        This intentionally does not normalize or search for individual
        clauses. If text is injected inside the wrapper, the pattern does not
        match and the full message is inspected.
        """
        return SecurityEngine._strip_orchestrator_notice_with_offset(content)[0]

    @staticmethod
    def _strip_orchestrator_notice_with_offset(content: str) -> tuple[str, int]:
        match = ORCHESTRATOR_NOTICE_PATTERN.match(content)
        if match is None:
            return content, 0
        remainder = content[match.end():]
        leading_chars = len(remainder) - len(remainder.lstrip())
        return remainder.strip(), match.end() + leading_chars

    @staticmethod
    def _rebase_intent_findings(
        findings: List[SecurityFinding], base_offset: int, full_content: str,
        *, refresh_evidence: bool = False, offset_map=None,
    ) -> List[SecurityFinding]:
        """把意图视图里的偏移换算回原文。

        offset_map：视图不是原文前缀切片时（智能体区段紧凑视图），先映射到意图文本偏移。
        refresh_evidence：视图与原文等长但有空白遮盖时，命中原文要从原文重新截取。
        """
        if base_offset <= 0 and not refresh_evidence and offset_map is None:
            return findings
        location_pattern = re.compile(r"^content\[(\d+):(\d+)\]$")
        for finding in findings:
            match = location_pattern.fullmatch(finding.matched_location or "")
            if match is None:
                continue
            start, end = map(int, match.groups())
            if offset_map is not None:
                mapped_start = offset_map(start)
                mapped_end = offset_map(end, end=True)
                if mapped_start is None or mapped_end is None:
                    finding.matched_location = "content[unavailable]"
                    finding.raw_evidence = ""
                    continue
                start, end = mapped_start, mapped_end
            start += base_offset
            end += base_offset
            if not (0 <= start < end <= len(full_content)):
                finding.matched_location = "content[unavailable]"
                finding.raw_evidence = ""
                continue
            finding.matched_location = f"content[{start}:{end}]"
            finding.raw_evidence = full_content[start:end]
        return findings

    @staticmethod
    def _annotate_admin_evidence(
        findings: List[SecurityFinding],
        content: str,
        content_source: str,
        stage: str,
    ) -> None:
        """补齐管理员证据元数据；不改变面向普通链路的脱敏摘要。"""
        location_pattern = re.compile(r"^content\[(\d+):(\d+)\]$")
        for finding in findings:
            if not finding.content_source:
                finding.content_source = content_source

            if finding.type == "semantic_attack":
                finding.evidence_kind = "semantic"
                if not finding.raw_evidence:
                    finding.raw_evidence = content
                if not finding.evidence_reason:
                    finding.evidence_reason = str(
                        finding.triage.get("reason") or finding.redacted_evidence
                    )
                continue

            if finding.type in {
                "semantic_telemetry", "engine_runtime", "llm_judge"
            }:
                finding.evidence_kind = "runtime"
                if not finding.evidence_reason:
                    finding.evidence_reason = (
                        finding.redacted_evidence or finding.matched_text_preview
                    )
                continue

            location_match = location_pattern.match(finding.matched_location)
            if not finding.raw_evidence and location_match:
                start, end = map(int, location_match.groups())
                if 0 <= start <= end <= len(content):
                    finding.raw_evidence = content[start:end]

            # 告警证据必须能独立交付，不能依赖普通内容留存是否开启。只保存命中点
            # 前后各 500 字符，既保留完整语义上下文，也避免把整段超长工具输出塞入事件。
            if not finding.evidence_context and location_match:
                start, end = map(int, location_match.groups())
                if 0 <= start <= end <= len(content):
                    finding.evidence_context = evidence_context_for(content, start, end)

            if finding.raw_evidence:
                finding.evidence_kind = finding.evidence_kind or "literal"
                finding.evidence_reason = finding.evidence_reason or (
                    f"规则在{finding.matched_location or stage}命中上述原文"
                )
            else:
                finding.evidence_kind = finding.evidence_kind or "contextual"
                finding.evidence_reason = finding.evidence_reason or (
                    finding.redacted_evidence
                    or finding.matched_text_preview
                    or finding.rule_name
                )

    @staticmethod
    def _annotate_file_content_provenance(
        findings: List[SecurityFinding],
        content: str,
        file_content_start: Optional[int],
        file_content_end: Optional[int],
    ) -> None:
        """保留拼接正文的来源及附件序号，避免附件命中被归为用户文本。"""
        if file_content_start is None or file_content_end is None:
            return
        location_pattern = re.compile(r"^content\[(\d+):(\d+)\]")
        anchors = list(
            re.finditer(
                r"\[attachment:(\d+) file:[^\]]*\]",
                content[file_content_start:file_content_end],
            )
        )
        attachment_ranges = [
            (
                file_content_start + anchor.start(),
                file_content_start + (
                    anchors[index + 1].start()
                    if index + 1 < len(anchors)
                    else file_content_end - file_content_start
                ),
                int(anchor.group(1)),
            )
            for index, anchor in enumerate(anchors)
        ]
        for finding in findings:
            match = location_pattern.match(finding.matched_location or "")
            if match is None:
                continue
            start, end = map(int, match.groups())
            if start < file_content_end and end > file_content_start:
                finding.content_source = "file_attachment"
                if finding.attachment_index is None:
                    for range_start, range_end, attachment_index in attachment_ranges:
                        if start < range_end and end > range_start:
                            finding.attachment_index = attachment_index
                            break

    @staticmethod
    def _normalize_agent_type(value: Any) -> str:
        """与 shared-go agentdetect 的 normalize 同构：小写、下划线归连字符、压空白。"""
        normalized = str(value or "").strip().lower().replace("_", "-")
        return "-".join(normalized.split())

    @staticmethod
    def _annotate_message_anchor(
        findings: List[SecurityFinding], context: Optional[dict]
    ) -> None:
        """用可信内部 context 为本次检测结果补结构化消息锚点。"""
        if not isinstance(context, dict):
            return
        message_index = context.get("message_index")
        if isinstance(message_index, bool) or not isinstance(message_index, int):
            message_index = None
        message_role = context.get("message_role")
        if not isinstance(message_role, str):
            message_role = ""
        for finding in findings:
            if finding.message_index is None:
                finding.message_index = message_index
            if not finding.message_role:
                finding.message_role = message_role

    def _dict_findings_to_objects(self, dict_findings: List[Dict]) -> List[SecurityFinding]:
        """Convert dict findings to SecurityFinding objects"""
        result = []
        for f in dict_findings:
            result.append(SecurityFinding(
                type=f.get("type", "unknown"),
                category=f.get("category", ""),
                severity=f.get("severity", "low"),
                matched_text_preview=f.get("matched_text_preview", ""),
                rule_id=f.get("rule_id", ""),
                rule_name=f.get("rule_name", ""),
                rule_type=f.get("rule_type", "builtin"),
                confidence=f.get("confidence", 0.0),
                action=f.get("action", ""),
                counts_as_security_finding=f.get("counts_as_security_finding", True),
                matched_location=f.get("matched_location", ""),
                redacted_evidence=f.get("redacted_evidence", ""),
                exception_id=f.get("exception_id", ""),
                triage=f.get("triage", {}),
                raw_evidence=f.get("raw_evidence", ""),
                evidence_kind=f.get("evidence_kind", ""),
                evidence_reason=f.get("evidence_reason", ""),
                message_index=f.get("message_index"),
                message_role=f.get("message_role", ""),
                attachment_index=f.get("attachment_index"),
            ))
        return result

    @staticmethod
    def _reply_template_keys(findings: List[SecurityFinding]) -> List[str]:
        keys: List[str] = []
        for finding in findings:
            for value in (finding.policy_scene, finding.type):
                if value and value not in keys:
                    keys.append(value)
        return keys

    @staticmethod
    def _should_reply(findings: List[SecurityFinding], policy: ReplyPolicy) -> bool:
        """开启固定回复后，所有阻断都用固定回复（2.9.22 设计 5.4）。

        原先凭据、证件号等严重或不可降级命中强制硬拦、不代答；用户 11-17 决定去掉。
        没有专属模板的类型由 ReplyGenerator 落到 default 模板。
        """
        return bool(policy.enabled)

    def _get_regex_pii_severity(self, pattern_name: str) -> str:
        severity_map = {
            "phone_cn": "medium",
            "id_card_cn": "high",
            "bank_card_cn": "high",
            "email": "low",
        }
        return severity_map.get(pattern_name, "medium")

    def _get_secret_severity(self, pattern_name: str) -> str:
        severity_map = {
            "aws_access_key": "critical",
            "aws_secret_key": "critical",
            "github_token": "critical",
            "generic_api_key": "high",
            "jwt_token": "high",
            "openai_key": "critical",
            "anthropic_key": "critical",
        }
        return severity_map.get(pattern_name, "high")

    def _get_code_severity(self, pattern_name: str) -> str:
        severity_map = {
            "env_file": "medium",
            "openssh_private_key": "critical",
            "ssh_private_key": "critical",
            "config_file": "medium",
        }
        return severity_map.get(pattern_name, "medium")

    def _issue_file_binding_tokens(self, context, action, findings, policy_version):
        """Issue opaque tokens for scanned bytes; do not trust client file_ids.

        The gateway may consume these tokens only after receiving a real
        upstream ``object=file`` response and then calls the bind endpoint.
        """
        if not isinstance(context, dict):
            return []
        attachments = context.get("attachments")
        if not isinstance(attachments, list):
            return []
        if str(action or "").lower() == "reply":
            return []
        try:
            from app.scan_service import scan_service
        except Exception:
            return []
        import base64

        tenant = str(context.get("tenant_id") or "")
        subject = str(context.get("user_id") or "")
        provider = str(context.get("provider") or "")
        if not tenant:
            return []
        verdict = str(action or "allow").lower()
        if verdict not in ("allow", "audit", "quarantine", "pending"):
            verdict = "audit"
        issued = []
        for attachment in attachments:
            if not isinstance(attachment, dict):
                continue
            # A client-supplied reference is never trusted or rebound merely
            # because bytes were also included in the same request.
            if any(attachment.get(key) for key in ("file_id", "reference_id")):
                continue
            data = None
            if "data_base64" in attachment:
                raw = attachment.get("data_base64")
                if not isinstance(raw, str):
                    continue
                try:
                    data = base64.b64decode(raw, validate=True)
                except Exception:
                    continue
            elif attachment.get("object_id") and tenant:
                try:
                    store = scan_service.store
                    if store is not None:
                        data = store.read_bytes(str(attachment["object_id"]), tenant)
                except Exception:
                    continue
            if data is None:
                continue
            digest = hashlib.sha256(data).hexdigest()
            supplied_digest = str(attachment.get("sha256") or "").strip().lower()
            if supplied_digest and supplied_digest != digest:
                continue
            token = scan_service.registry.issue_binding_token(
                tenant=tenant,
                subject=subject,
                provider=provider,
                sha256=digest,
                verdict=verdict,
                policy_version=policy_version,
                engine_build=self.engine_build,
            )
            if token:
                issued.append(FileBindingToken(token=token, sha256=digest))
        return issued

    @staticmethod
    def _is_runtime_enforcement(finding):
        # A failed mask/inspection may still enforce its configured fail-closed
        # contract without claiming that the inspected content is an attack.
        return (finding.evidence_kind == "runtime"
                and finding.type in {"regex_timeout", "custom_scan_incomplete", "file"}
                and finding.category in {"custom_regex_timeout", "custom_scan_incomplete", "file_unknown_type"}
                and finding.action in {"block", "quarantine"})

    @staticmethod
    def _is_runtime_evidence(finding):
        """运行时留证：未知类型文件按文件策略“告警放行”（2.9.22 缺省）或被例外降为 audit。

        不算安全命中、也不执行，但要参与决策，使结果至少留 audit。
        """
        return (finding.evidence_kind == "runtime" and finding.type == "file"
                and finding.category == "file_unknown_type" and finding.action in {"alert", "audit"})

    @classmethod
    def _counts_for_decision(cls, finding):
        """参与 allow/audit/block 决策的命中：安全命中、运行时执行、运行时留证；裁判影子意见除外。"""
        return finding.type != "llm_judge" and (
            finding.counts_as_security_finding
            or cls._is_runtime_enforcement(finding)
            or cls._is_runtime_evidence(finding)
        )

    @staticmethod
    def _annotate_credential_assessment(findings, runtime):
        """Record what a credential detector established, before policy actions.

        A literal/format match is not proof of validity, compromise or exfiltration.
        Scores remain compatible rule weights, explicitly not probabilities.
        """
        for finding in findings:
            if finding.type != "secret" and not finding.category.startswith("code_leak_"):
                continue
            format_match = is_credential_format_match(finding.type, finding.category)
            finding.triage = {
                **finding.triage,
                "assessment_version": "credential-evidence-v1",
                "detection_method": "deterministic_rule",
                "confidence_kind": "heuristic_rule_score",
                "validation_status": "format_match" if format_match else "literal_candidate",
                "credential_validity": "unknown",
                "risk_basis": "potential_impact_if_real",
                "review_status": "not_requested",
            }
            explanation = credential_explanation(finding.type, finding.category)
            finding.evidence_reason = explanation + "；尚未验证凭据有效性或证实泄露，风险等级表示潜在影响"
            if not finding.redacted_evidence:
                finding.redacted_evidence = credential_evidence_text(
                    finding.type, finding.category, finding.matched_text_preview
                )

    @staticmethod
    def _explain_severity(findings):
        labels = {"info": "提示", "warning": "提醒", "low": "低危", "medium": "中危", "high": "高危", "critical": "严重"}
        for finding in findings:
            previous = finding.triage.get("severity_explanation", "")
            reason = finding.evidence_reason
            if previous and reason.endswith(previous):
                reason = reason[:-len(previous)].rstrip("； ")
            if finding.severity not in labels or _is_model_output_classified_observation(finding):
                # 模型输出密级留证只写留证原因，不追加“策略级别/告警级别”（2.9.21）。
                if previous:
                    finding.evidence_reason = reason
                    finding.triage = {k: v for k, v in finding.triage.items() if k != "severity_explanation"}
                continue
            baseline = finding.triage.get("policy_severity")
            downgrade = finding.triage.get("severity_downgrade_reason")
            if baseline not in labels and not downgrade:
                continue
            if downgrade:
                if reason == downgrade:
                    reason = ""
                elif reason.endswith("；" + downgrade):
                    reason = reason[:-len(downgrade) - 1].rstrip("； ")
            alert_level = f"告警级别：{labels[finding.severity]}"
            if downgrade:
                alert_level += f"（{downgrade}）"
            explanation = f"策略级别：{labels[baseline]}；{alert_level}" if baseline in labels else alert_level
            finding.evidence_reason = (reason + "；" if reason else "") + explanation
            finding.triage = {**finding.triage, "severity_explanation": explanation}

    def _determine_action(
        self,
        findings: List[SecurityFinding],
        runtime: Optional[SemanticRuntimeSnapshot] = None,
        *, context=None, principal=None, policies=None,
    ) -> str:
        runtime = runtime or self.snapshot_semantic_runtime()
        # llm_judge 是影子意见，永不参与 allow/block 决策
        self._explain_severity(findings)
        all_findings = findings
        findings = [f for f in findings if self._counts_for_decision(f)]
        if not findings:
            if any(
                f.type in {"engine_runtime", "regex_timeout", "custom_scan_incomplete"}
                and (f.action or "").lower() == "audit"
                for f in all_findings
            ):
                return "audit"
            return "allow"
        # 全局观察留痕管全部检测类拦截（2.9.22 D6）：集成凭据的 DLP 强制档也只记录。
        if runtime.audit_only:
            return "audit"
        # 文件正文命中与其它命中一样，按命中规则/策略在控制台配置的动作处置；
        # 不再因"来自附件"而一律升级为阻断。
        if not runtime.confidence_gating_enabled:
            return self._raw_action(findings, runtime, context=context, principal=principal, policies=policies)
        # 门控开启：只有达到阈值的 finding 才算强信号。
        strong = [
            f for f in findings
            if f.confidence >= runtime.confidence_downgrade_threshold
        ]
        if len(strong) == len(findings):
            return self._raw_action(findings, runtime, context=context, principal=principal, policies=policies)
        base = self._raw_action(strong, runtime, context=context, principal=principal, policies=policies) if strong else "allow"
        # 有弱信号但被门控筛掉：不直接放行，至少留审计
        return "audit" if base == "allow" else base

    def _raw_action(
        self,
        findings: List[SecurityFinding],
        runtime: Optional[SemanticRuntimeSnapshot] = None,
        *, context=None, principal=None, policies=None,
    ) -> str:
        runtime = runtime or self.snapshot_semantic_runtime()
        self._explain_severity(findings)
        all_findings = findings
        findings = [f for f in findings if self._counts_for_decision(f)]
        if not findings:
            if any(
                f.type in {"engine_runtime", "regex_timeout", "custom_scan_incomplete"}
                and (f.action or "").lower() == "audit"
                for f in all_findings
            ):
                return "audit"
            return "allow"
        # 全局观察留痕管全部检测类拦截（2.9.22 D6）：集成凭据的 DLP 强制档也只记录。
        if runtime.audit_only:
            return "audit"

        # 没有 policy_code 的内置 finding 尚未被策略中心纳管。它可以完整
        # 留证和告警，但不能仅凭检测器 severity 在前台不可见地执行 mask/block。
        # 只有显式绑定策略后的 finding 才能使用该策略配置的强制动作。
        def _explicitly_non_enforcing(f: SecurityFinding) -> bool:
            return (f.action or "").lower() in {"allow", "audit"}

        explicit_action_types = {
            "custom",
            "file",
            "guard",
            "regex_timeout",
            "custom_scan_incomplete",
        }
        all_builtin_findings = [
            f
            for f in findings
            if not f.policy_code and f.type not in explicit_action_types
        ]
        builtin_findings = [
            f for f in all_builtin_findings if not _explicitly_non_enforcing(f)
        ]
        builtin = "audit" if builtin_findings else "allow"
        if (
            builtin == "allow"
            and any((f.action or "").lower() == "audit" for f in all_builtin_findings)
        ):
            builtin = "audit"

        # 已绑定策略、自定义规则、文件检视和运行完整性保护携带显式 action；
        # 这些动作是可追溯配置或 fail-closed 契约，不再由 severity 猜测。
        custom = "allow"
        custom_actions = {
            f.action
            for f in findings
            if (f.policy_code or f.type in explicit_action_types) and f.action
        }
        if {"block", "quarantine"} & custom_actions:
            custom = "block"
        elif "mask" in custom_actions:
            custom = "mask"
        elif custom_actions & {"alert", "audit"}:
            custom = "audit"
        elif custom_actions - {"allow"}:
            # Unknown internal/file actions must never become an implicit allow.
            custom = "audit"

        # 取强者：block > mask > audit > allow
        rank = {"allow": 0, "audit": 1, "mask": 2, "block": 3}
        return builtin if rank[builtin] >= rank[custom] else custom

    def _split_attachment_masks(
        self, findings, content, file_text, file_start, file_end, policies, custom_rules,
    ) -> bool:
        """把脱敏命中分成消息文本和附件正文两部分，返回消息文本是否还有可改写的命中。

        附件字节无法改写，其中的脱敏命中标记"无法脱敏"；消息文本照常脱敏。
        同值命中会被去重并入消息文本那条 finding，这里按改写结果补一条附件命中，
        保证附件里仍有明文时一定留下"无法脱敏"告警。
        """
        masks = [f for f in findings if (f.action or "").lower() == "mask"]
        file_masks = [f for f in masks if f.content_source == "file_attachment"]
        text_masks = [f for f in masks if f.content_source != "file_attachment"]
        covered = {f.rule_id for f in file_masks}
        for finding in text_masks:
            if finding.rule_id in covered:
                continue
            rewritten = self._mask_content(content, [finding], None, policies, custom_rules)
            if rewritten.endswith(file_text):
                continue
            extra = finding.model_copy(deep=True)
            extra.content_source = "file_attachment"
            extra.matched_location = f"content[{file_start}:{file_end}]"
            findings.append(extra)
            file_masks.append(extra)
            covered.add(finding.rule_id)
        if file_masks:
            self._mask_unavailable(file_masks)
        return bool(text_masks)

    @staticmethod
    def _mask_unavailable(findings: List[SecurityFinding]) -> str:
        """A configured mask that cannot be applied is forwarded with an alert.

        Only an action an administrator configured as "block" may interrupt
        traffic; a mask the gateway cannot perform is recorded on every
        masking finding and downgraded to audit.
        """
        for finding in findings:
            if (finding.action or "").lower() == "mask":
                finding.triage = {**finding.triage, "mask_unavailable": True}
                note = "规则动作为脱敏，但该内容无法安全脱敏，已按原文放行并告警"
                if note not in (finding.evidence_reason or ""):
                    finding.evidence_reason = ((finding.evidence_reason + "；") if finding.evidence_reason else "") + note
        return "audit"


    @staticmethod
    def _is_unmaskable(finding: SecurityFinding) -> bool:
        """配置为脱敏但无法安全改写的命中：自定义关键字/字段名等非正则规则。"""
        return finding.type == "custom" and finding.action == "mask" and finding.rule_type != "regex"

    def _flag_unmaskable(self, findings: List[SecurityFinding]) -> None:
        """其它命中已脱敏时，只对无法改写的那部分标记"无法脱敏"并告警。"""
        unmaskable = [finding for finding in findings if self._is_unmaskable(finding)]
        if unmaskable:
            self._mask_unavailable(unmaskable)

    def _mask_preview(self, text: str) -> str:
        if len(text) <= 4:
            return "<MASKED>"
        return text[:2] + "****" + text[-2:]

    def _mask_content(self, content: str, findings: List[SecurityFinding], redaction_mapping=None, policies=None, custom_rules=None) -> str:
        """Rewrite concrete spans once; restoration values live only in this result.

        Never put the mapping into findings/raw_findings, fingerprint caches,
        rule packs, audit events, or any process-global object.
        """
        import secrets
        from app.policy_bindings import RedactionSettings

        settings = {policy.policy_id: policy.redaction for policy in getattr(policies, "policies", ()) if policy.redaction is not None}
        for rule, _pattern in getattr(custom_rules, "active_rules", ()):
            if rule.rule_id not in settings and rule.scope.get("redaction") is not None:
                settings[rule.rule_id] = RedactionSettings.model_validate(rule.scope["redaction"])
        candidates = []
        numeric = None
        view = None
        # 数字类 PII 按类别汇总：同类别多条命中只扫一遍全文（第三轮复审问题 1）。
        # category -> [规则 ID 最小的 (rule_id, setting), 待补齐的规范值集合]
        numeric_by_category = {}
        for finding in findings:
            # 只改写配置为"脱敏"的命中。语义裁判等没有动作的命中位置覆盖整句，
            # 纳入后会把"请汇款到"之类上下文一起替换掉（2.9.11 实测 A11）。
            if finding.action != "mask":
                continue
            # 自定义关键字/字段名的"脱敏"不能安全替换（字段名命中的是键不是值）：
            # 不改写它，由调用方单独告警；同消息里其它能定位的命中照常脱敏。
            if self._is_unmaskable(finding):
                continue
            setting = settings.get(finding.rule_id)
            location = re.fullmatch(r"content\[(\d+):(\d+)\]", finding.matched_location)
            if location is not None:
                start, end = int(location.group(1)), int(location.group(2))
                if 0 <= start < end <= len(content):
                    candidates.append((start, end, finding.rule_id, finding.category, setting))
            if finding.type == "custom":
                continue
            if finding.category in NUMERIC_PII_CATEGORIES:
                # 同值/同预览的命中在去重时合并成一条，其余出现要在这里补齐。
                # 字面正则认不出分隔符/全角/零宽写法，改用检测同一套变体识别，
                # 同类别全部候选区间一起替换（审查 B1：第二处变体明文发往上游）。
                # 第二处号码前常没有"卡号/手机"等上下文词，过不了检测闸门（审查 B-2），
                # 对已命中的规范值按值全文匹配（数字边界仍判断）补齐其余出现。
                # 同一区间多条规则时合并取规则 ID 最小者，所以每类只需记规则 ID 最小的那条。
                entry = numeric_by_category.setdefault(finding.category, [(finding.rule_id, setting), set()])
                if finding.rule_id < entry[0][0]:
                    entry[0] = (finding.rule_id, setting)
                if location is not None:
                    entry[1].add(compact_digits(normalize_view(content[int(location.group(1)):int(location.group(2))]).text))
                continue
            pattern = self._get_pattern_for_category(finding.category)
            if pattern is not None:
                candidates.extend((match.start(), match.end(), finding.rule_id, finding.category, setting) for match in pattern.finditer(content))
        if numeric_by_category:
            view = normalize_view(content)
            numeric = [
                candidate for candidate in find_numeric_pii(content, view)
                if candidate.variant
                or not self._should_drop_invalid_pii(candidate.category, candidate.value)
            ]
            for category, ((rule_id, setting), values) in numeric_by_category.items():
                same_category = [candidate for candidate in numeric if candidate.category == category]
                candidates.extend(
                    (candidate.start, candidate.end, rule_id, category, setting)
                    for candidate in same_category
                )
                values.update(candidate.value for candidate in same_category)
                candidates.extend(
                    (start, end, rule_id, category, setting)
                    for start, end in find_numeric_values(content, category, values, view)
                )
        # Merge overlapping matches so even the tail of a shorter match cannot
        # leak. Choose the widest rule's replacement, then stable policy identity.
        # Sorting + one sweep bounds this work for requests with many matches.
        selected = []
        for item in sorted(candidates, key=lambda value: (value[0], -(value[1]-value[0]), value[2])):
            if selected and item[0] < selected[-1][1]:
                previous = selected[-1]
                winner = min((previous, item), key=lambda value: (-(value[1]-value[0]), value[2]))
                selected[-1] = (previous[0], max(previous[1], item[1]), winner[2], winner[3], winner[4])
            else:
                selected.append(item)
        nonce = secrets.token_hex(16)
        while nonce in content:
            nonce = secrets.token_hex(16)
        # 逐段拼接（不在循环里反复切整串，几千处替换时避免平方级拷贝）；
        # 编号仍按从后往前的次序，与此前生成的占位符一致。
        pieces = []
        cursor = len(content)
        for index, (start, end, _rule, category, setting) in enumerate(sorted(selected, reverse=True)):
            replacement = setting.replacement if setting else "<MASKED>"
            if setting and setting.restore_response and redaction_mapping is not None:
                label = re.sub(r"[^\w]", "_", setting.replacement).strip("_")[:40] or re.sub(r"[^a-zA-Z0-9_]", "_", category)[:40] or "data"
                replacement = f"<JJD_{label}_{nonce}_{index}>"
                redaction_mapping[replacement] = content[start:end]
            pieces.append(content[end:cursor])
            pieces.append(replacement)
            cursor = start
        pieces.append(content[:cursor])
        return "".join(reversed(pieces))

    def _get_pattern_for_category(self, category: str) -> Optional[re.Pattern[str]]:
        if category in self.chinese_patterns:
            return self.chinese_patterns[category]
        if category in self.secret_patterns:
            return self.secret_patterns[category]
        if category in self.code_patterns:
            return self.code_patterns[category]
        return None

    def _hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:16]


engine = SecurityEngine()
