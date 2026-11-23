"""
Prompt 注入检测器 - 四层防御：关键词、编码绕过、语义绕过、结构化注入
"""
import base64
import binascii
import re
from typing import Dict, List
from app.detectors.evidence_context import SentenceIndex, observation, prepare_reference_context
from app.detectors.greedy_scan import GreedyScan


BASE64_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"
)
BASE64_INJECTION_HINTS = re.compile(
    r"(ignore|instruction|system\s+prompt|developer\s+message|jailbreak|"
    r"reveal|DAN|bypass|override|忽略|指令|系统提示|越狱|泄露|绕过|工具)",
    re.IGNORECASE,
)
INJECTION_CONTEXT_HINTS = re.compile(
    r"(ignore|disregard|instruction|system\s+prompt|developer\s+message|jailbreak|"
    r"reveal|override|bypass|DAN|忽略|指令|系统提示|越狱|泄露|绕过|覆盖)",
    re.IGNORECASE,
)
ACTIONABLE_INJECTION_HINTS = re.compile(
    r"(?:ignore|disregard).{0,40}(?:instructions?|prompts?|rules?|messages?)|"
    r"(?:override|bypass).{0,40}(?:instructions?|prompts?|rules?|safety|guardrails?)|"
    r"jailbreak|\bDAN\b|reveal.{0,40}system\s+prompt|"
    r"(?:忽略|无视|覆盖).{0,30}(?:指令|规则|要求|系统提示)|"
    r"越狱|绕过.{0,20}(?:规则|限制|审查|防护)|泄露.{0,20}(?:系统提示|密钥|令牌|凭据)",
    re.IGNORECASE,
)

# An indirect injection in retrieved/tool text addresses the assistant and tells
# it what to do. Topic words alone (keys, tunnels, proxies, logs about them) are
# data. The addressee and the directive must share one line.
_INJECTION_ADDRESSEE = (
    r"(?:\bai\b|assistant|chatbot|\bllm\b|language\s+model|\bmodel\b|\bagent\b|copilot|chatgpt|claude|"
    r"gemini|codex|\bgpt\b|助手|模型|智能体|机器人)"
)
_INJECTION_DIRECTIVE = (
    r"(?:ignore|disregard|forget|override|bypass|you\s+must|you\s+should|you\s+need\s+to|you\s+have\s+to|"
    r"you\s+are\s+now|from\s+now\s+on|before\s+(?:replying|answering|responding)|proceed|"
    r"do\s+not\s+(?:mention|tell|reveal)|don'?t\s+(?:mention|tell|reveal)|\brun\b|execute|\bsend\b|upload|"
    r"\bpost\b|e-?mail|forward|exfiltrate|\bprint\b|reveal|disclose|"
    r"请|必须|应当|从现在起|立即|忽略|无视|执行|运行|发送|上传|外发|转发|打印|输出|泄露|透露|不要告诉|别告诉|不要提|别提)"
)
INDIRECT_DIRECTIVE = re.compile(
    _INJECTION_ADDRESSEE + r"[^\n]{0,80}?" + _INJECTION_DIRECTIVE + "|" +
    _INJECTION_DIRECTIVE + r"[^\n]{0,40}?" + _INJECTION_ADDRESSEE,
    re.IGNORECASE,
)
# An imperative that moves protected material somewhere needs no explicit
# addressee: the reader of the context is the one being told to send it.
_EXFIL_VERB = r"(?:\b(?:send|upload|post|forward|exfiltrate|transmit|relay|leak)\b|发送|上传|外发|转发|转送|传到|发到|外传)"
_PROTECTED = (r"(?:api[ _-]?keys?|access[ _-]?tokens?|tokens?|secrets?|passwords?|passwd|credentials?|"
              r"private[ _-]?keys?|id_rsa|\.env\b|environment\s+variables?|system\s+prompt|hidden\s+(?:(?:system|developer)\s+)?(?:context|instructions?)|confidential\s+(?:configuration|config|data)|"
              r"(?:personal(?:ly\s+identifiable)?|genetic|medical|health|biometric|financial)\s+(?:data|information|records?)|\bPII\b|"
              r"密钥|令牌|密码|凭据|私钥|环境变量|系统提示词?|隐藏(?:的)?(?:(?:系统|开发者)(?:的)?)?(?:上下文|指令)|(?:内部|保密|机密)(?:保密)?(?:配置|资料|数据)|个人(?:身份识别)?(?:数据|信息)|遗传(?:数据|信息)|基因数据|医疗(?:数据|信息|记录)|健康(?:数据|信息|记录)|生物识别数据|财务(?:数据|信息|记录))")
# Verb and object stay inside one clause: "upload finished; token refreshed"
# is two statements about past events, not an order.
_CLAUSE = r"[^\n;.。；!！?？]{0,60}?"
INDIRECT_EXFIL_IMPERATIVE = re.compile(
    _EXFIL_VERB + _CLAUSE + _PROTECTED + "|" +
    _PROTECTED + _CLAUSE + _EXFIL_VERB + r"[^\n;.。；]{0,40}?(?:\bto\b|至|到|给|https?://|@)",
    re.IGNORECASE,
)


# Disclosure of protected instructions is an instruction even without naming
# an assistant. This only corroborates a model verdict; it does not block by
# itself. Whole-word verbs avoid treating past-tense incident reports as orders.
INDIRECT_DISCLOSURE_IMPERATIVE = re.compile(
    r"(?:\b(?:reveal|disclose|print|show|publish|output)\b|公布|公开|展示|披露|输出|打印|泄露)"
    + _CLAUSE + _PROTECTED,
    re.IGNORECASE,
)


def indirect_instruction_signal(text: str) -> bool:
    """Deterministic evidence that untrusted text instructs the assistant."""
    if not text:
        return False
    return bool(ACTIONABLE_INJECTION_HINTS.search(text) or INDIRECT_DIRECTIVE.search(text)
                or INDIRECT_EXFIL_IMPERATIVE.search(text) or INDIRECT_DISCLOSURE_IMPERATIVE.search(text))


# Only an imperative in lower-trust content that names protected material and
# a concrete external destination is promoted without a model verdict.
_EXFIL_ORDER_CUE = re.compile(
    r"(?:^|[\"':\n])\s*(?:please\s+|kindly\s+|请|务必\s*|立即\s*)?"
    r"(?:(?:retrieve|fetch|read|collect|get|access|send|upload|post|forward|e-?mail)\b|"
    r"提取|获取|读取|发送|上传|外发|转发)",
    re.IGNORECASE | re.MULTILINE,
)
_EXFIL_DESTINATION = re.compile(
    r"(?:[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|https?://[^\s\"'<>]+)",
    re.IGNORECASE,
)


# Two keyword rules are words joined by .*: scanned without the regex's rescans of a long line.
_REVERSE_INDUCTION = GreedyScan(["用英文回答", "但", ("中文", "拼音")], flags=re.I)
_CONDITIONAL_BYPASS = GreedyScan(["回答", ("是", "yes"), "如果不是", "就用", "回答"], flags=re.I)


class PromptInjectionDetector:
    """四层 Prompt 注入检测"""

    def __init__(self):
        # 第一层：关键词匹配
        self.keyword_patterns: List[Dict] = [
            {"pattern": re.compile(r'忽略(以上|之前|所有).{0,20}(指令|命令|规则|要求)', re.I), "type": "classic_injection"},
            {"pattern": re.compile(r'(扮演|假装|假装你是).{0,20}(DAN|越狱|jailbreak)', re.I), "type": "roleplay"},
            {"pattern": re.compile(r'(请|帮我).{0,10}(忘记|忽略).{0,10}(角色|身份|限制)', re.I), "type": "forget_restriction"},
            {"pattern": _REVERSE_INDUCTION.pattern, "finditer": _REVERSE_INDUCTION.finditer, "type": "reverse_induction"},
            {"pattern": _CONDITIONAL_BYPASS.pattern, "finditer": _CONDITIONAL_BYPASS.finditer, "type": "conditional_bypass"},
            {"pattern": re.compile(r'(跳过|绕过|跳开|无视|摆脱).{0,6}(任何|一切|所有|内容|安全|道德|伦理|法律|法规|审查|系统|规则|准则|防护).{0,6}(限制|约束|准则|审查|过滤|防护)', re.I), "type": "bypass_restriction"},
            {"pattern": re.compile(r'(进入|启用|切换到|开启).{0,6}(dan模式|无限制模式|越狱模式|上帝模式)', re.I), "type": "dev_mode"},
            {"pattern": re.compile(r'(开发者模式|developer\s*mode).{0,12}(不受限|不受.{0,4}限制|没有限制|无限制|越狱|绕过|忽略|jailbreak)|(不受限|没有限制|无限制|越狱|绕过|忽略|jailbreak).{0,12}(开发者模式|developer\s*mode)', re.I), "type": "dev_mode"},
            {"pattern": re.compile(r'(你现在是|从现在起你是|你将扮演).{0,30}(不受限|没有限制|无限制|无道德|无审查)', re.I), "type": "persona_unrestricted"},
            {"pattern": re.compile(r'(假设|想象|设想).{0,16}(没有任何|不存在|抛开).{0,8}(规则|限制|道德|法律|约束)', re.I), "type": "assume_no_rules"},
            # —— 英文 prompt injection 关键词层（P1-A：现状零覆盖）——
            {"pattern": re.compile(r'ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|preceding|earlier)\s+(instructions?|prompts?|rules?|messages?)', re.I), "type": "classic_injection_en"},
            {"pattern": re.compile(r'disregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|preceding)\s+(instructions?|prompts?|rules?)', re.I), "type": "classic_injection_en"},
            {"pattern": re.compile(r'you\s+are\s+now\s+(a\s+|an\s+)?(DAN|jailbroken|unrestricted|uncensored|developer\s+mode)', re.I), "type": "roleplay_en"},
            {"pattern": re.compile(r'(reveal|print|show|repeat|output)\s+(me\s+)?(your\s+|the\s+)?(system\s+prompt|initial\s+instructions?|the\s+prompt\s+above|your\s+instructions?)', re.I), "type": "system_prompt_leak_en"},
            {"pattern": re.compile(r'(enable|enter|activate|switch\s+to)\s+(the\s+)?(developer|god|dan|jailbreak|unrestricted)\s+mode', re.I), "type": "dev_mode_en"},
        ]

        # 第二层：编码检测
        self.encoding_patterns: List[Dict] = [
            {"pattern": BASE64_CANDIDATE, "type": "base64", "validator": self._is_suspicious_base64},
            {"pattern": re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}'), "type": "hex_escape",
             "validator": self._is_suspicious_hex_escape},
            {"pattern": re.compile(r'(?:\\u[0-9a-fA-F]{4}){3,}'), "type": "unicode_escape",
             "validator": self._is_suspicious_unicode_escape},
        ]

        # 第三层：语义绕过
        self.semantic_patterns: List[Dict] = [
            {"pattern": re.compile(
                r'第一步(?:(?!第二步)[\s\S]){0,160}'
                r'第二步(?:(?!第三步)[\s\S]){0,160}'
                r'第三步(?:(?!\n\s*\n)[\s\S]){0,160}',
                re.I,
            ), "type": "step_by_step_bypass",
             "context_required": ACTIONABLE_INJECTION_HINTS, "context_scope": "match"},
            {"pattern": re.compile(r'假设.{0,20}(黑客|攻击|越狱).{0,20}(小说|故事|剧本)', re.I), "type": "hypothetical_bypass"},
            {"pattern": re.compile(r'不要(拒绝|阻止|拦截).{0,10}(直接|立即).{0,10}(回答|输出)', re.I), "type": "negation_bypass"},
            {"pattern": re.compile(r'翻译.{0,10}(日文|英文|法文|德文).{0,20}忽略.{0,10}指令', re.I), "type": "translation_bypass"},
        ]

        # 第四层：结构化注入
        self.structured_patterns: List[Dict] = [
            # html 注释：整条注释一起匹配（含注释体），注入语境佐证只在“注释体内”查，
            # 避免文档别处出现 ignore/instruction/system prompt 等普通英文词就误报裸注释。
            {"pattern": re.compile(r'<!--.*?(?:-->|$)', re.I | re.S), "type": "html_comment",
             "context_required": INJECTION_CONTEXT_HINTS, "context_scope": "match"},
            {"pattern": re.compile(r'<\|im_start\|>|<\|im_end\|>', re.I), "type": "template_injection"},
            {"pattern": re.compile(r'```.{0,10}\n.*忽略', re.I), "type": "code_block_injection"},
        ]

    def detect(self, content: str, *, indirect_source: bool = False) -> List[Dict]:
        """对内容执行四层注入检测"""
        findings: List[Dict] = []
        reference_context = prepare_reference_context(content)
        # Each occurrence looks up its sentence and quote instead of rescanning the text from the start.
        sentences = SentenceIndex(content)
        for layer_name, patterns in [
            ("keyword", self.keyword_patterns),
            ("encoding", self.encoding_patterns),
            ("semantic", self.semantic_patterns),
            ("structured", self.structured_patterns),
        ]:
            for p in patterns:
                candidates = []
                for match in p.get("finditer", p["pattern"].finditer)(content):
                    matched = match.group()
                    validator = p.get("validator")
                    if validator is not None and not validator(matched):
                        continue
                    ctx_req = p.get("context_required")
                    if ctx_req is not None:
                        # 默认在整段 content 里找语境佐证；context_scope="match" 时只在匹配片段内找，
                        # 使佐证与命中体本身绑定（如 html 注释体内是否真含注入指令）。
                        haystack = matched if p.get("context_scope") == "match" else content
                        if not ctx_req.search(haystack):
                            continue
                    finding = {
                        "type": "prompt_injection",
                        "category": f"{layer_name}_{p['type']}",
                        "severity": "high",
                        "matched_text_preview": self._mask_preview(matched),
                        "raw_evidence": matched,
                        "matched_location": f"content[{match.start()}:{match.end()}]",
                        "evidence_kind": "literal",
                        "evidence_reason": f"命中提示注入{layer_name}层规则",
                        "rule_id": f"prompt_injection_{p['type']}",
                        "confidence": 0.85 if layer_name == "keyword" else 0.7,
                    }
                    reason = ""
                    if layer_name == "keyword" or p["type"] == "code_block_injection":
                        reason = sentences.quoted_reference_reason(match.start(), match.end(), reference_context)
                        if not reason:
                            reason = sentences.refusal_reason(match.start(), match.end())
                    elif p["type"] == "template_injection":
                        reason = sentences.quoted_reference_reason(match.start(), match.end(), reference_context)
                        if not reason:
                            reason = sentences.documented_reference_reason(match.start(), match.end())
                    if reason:
                        observation(finding, reason)
                    candidates.append(finding)
                if candidates:
                    findings.append(max(candidates, key=lambda f: f.get("counts_as_security_finding", True)))
        if indirect_source:
            for match in INDIRECT_EXFIL_IMPERATIVE.finditer(content):
                local = content[max(0, match.start()-80):min(len(content), match.end()+100)]
                if not (_EXFIL_ORDER_CUE.search(local)
                        and _EXFIL_DESTINATION.search(local)):
                    continue
                finding = {
                    "type": "prompt_injection",
                    "category": "indirect_private_data_exfil",
                    "severity": "high",
                    "matched_text_preview": self._mask_preview(match.group()),
                    "raw_evidence": match.group(),
                    "matched_location": f"content[{match.start()}:{match.end()}]",
                    "evidence_kind": "literal",
                    "evidence_reason": "Untrusted content instructs a protected-data transfer to an external destination",
                    "rule_id": "prompt_injection_indirect_private_data_exfil",
                    "confidence": 0.90,
                }
                reason = (sentences.quoted_reference_reason(match.start(), match.end(), reference_context)
                          or sentences.refusal_reason(match.start(), match.end())
                          or sentences.documented_reference_reason(match.start(), match.end()))
                if reason:
                    observation(finding, reason)
                findings.append(finding)
                break
        for finding in findings:
            finding.setdefault("triage", {}).setdefault("confidence_kind", "heuristic_rule_score")
        return findings

    @staticmethod
    def _mask_preview(text: str) -> str:
        if len(text) <= 8:
            return "<MASKED>"
        return text[:4] + "****" + text[-4:]

    @staticmethod
    def _is_suspicious_base64(text: str) -> bool:
        decoded = PromptInjectionDetector._decode_base64_candidate(text)
        return bool(decoded and BASE64_INJECTION_HINTS.search(decoded))

    @staticmethod
    def _is_suspicious_hex_escape(text: str) -> bool:
        try:
            decoded = bytes.fromhex(text.replace("\\x", "")).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return False
        return bool(ACTIONABLE_INJECTION_HINTS.search(decoded))

    @staticmethod
    def _is_suspicious_unicode_escape(text: str) -> bool:
        try:
            decoded = text.encode("ascii").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
            return False
        return bool(ACTIONABLE_INJECTION_HINTS.search(decoded))

    @staticmethod
    def _decode_base64_candidate(text: str) -> str:
        candidate = text.strip()
        if len(candidate) < 40:
            return ""
        padding = "=" * ((4 - len(candidate) % 4) % 4)
        try:
            raw = base64.b64decode(candidate + padding, validate=True)
        except (binascii.Error, ValueError):
            return ""
        if len(raw) < 16:
            return ""
        decoded = raw.decode("utf-8", errors="ignore")
        if not decoded:
            return ""
        printable = sum(ch.isprintable() or ch.isspace() for ch in decoded) / len(decoded)
        if printable < 0.8:
            return ""
        return decoded
