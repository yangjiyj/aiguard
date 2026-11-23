"""Deterministic sensitive-data detectors with contextual false-positive gates."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from datetime import date, datetime
from typing import Callable, Dict, Iterable, List, Optional

from app.detectors.config_evidence import is_empty_shell_parameter, read_credential_value
from app.detectors.hit_display import masked_placeholder
from app.detectors.pii_checksum import validate_bank_card, validate_id_card_cn
from app.detectors.numeric_context import is_complete_pii_token
from app.text_normalize import NormalizedText, normalize_view


def is_public_service_email(value: str) -> bool:
    """An exact public attribution mailbox, never a vendor-domain exemption.

    This says nothing about the safety of surrounding text or an email send.
    Customer-specific email rules retain their own policy semantics.
    """
    return value.lower() == "noreply@anthropic.com"


# 包名@版本号.后缀（pnpm patches/foo@1.2.0.patch、node-pty@1.2.0-beta.15.patch）：@ 后是
# 至少两段数字版本，不是邮箱域名（163.com 这类单段数字域名不受影响）。
_VERSIONED_AT_DOMAIN = re.compile(r"^\d+\.\d+(?:[.\-+]|$)")


def is_non_mailbox_at_reference(value: str) -> bool:
    """形似邮箱但不是邮箱：包名@版本号文件、OpenSSH 协议扩展名（hostkeys-00@openssh.com）。"""
    local, _, domain = value.rpartition("@")
    if not local or not domain:
        return False
    domain = domain.lower()
    return bool(_VERSIONED_AT_DOMAIN.match(domain)) or domain == "openssh.com"


SENSITIVE_DATA_CATEGORIES = {
    "passport_cn",
    "hk_macao_taiwan_id",
    "officer_id_cn",
    "driver_license_cn",
    "social_security_cn",
    "home_address_cn",
    "ip_address",
    "birth_date",
    "communication_record",
    "gps_location",
    "plain_password",
    "cloud_credential",
    "credit_card_cvv",
    "bank_statement",
    "insurance_info",
    "medical_record",
    "genetic_data",
    "biometric_data",
    "internal_project_code",
    "sensitive_code",
    "education_background",
    "criminal_record",
}

SECRET_CATEGORIES = {"plain_password", "cloud_credential"}
PII_CATEGORIES = {
    "passport_cn",
    "hk_macao_taiwan_id",
    "officer_id_cn",
    "driver_license_cn",
    "social_security_cn",
    "home_address_cn",
    "ip_address",
    "birth_date",
    "communication_record",
    "gps_location",
    "credit_card_cvv",
    "bank_statement",
    "insurance_info",
    "medical_record",
    "genetic_data",
    "biometric_data",
    "education_background",
    "criminal_record",
}


PLACEHOLDER_VALUE = re.compile(
    r"^(?:your[-_ ]?|example[-_ ]?|sample[-_ ]?|dummy[-_ ]?|test[-_ ]?|"
    r"change[-_ ]?me|password|passwd|pwd|x{3,}|\*{3,}|<[^>]+>|\$\{[^}]+\})$",
    re.IGNORECASE,
)
ADDRESS_CORROBORATION = re.compile(
    r"(?:省|自治区|市|州|区|县|镇|乡|街道|路|街|巷|弄|号|栋|幢|单元|室|小区|村)"
)
# 地址标签：保持"标签 + 地址内容"结构。带限定词的标签直接认；裸"地址"只在句首/标点后
# 或"的地址"时才算标签，避免"服务器地址""IP地址""邮箱地址""浏览器地址栏"。
LEGACY_ADDRESS_LABELS = frozenset({"家庭住址", "家庭地址", "现住址", "居住地址", "收货地址"})
ADDRESS_LABEL = (
    r"(?:家庭住址|家庭地址|现居住地址|现住址|现居地址|居住地址|常住地址|"
    r"收货地址|收件地址|寄件地址|送货地址|配送地址|邮寄地址|联系地址|通讯地址|通信地址|"
    r"户籍地址|户口地址|详细地址|住址|家住(?:在|于)?|"
    r"地址(?:(?<=的地址)|(?<![一-鿿A-Za-z0-9_]地址)))"
)
# 地址内容到换行、逗号、分号、句末标点为止；遇到"联系人/电话/手机/邮编…"等下一个字段也停下，
# 不把后面的无关文字吞进脱敏区间。逐字符有界（≤80），无嵌套量词。
ADDRESS_VALUE = (
    r"(?:(?!\s*(?:联系人|收件人|收货人|联系电话|电话|手机|邮编|姓名))[^\n,，;；。！？!?]){6,80}"
)
ADDRESS_STREET = re.compile(
    r"(?:路|街|大道|巷|弄|胡同|号|栋|幢|单元|室|楼|小区|村|院|大厦|园|座|广场|公寓)"
)
ADDRESS_REGION = re.compile(r"(?:省|自治区|市|州|区|县|镇|乡|旗|[0-9一二三四五六七八九十])")
COMMUNICATION_CORROBORATION = re.compile(
    r"(?:1[3-9]\d{9}|\d{4}[-/.年]\d{1,2}[-/.月]\d{1,2}|\d{1,2}:\d{2}|"
    r"\d+\s*(?:秒|分钟)|短信内容|通话时长|对方号码)"
)
BANK_STATEMENT_CORROBORATION = [
    re.compile(r"(?:交易|转账|收款|付款|借方|贷方|摘要)"),
    re.compile(r"(?:金额|余额|人民币|CNY|RMB|\d+(?:\.\d{2})?\s*元)", re.IGNORECASE),
    re.compile(r"(?:账号|账户|卡号|对方|户名)"),
    re.compile(r"(?:20\d{2}[-/.年]\d{1,2}[-/.月]\d{1,2})"),
]
MEDICAL_CORROBORATION = [
    re.compile(r"(?:病历|患者|门诊|住院|医院|病区)"),
    re.compile(r"(?:诊断|处方|用药|检查结果|检验结果|治疗|过敏史)"),
]
CRIMINAL_CORROBORATION = re.compile(
    r"(?:犯罪|罪名|刑事|案底|判处|判决|拘役|有期徒刑|无期徒刑|缓刑|服刑|案件编号)"
)
CODE_CORROBORATION = re.compile(
    r"(?:\bdef\s+\w+\s*\(|\bclass\s+\w+|\bfunction\s+\w+\s*\(|"
    r"\breturn\b|\bSELECT\b.+\bFROM\b|\bprivate\s+key\b|\bhmac\.|"
    r"\bsha(?:256|512)\b|\b[A-Za-z_]\w*\s*[:=]\s*[^,，。]+)",
    re.IGNORECASE,
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in counts.values()
    )


def _mask_preview(value: str) -> str:
    compact = value.strip()
    if len(compact) <= 8:
        return "<MASKED>"
    return compact[:2] + "****" + compact[-2:]


_LOCATION = re.compile(r"content\[(\d+):(\d+)\]")


def _remap_location(finding: Dict, view: NormalizedText) -> None:
    location = _LOCATION.fullmatch(str(finding.get("matched_location") or ""))
    if location is None:
        return
    start, end = view.source_span(int(location.group(1)), int(location.group(2)))
    finding["matched_location"] = f"content[{start}:{end}]"


class SensitiveDataDetector:
    """Detect the sensitive-data catalog items absent from legacy detectors."""

    categories = frozenset(SENSITIVE_DATA_CATEGORIES)

    def __init__(self) -> None:
        label_sep = r"\s*(?:号码?|编号|No\.?|Number)?\s*[:：#]?\s*"
        self.labeled_patterns: List[Dict[str, object]] = [
            self._rule(
                "passport_cn", "high",
                rf"(?:中国)?(?:护照|passport){label_sep}(?P<value>[EGDSPHM]\d{{7,8}})\b",
                confidence=0.98,
            ),
            self._rule(
                "hk_macao_taiwan_id", "high",
                rf"(?:香港(?:永久性)?(?:居民)?身份证|澳门(?:居民)?身份证|台湾(?:居民)?身份证|"
                rf"港澳台(?:居民)?证件|回乡证|台胞证){label_sep}"
                rf"(?P<value>(?:[A-Z]{{1,2}}\d{{6}}\(?[A-Z0-9]\)?|[A-Z]\d{{9}}|\d{{7,8}}\(?[A-Z0-9]\)?))",
                confidence=0.96,
            ),
            self._rule(
                "officer_id_cn", "high",
                rf"(?:军官证|警官证|武警证|士兵证){label_sep}"
                rf"(?P<value>[一-鿿A-Z]{{0,6}}(?:字第)?\d{{6,12}}号?)",
                confidence=0.95,
            ),
            self._rule(
                "driver_license_cn", "high",
                rf"(?:驾驶证|驾照){label_sep}(?P<value>(?:[0-9]{{17}}[0-9Xx]|[0-9]{{12}}))"
                rf"(?![A-Za-z0-9_]|\d)",
                validator=self._valid_driver_license,
                confidence=0.98,
            ),
            self._rule(
                "social_security_cn", "high",
                rf"(?:社会保障卡|社会保障号码|社保卡){label_sep}"
                rf"(?P<value>(?:[0-9]{{17}}[0-9Xx]|[A-Z0-9]{{9,18}}))"
                rf"(?![A-Za-z0-9_]|\d)",
                validator=self._valid_social_security_number,
                confidence=0.96,
            ),
            self._rule(
                "home_address_cn", "high",
                rf"(?P<label>{ADDRESS_LABEL})(?P<sep>\s*[:：]\s*|\s*(?:是|为)\s*|\s+|)"
                rf"(?P<value>{ADDRESS_VALUE})",
                validator=self._valid_home_address,
                confidence=0.9,
            ),
            self._rule(
                "birth_date", "medium",
                r"(?:出生日期|出生年月|出生时间|生日|date\s+of\s+birth|DOB)\s*[:：]?\s*"
                r"(?P<value>(?:19|20)\d{2}(?:[-/.年]\d{1,2})(?:[-/.月]\d{1,2})日?)",
                validator=self._valid_birth_date,
                confidence=0.98,
            ),
            self._rule(
                "communication_record", "high",
                r"(?:通话记录|通信记录|短信记录|短信内容|聊天记录)\s*[:：]\s*"
                r"(?P<value>[^\n]{8,180})",
                validator=lambda value, _content, _match: bool(COMMUNICATION_CORROBORATION.search(value)),
                confidence=0.9,
            ),
            self._rule(
                "plain_password", "critical",
                r"(?:(?:登录密码|账户密码|用户密码|明文密码|password|passwd|passphrase|pwd)(?:\\*[\"'])?"
                r"[ \t]*[:=：]|(?:密码|口令)[ \t]*(?:(?:是|为)(?!否|不是|什么|对的|错的|通过|从|由|空|必填)|[:=：]))"
                r"[ \t]*[\"']?(?P<value>(?:(?!\\+[nrt\"'])[^\s,，;；。！？、）」】》\"']){8,128})",
                validator=self._credible_password,
                confidence=0.98,
            ),
            self._rule(
                "cloud_credential", "critical",
                r"(?:(?:AWS|Azure|GCP|Google\s+Cloud|阿里云|腾讯云|华为云)[^\n]{0,40})?"
                r"(?:AccountKey|client[_ -]?secret|secret[_ -]?access[_ -]?key|service[_ -]?account[_ -]?key|"
                r"云(?:厂商)?凭据|云密钥)\s*[:=：]\s*[\"']?"
                r"(?P<value>[A-Za-z0-9_+/=-]{16,256})",
                validator=self._credible_secret,
                confidence=0.99,
            ),
            self._rule(
                "credit_card_cvv", "critical",
                r"(?<![A-Za-z])(?:CVV2?|CVC2?|CID|信用卡安全码|卡片安全码|安全码)[ \t]*[:=：]?[ \t]*"
                r"(?P<value>\d{3,4})(?!\d)",
                confidence=0.99,
            ),
            self._rule(
                "bank_statement", "high",
                r"(?:银行流水|账户流水|交易明细|账户明细)\s*[:：]\s*(?P<value>[^\n]{12,220})",
                validator=self._valid_bank_statement,
                confidence=0.92,
            ),
            self._rule(
                "insurance_info", "high",
                r"(?:保险单号|保单号|理赔编号|理赔案号)\s*[:：#]?\s*"
                r"(?P<value>[A-Z0-9][A-Z0-9_-]{7,31}(?:[^\n]{0,80})?)",
                confidence=0.95,
            ),
            self._rule(
                "medical_record", "high",
                r"(?:病历记录|电子病历|病历号|门诊记录|住院记录)\s*[:：#]?\s*"
                r"(?P<value>[^\n]{8,220})",
                validator=self._valid_medical_record,
                confidence=0.94,
            ),
            self._rule(
                "genetic_data", "critical",
                r"(?:DNA|RNA|基因|核酸)\s*(?:检测)?\s*(?:序列|数据|结果)\s*[:：]\s*"
                r"(?P<value>[ACGTUNacgtun\s-]{20,500})",
                validator=self._valid_genetic_sequence,
                confidence=0.99,
            ),
            self._rule(
                "biometric_data", "high",
                r"(?:生物识别)?(?:指纹(?:特征)?(?:数据|模板)?|虹膜(?:特征)?(?:数据|模板)?|"
                r"人脸特征(?:向量|模板|数据)?|声纹特征(?:向量|模板|数据)?|掌纹(?:特征)?(?:数据|模板)?)"
                r"\s*[:：]\s*(?P<value>[A-Za-z0-9+/=,._ -]{20,500})",
                validator=self._credible_secret,
                confidence=0.97,
            ),
            self._rule(
                "internal_project_code", "high",
                r"(?:内部项目代号|项目代号|内部产品代号|产品代号|project\s+code)\s*[:=：]\s*"
                r"(?P<value>[A-Z][A-Z0-9_-]{3,31})",
                validator=lambda value, _content, _match: bool(re.search(r"[0-9_-]", value)),
                confidence=0.94,
            ),
            self._rule(
                "sensitive_code", "high",
                r"(?:敏感代码片段|核心算法代码|核心源代码|专有源代码|proprietary\s+source\s+code)"
                r"\s*[:：]\s*(?P<value>[^\n]{16,400})",
                validator=lambda value, _content, _match: bool(CODE_CORROBORATION.search(value)),
                confidence=0.92,
            ),
            self._rule(
                "education_background", "medium",
                r"(?:教育背景|学历信息|学历|毕业院校|毕业学校)\s*[:：]\s*"
                r"(?P<value>[^\n,，;；]{4,80})",
                validator=self._valid_education,
                confidence=0.9,
            ),
            self._rule(
                "criminal_record", "high",
                r"(?:犯罪记录|刑事处罚记录|案底|判决记录)\s*[:：]\s*"
                r"(?P<value>[^\n]{6,220})",
                validator=lambda value, _content, _match: bool(CRIMINAL_CORROBORATION.search(value)),
                confidence=0.96,
            ),
        ]
        ip_label = r"(?:客户端|用户|访客|来源|登录|注册|设备)\s*IP|IP\s*地址|[\"']ip[\"']"
        self.ipv4_pattern = re.compile(
            rf"(?:{ip_label})\s*[:=：]\s*(?P<value>(?:\d{{1,3}}\.){{3}}\d{{1,3}})",
            re.IGNORECASE,
        )
        self.ipv6_labeled_pattern = re.compile(
            rf"(?:IPv6|{ip_label})\s*[:=：]\s*(?P<value>[0-9A-Fa-f:]{{3,45}})",
            re.IGNORECASE,
        )
        self.gps_pattern = re.compile(
            r"(?:GPS(?:\s*坐标)?|经纬度|地理坐标|location)\s*[:=：]\s*"
            r"(?P<lat>[+-]?\d{1,2}(?:\.\d{3,8})?)\s*[,，]\s*"
            r"(?P<lon>[+-]?\d{1,3}(?:\.\d{3,8})?)",
            re.IGNORECASE,
        )

    @staticmethod
    def _rule(
        category: str,
        severity: str,
        pattern: str,
        *,
        validator: Optional[Callable[[str, str, re.Match[str]], bool]] = None,
        confidence: float,
    ) -> Dict[str, object]:
        return {
            "category": category,
            "severity": severity,
            "pattern": re.compile(pattern, re.IGNORECASE),
            "validator": validator,
            "confidence": confidence,
        }

    def detect(self, content: str) -> List[Dict]:
        """在归一化视图上检测（全角、零宽变体），matched_location 映射回原文坐标。"""
        view = normalize_view(content or "")
        findings = self._detect_text(view.text)
        if view.changed:
            for finding in findings:
                _remap_location(finding, view)
        return findings

    def _detect_text(self, content: str) -> List[Dict]:
        findings: List[Dict] = []
        for rule in self.labeled_patterns:
            pattern = rule["pattern"]
            assert isinstance(pattern, re.Pattern)
            validator = rule["validator"]
            for match in pattern.finditer(content):
                value = match.group("value").strip()
                if validator is not None and not validator(value, content, match):
                    continue
                start, end = match.start("value"), match.end("value")
                if rule["category"] == "plain_password":
                    parsed = read_credential_value(content, start)
                    value, start, end = parsed.value, parsed.start, parsed.end
                finding = self._finding(
                    str(rule["category"]), str(rule["severity"]), value,
                    start, end, float(rule["confidence"]),
                )
                if rule["category"] == "credit_card_cvv":
                    window = content[max(0, match.start()-160):match.end()+160]
                    label = match.group(0)
                    new_form = label.startswith("安全码") or not re.search(r"[:=：]", label)
                    if new_form:
                        # 新增的写法（“CVV 123”“安全码 123”）卡号佐证只看同一段：空行隔开的不算
                        local = match.start() - max(0, match.start()-160)
                        para_start = window.rfind("\n\n", 0, local)
                        para_end = window.find("\n\n", local)
                        window = window[(para_start + 2 if para_start != -1 else 0):(para_end if para_end != -1 else len(window))]
                    # 连写或空格/短横分组的有效卡号都算佐证
                    corroborated = any(
                        validate_bank_card(digits[:n])
                        for digits in (re.sub(r"\D", "", c) for c in re.findall(r"(?<!\d)[3-6](?:[ -]?\d){12,18}(?!\d)", window))
                        for n in range(13, min(len(digits), 19) + 1)
                    )
                    if label.startswith("安全码") and not re.search(r"卡|有效期|CVV|CVC|银行", window, re.I):
                        # 单写“安全码”：同段除卡号外还要有卡/有效期/CVV/银行之一，只有一串数字不算
                        continue
                    if not corroborated and (
                        label[:3].lower() == "cid"
                        # 单写“安全码”、或 CVV 与数字之间没有冒号/等号（“CVV 123”）：像普通文字，必须有卡号佐证
                        or new_form
                    ):
                        # "cid=284"/"CID: 404" 多是频道/内容/客户端 ID；CID 只在旁边有卡号时才是安全码。
                        continue
                    if not corroborated:
                        finding.update(severity="medium", confidence=0.65)
                        finding["evidence_reason"] = "安全码格式候选，缺少有效卡号佐证"
                        finding["triage"] = {**finding.get("triage", {}), "severity_downgrade_reason": "安全码格式候选，缺少有效卡号佐证"}
                elif rule["category"] == "genetic_data":
                    finding["severity"] = "high"
                    finding["evidence_reason"] = "基因序列格式候选，未证明个人身份关联或外泄影响"
                    finding["triage"] = {**finding.get("triage", {}), "severity_downgrade_reason": "基因序列格式候选，未证明个人身份关联或外泄影响"}
                findings.append(finding)

        findings.extend(self._detect_ip_addresses(content))
        findings.extend(self._detect_gps(content))
        return findings

    def _detect_ip_addresses(self, content: str) -> Iterable[Dict]:
        seen = set()
        for match in self.ipv4_pattern.finditer(content):
            value = match.group("value")
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_unspecified or address.is_multicast:
                continue
            span = (match.start("value"), match.end("value"))
            seen.add(span)
            yield self._finding("ip_address", "medium", value, span[0], span[1], 0.99)
        for match in self.ipv6_labeled_pattern.finditer(content):
            value = match.group("value")
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            span = (match.start("value"), match.end("value"))
            if span in seen or address.is_unspecified or address.is_multicast:
                continue
            yield self._finding("ip_address", "medium", value, span[0], span[1], 0.99)

    def _detect_gps(self, content: str) -> Iterable[Dict]:
        for match in self.gps_pattern.finditer(content):
            lat, lon = float(match.group("lat")), float(match.group("lon"))
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                continue
            start, end = match.start("lat"), match.end("lon")
            value = content[start:end]
            yield self._finding("gps_location", "high", value, start, end, 0.99)

    @staticmethod
    def _finding(
        category: str,
        severity: str,
        value: str,
        start: int,
        end: int,
        confidence: float,
    ) -> Dict:
        return {
            "type": (
                "secret" if category in SECRET_CATEGORIES
                else "pii" if category in PII_CATEGORIES
                else "data_leak"
            ),
            "category": category,
            "severity": severity,
            "matched_text_preview": _mask_preview(value),
            "raw_evidence": value,
            "redacted_evidence": masked_placeholder(category),
            "matched_location": f"content[{start}:{end}]",
            "evidence_kind": "literal",
            "evidence_reason": "命中带格式校验或上下文佐证的敏感数据规则",
            "rule_id": f"sensitive_data_{category}",
            "confidence": confidence,
        }

    @staticmethod
    def _valid_driver_license(value: str, content: str, match: re.Match[str]) -> bool:
        return is_complete_pii_token(content, *match.span("value")) and (
            len(value) == 12 or validate_id_card_cn(value)
        )

    @staticmethod
    def _valid_social_security_number(value: str, content: str, match: re.Match[str]) -> bool:
        return is_complete_pii_token(content, *match.span("value")) and (
            not re.fullmatch(r"[0-9]{17}[0-9Xx]", value) or validate_id_card_cn(value)
        )

    @staticmethod
    def _valid_home_address(value: str, _content: str, match: re.Match[str]) -> bool:
        if "://" in value or "@" in value:
            return False
        if match.group("label") in LEGACY_ADDRESS_LABELS and re.search(r"[:：]", match.group("sep")):
            # 旧标签 + 冒号：保持原判定（≥8 字、任一地址要素）
            return len(value) >= 8 and bool(ADDRESS_CORROBORATION.search(value))
        # 新标签或无冒号：要像一个具体地址——至少 4 个汉字、有路/号/室等门牌要素，
        # 且有行政区划或门牌数字
        cjk = sum(1 for ch in value if "一" <= ch <= "鿿")
        return cjk >= 4 and bool(ADDRESS_STREET.search(value)) and bool(ADDRESS_REGION.search(value))

    @staticmethod
    def _valid_birth_date(value: str, _content: str, _match: re.Match[str]) -> bool:
        normalized = re.sub(r"[年月/.]", "-", value).rstrip("日")
        try:
            parsed = datetime.strptime(normalized, "%Y-%m-%d").date()
        except ValueError:
            return False
        return date(1900, 1, 1) <= parsed <= date.today()

    @staticmethod
    def _credible_password(value: str, _content: str, _match: re.Match[str]) -> bool:
        parsed = read_credential_value(_content, _match.start("value"))
        if parsed.kind != "literal":
            return False
        normalized = parsed.value
        value = normalized
        if re.match(r"(?:密码|口令)", _match.group(0)) and not re.fullmatch(r"[\x21-\x7e]+", normalized):
            # 中文“密码是/为/：”写法的取值必须全是 ASCII 可见字符：真密码不会夹汉字，夹了就是一句话
            return False
        if is_empty_shell_parameter(_content, _match.start()):
            return False
        if PLACEHOLDER_VALUE.fullmatch(normalized):
            return False
        classes = sum(bool(pattern.search(value)) for pattern in (
            re.compile(r"[a-z]"), re.compile(r"[A-Z]"), re.compile(r"\d"), re.compile(r"[^A-Za-z0-9]"),
        ))
        return len(normalized) >= 10 and classes >= 3 and _entropy(normalized) >= 3.0

    @staticmethod
    def _credible_secret(value: str, _content: str, _match: re.Match[str]) -> bool:
        normalized = value.strip()
        return (
            len(normalized) >= 16
            and not PLACEHOLDER_VALUE.fullmatch(normalized)
            and _entropy(normalized) >= 3.0
        )

    @staticmethod
    def _valid_bank_statement(value: str, _content: str, _match: re.Match[str]) -> bool:
        return sum(bool(pattern.search(value)) for pattern in BANK_STATEMENT_CORROBORATION) >= 2

    @staticmethod
    def _valid_medical_record(value: str, content: str, match: re.Match[str]) -> bool:
        start, end = max(0, match.start() - 32), min(len(content), match.end() + 80)
        window = content[start:end]
        return all(pattern.search(window) for pattern in MEDICAL_CORROBORATION)

    @staticmethod
    def _valid_genetic_sequence(value: str, _content: str, _match: re.Match[str]) -> bool:
        compact = re.sub(r"[\s-]", "", value).upper()
        return len(compact) >= 20 and set(compact) <= set("ACGTUN") and len(set(compact)) >= 3

    @staticmethod
    def _valid_education(value: str, _content: str, _match: re.Match[str]) -> bool:
        return bool(re.search(r"(?:大学|学院|学校|本科|硕士|博士|研究生|大专|中专|高中)", value))
