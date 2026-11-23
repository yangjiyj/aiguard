"""
数据泄露检测器 - 敏感文件、涉密文档、代码泄露、Key 泄露检测
"""
import re
from typing import Dict, List
from app.detectors.config_evidence import has_literal_sensitive_config, is_empty_shell_parameter, read_credential_value, credential_url_has_literal


class DataLeakDetector:
    """数据泄露检测增强"""

    def __init__(self):
        # 涉密标记检测：密级词必须和文档/数据实体形成近邻佐证，避免把普通分类用语当作外发标记。
        self.classified_markers: List[Dict] = [
            {"pattern": re.compile(r'(机密|绝密|秘密|内部文件|内部资料)', re.I), "type": "classified_cn", "severity": "high"},
            {"pattern": re.compile(r'\b(confidential|top secret|classified|internal use)\b', re.I), "type": "classified_en", "severity": "high"},
            # 商密标志（商密★3年、商业秘密★、核心商密★长期）：只认带 ★ 的写法；
            # 不带 ★ 的“商业秘密”是普通名词，不在这里认。
            {"pattern": re.compile(r'(?:核心商密|普通商密|商业秘密|商密)(?=\s*[★☆*＊])'), "type": "classified_cn", "severity": "high"},
        ]
        # 标头式写法本身就是标志，不需要再从窗口里找“文件/报告”佐证（标头后面常是会议纪要、方案、预算）：
        # 1) 国家秘密标志“密级★保密期限”：机密★10年、绝密★长期、秘密☆3个月；商密同形。
        #    ★ ☆ 可以不带期限；* ＊ 容易是 Markdown 加粗/通配符，必须紧跟期限，且前面不能紧挨另一个 *。
        self.classified_star_header = re.compile(
            r'(?:核心商密|普通商密|商业秘密|商密|机密|绝密|秘密)\s*(?:[★☆]\s*(?:\d{1,2}\s*(?:年|个月|月)|长期)?|'
            r'[*＊]\s*(?:\d{1,2}\s*(?:年|个月|月)|长期))'
        )
        # 2) 行首方括号/书名号式标头：【机密】［绝密］[秘密]；括号必须紧贴密级词，
        #    【机密计算】这类在括号里继续写别的词的不算，[机密](链接) 也不算。
        self.classified_bracket_header = re.compile(
            r'^[ \t]*[【\[［〔《][ \t]*(?:机密|绝密|秘密|商密|核心商密|普通商密)[ \t]*[】\]］〕》](?!\()',
            re.M,
        )
        # 3) 英文标头：整行大写（不含小写字母）且整行就是标头——标志后只能跟分隔符+大写说明
        #    （- DO NOT DISTRIBUTE、//NOFORN），或 DOCUMENT/MATERIAL/INFORMATION/MEMO 这类标头成分；
        #    后面跟别的业务名词（CLASSIFIED ADS MODULE、CONFIDENTIAL COMPUTING OVERVIEW、INTERNAL USE CASES）的不算。
        self.classified_en_header_line = re.compile(
            r'(?:(?:STRICTLY|HIGHLY|COMPANY|FIRM|PRIVATE\s+AND|NDA)\s+)?'
            r'(?:CONFIDENTIAL|TOP\s+SECRET|CLASSIFIED|INTERNAL\s+USE\s+ONLY)'
            r'(?:\s+(?:DOCUMENT|MATERIALS?|INFORMATION|MEMO(?:RANDUM)?|PROPRIETARY|DO\s+NOT\s+[A-Z ]+|NOT\s+FOR\s+[A-Z ]+))?'
            r'(?:\s*(?://|[-–—:])\s*[A-Z][A-Z0-9 /,.&-]{0,60})?'
        )
        # 密级词作为“标记”出现时才有语法位置：紧跟 ★/级/文档实体/冒号/右括号，
        # 或紧跟在“密级：/标注为/属于/【”之后。作为普通名词（“存在秘密”“保守秘密”）
        # 出现时，±80 字窗口里的“数据/协议”佐证只是同段落里的其他话题，不是标记。
        self.classified_marker_syntax_before = re.compile(
            r'(?:密级|等级|级别|定为|定密|标注为|标记为|标识为|标为|属于|视为|列为|归为|划为)\s*[:：为]?\s*$|'
            r'[【\[（(《「『]\s*$'
        )
        self.classified_marker_syntax_after = re.compile(
            r'^\s*(?:★|☆|级|等级|[:：]|[】\]）)》」』]|'
            r'文件|文档|资料|数据|信息|材料|档案|名单|清单|报告|合同|协议|附件|表格|记录|图纸|方案|计划|'
            r'会议|纪要|项目|技术|产品|客户|财务|人事|员工|工资|薪资|内容|事项|级别|等级|范围|文本)'
        )
        # 涉密近邻佐证：命中文档/数据/名单等实体，才算真的涉密数据外泄。
        self.classified_corroboration = re.compile(
            r'(文件|文档|资料|报告|合同|协议|名单|清单|数据|数据库|附件|表格|材料|'
            r'report|document|file|contract|agreement|dataset|attachment|memo|records?)',
            re.I,
        )
        # 强业务数据佐证：编码 agent 里也不能当普通代码注释降噪。
        # 这些词与涉密标记近邻出现时，基本已经不是“规则/文档提到机密”这种弱信号。
        self.classified_strong_corroboration = re.compile(
            r'(客户名单|客户清单|客户数据|客户资料|财务数据|财务报表|财务预测|工资表|薪资|'
            r'员工绩效|身份证|手机号|银行账户|合同|协议|数据库|'
            r'customer[-_\s]*(?:list|data|info|contract|agreement|records?)|'
            r'financial[-_\s]*(?:data|report|statement|forecast|budget)|'
            r'salary|payroll|employee[-_\s]*(?:review|eval|performance|records?|data))',
            re.I,
        )
        # 告警、规则、matched_summary、raw_evidence 等元讨论不是客户数据本体；
        # 先把这些标签化片段从近邻佐证窗口里剥掉，避免“数据泄露规则 ... raw_evidence=机密”误报。
        self.classified_meta_context = re.compile(
            r'(matched_summary|raw_evidence|evidence_reason|rule_name|rule_id|class_key|category|'
            r'counts_as_security_finding|安全告警|告警|规则|检测|命中|误报|分类)',
            re.I,
        )
        self.classified_meta_fragment = re.compile(
            r'(?:matched_summary|raw_evidence|evidence_reason|rule_name|rule_id|class_key|category|'
            r'counts_as_security_finding)\s*[:=][^,，。\n]{0,120}',
            re.I,
        )

        # 谈规则不是标记（2026-11-20 客户现场）：引号里的密级词后面紧跟“标记/字样/marker”，
        # 同一句里又有网关/拦截/检测语境，说的是“网关会拦含 X 标记的内容”，不是这段内容被标了密级。
        # 只排除这一处出现；同一段里另有真实标记照样命中。
        self.classified_quote_chars = "\"'“”‘’「」`"
        self.classified_mention_noun_after = re.compile(
            r'^\s*(?:classification\s+|sensitivity\s+|security\s+)?'
            r'(?:markers?|labels?|tags?|keywords?|strings?|words?|watermarks?|banners?|markings?)\b|'
            r'^\s*(?:密级)?(?:标记|标识|标签|字样|关键词|关键字|水印|字眼)',
            re.I,
        )
        self.classified_rule_context = re.compile(
            r'(gateway|firewall|\bdlp\b|proxy|filter|guardrail|\bblock(?:s|ed|ing)?\b|\breject(?:s|ed)?\b|'
            r'\bredact(?:s|ed)?\b|\bdetect(?:s|ed|ion)?\b|\bflag(?:s|ged)?\b|'
            r'网关|拦截|阻断|拦下|拦住|过滤|检测|识别|命中)',
            re.I,
        )
        # 叮嘱句：“不要把机密内容放进提示词”“禁止将绝密文件外传”是提醒，不是标记。
        self.classified_instruction_prefix = re.compile(
            r'(?:不要|不得|不能|不可|切勿|请勿|勿|禁止|严禁|避免|别)\s*(?:把|将|在|向|对|上传|外传|发送|粘贴|放入|输入)?\s*$'
        )

        # 敏感文件识别
        self.sensitive_files: List[Dict] = [
            {"pattern": re.compile(r'(?:internal[-_]?(?:doc|memo|report|plan|strategy))', re.I), "type": "internal_doc", "severity": "high"},
            {"pattern": re.compile(r'(?:customer[-_]?(?:list|data|info|contract|agreement))', re.I), "type": "customer_data", "severity": "high"},
            {"pattern": re.compile(r'(?:salary|payroll|employee[-_]?(?:review|eval|performance))', re.I), "type": "hr_data", "severity": "high"},
            {"pattern": re.compile(r'(?:financial[-_]?(?:report|statement|forecast|budget))', re.I), "type": "financial_data", "severity": "high"},
        ]

        # 代码泄露检测
        self.code_leak_patterns: List[Dict] = [
            {"pattern": re.compile(r"""(?:password|passwd|pwd)[ \t]*[:=][ \t]*(?:'[^'\r\n]{4,}'|"[^"\r\n]{4,}"|`[^`\r\n]{4,}`|[^\s,，;；`'"。！？：]{8,128})""", re.I), "type": "password_in_code", "severity": "critical"},
            {"pattern": re.compile(r'(?:access_key|accesskey|secret_key|secretkey)\s*[:=]\s*[\'\"][^\'\"]{4,}[\'\"]', re.I), "type": "access_key", "severity": "critical"},
            {"pattern": re.compile(
                r'(?:connection\s*[:=]\s*[\'\"])?'
                r'(?:(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://'
                r'[^\s\'\"]+@[^\s\'\"]+|'
                r'(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://'
                r'[^\s\'\"]*[?&](?:password|passwd|pwd|sslpassword|auth|token)=[^\s&\'\"]+)'
                r'(?:[\'\"])?',
                re.I,
            ), "type": "database_url", "severity": "critical"},
            {"pattern": re.compile(r'(?:private_key|privatekey|api_key|apikey)\s*[:=]\s*[\'\"][^\'\"]{4,}[\'\"]', re.I), "type": "api_key_leak", "severity": "critical"},
            {"pattern": re.compile(r'(?:token|secret)\s*[:=]\s*[\'\"][A-Za-z0-9_\-]{16,}[\'\"]', re.I), "type": "token_leak", "severity": "high"},
            {"pattern": re.compile(r'(?:AWS|Azure|GCP|阿里云|腾讯云|华为云)[A-Za-z0-9_\-\s]{0,40}(?:access[_\-\s]?key|secret|token|credential|client[_\-\s]?secret)\s*[:=]\s*[\'"]?[A-Za-z0-9_/\-+=]{12,}', re.I), "type": "cloud_credential", "severity": "critical"},
        ]

    def detect(self, content: str) -> List[Dict]:
        findings: List[Dict] = []
        for category, patterns in [
            ("classified", self.classified_markers),
            ("sensitive_file", self.sensitive_files),
            ("code_leak", self.code_leak_patterns),
        ]:
            for p in patterns:
                matches = self._password_matches(content) if p["type"] == "password_in_code" else p["pattern"].finditer(content)
                match = next((m for m in matches
                              if (category != "classified" or
                                  self._has_local_classified_corroboration(content, m))
                              and (category != "code_leak" or
                                   not is_empty_shell_parameter(content, m.start()) and
                                   self._has_literal_code_leak(p["type"], m.group()))
                              and (category != "sensitive_file" or
                                   self._has_sensitive_file_corroboration(content, m))), None)
                if match:
                    confidence = 0.9
                    triage: Dict[str, object] = {}
                    if category == "classified":
                        if not self._has_local_classified_corroboration(content, match):
                            # 单个 classified/confidential/机密 等普通词不是涉密文件外发证据。
                            continue
                        if self._has_strong_classified_corroboration(content, match):
                            triage = {
                                "cannot_downgrade": True,
                                "cannot_downgrade_reason": "strong_classified_data_corroboration",
                            }
                    findings.append({
                        "type": "data_leak",
                        "category": f"{category}_{p['type']}",
                        "severity": p["severity"],
                        "matched_text_preview": self._mask_preview(match.group()),
                        "raw_evidence": match.group(0),
                        "matched_location": f"content[{match.start()}:{match.end()}]",
                        "evidence_kind": "literal",
                        "evidence_reason": f"命中数据泄露{category}规则",
                        "rule_id": f"data_leak_{p['type']}",
                        "confidence": confidence,
                        "triage": triage,
                    })
        return findings

    @staticmethod
    def _password_matches(content):
        for key in re.finditer(r"(?:password|passwd|pwd)(?:\\*[\"'])?[ \t]*[:=][ \t]*", content, re.I):
            if is_empty_shell_parameter(content, key.start()):
                continue
            # 右边是函数调用或下标取值（request.form[…]、os.environ[…]、getpass(…)）：在读密码，不是写死密码。
            if re.match(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*[ \t]*[\[(]", content[key.end():key.end() + 96]):
                continue
            value = read_credential_value(content, key.end())
            minimum = 4 if any(q in content[key.end():value.start] for q in "\"'`") else 8
            if value.kind != "literal" or len(value.value) < minimum:
                continue
            end = value.end
            if end < len(content) and content[end] in "\"'`":
                end += 1
            # Reconstitute a match at original offsets. No decoded text is used
            # as evidence and the next assignment is scanned independently.
            yield re.compile(r"[\s\S]{%d}" % (end-key.start())).match(content, key.start())

    @staticmethod
    def _has_sensitive_file_corroboration(content, match):
        # A field/file stem is not a data record. Require a nearby literal
        # value, concrete file, or an explicit transfer signal, per occurrence.
        window = content[max(0, match.start()-60):match.end()+120]
        value = content[match.end():match.end()+100]
        return bool(
            re.search(r"^\s*[:=]\s*(?:[\"']?\d{2,}|[\[{])", value)
            or re.search(r"^\.(?:csv|xlsx?|pdf|docx?|json|parquet)\b", value, re.I)
            or re.search(r"发送|上传|导出|外传|\b(?:upload|export|exfiltrate|send)\b", window, re.I)
        )

    @staticmethod
    def _has_literal_code_leak(rule_type: str, evidence: str) -> bool:
        if rule_type == "cloud_credential":
            return True
        if rule_type == "password_in_code":
            # _password_matches already read the value with its full left
            # context; re-parsing the bare evidence would lose the string
            # boundary before the key and misjudge concatenated literals.
            return True
        if rule_type != "database_url":
            return has_literal_sensitive_config(evidence)
        # A connection endpoint is not a credential. Inspect only password
        # components; placeholder userinfo must not hide a literal query secret.
        match = re.search(r"""['"]([^'"]+)['"]""", evidence)
        raw_url = match.group(1) if match is not None else evidence.strip()
        scheme = re.search(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"]+",
            raw_url,
            re.IGNORECASE,
        )
        if scheme is None:
            return False
        return credential_url_has_literal(scheme.group(0))

    def _has_local_classified_corroboration(self, content: str, match: re.Match) -> bool:
        # Negated/synthetic labels describe the marker, not classified data.
        # Scope this to the immediate mention so another real label still wins.
        prefix = content[max(0, match.start()-24):match.start()]
        if re.search(r"(?:假|伪|非|模拟|示例|测试用|不属于|不是)\s*$|(?:fake|mock|synthetic|not)\s+$", prefix, re.I):
            return False
        if self.classified_instruction_prefix.search(prefix):
            return False
        if self._is_classified_rule_mention(content, match):
            return False
        if self._is_classified_en_noise(content, match):
            return False
        if self._is_classified_header(content, match):
            return True
        if not self._is_classified_marker_syntax(content, match):
            return False
        return bool(self.classified_corroboration.search(
            self._classified_evidence_window(content, match)
        ))

    _CLASSIFIED_EN_TECH_AFTER = re.compile(
        r"\s+(?:computing|compute|vms?|containers?|virtual\s+machines?|clusters?|enclaves?)\b", re.I)
    _CLASSIFIED_LICENSE_WORDS = re.compile(r"copyright|all rights reserved|proprietary|licen[sc]e|©", re.I)
    _CLASSIFIED_COMMENT_LINE = re.compile(r"[ \t]*(?:/\*|\*|//|#|--|;|<!--)")
    _CLASSIFIED_CODE_DEFINITION = re.compile(r"\b(?:enum|const|class|type)\b|[{}=]")
    _CLASSIFIED_TAXONOMY = re.compile(r"(?<![A-Za-z_])(?:PUBLIC|RESTRICTED|UNCLASSIFIED)(?![A-Za-z_])")

    def _is_classified_en_noise(self, content: str, match: re.Match) -> bool:
        """英文密级词不是标记的三种常见写法（2026-11-22，以不误报为先）：

        机密计算（confidential computing / VM / containers）这个技术名词；源码注释里的版权声明
        （proprietary and confidential）；数据分级的枚举取值（和 PUBLIC / RESTRICTED 并列的大写词）。
        """
        word = match.group()
        if not re.fullmatch(r"[A-Za-z ]+", word):
            return False
        if self._CLASSIFIED_EN_TECH_AFTER.match(content, match.end()):
            return True
        line_start = content.rfind("\n", 0, match.start()) + 1
        line_end = content.find("\n", match.end())
        if line_end == -1:
            line_end = len(content)
        if not word.isupper() and self._CLASSIFIED_COMMENT_LINE.match(content, line_start):
            previous_start = content.rfind("\n", 0, max(0, line_start - 1)) + 1
            if self._CLASSIFIED_LICENSE_WORDS.search(content[previous_start:line_end]):
                return True
        # 分级枚举只认两种写法：取值单独成行，或写在代码的枚举/常量定义里。
        # 散文里的逗号列表（PUBLIC, INTERNAL, CONFIDENTIAL file levels）维持 2.9.21 的口径，照常命中。
        if word.isupper() and self._CLASSIFIED_TAXONOMY.search(
                content[max(0, match.start() - 60):match.end() + 60]):
            line = content[line_start:line_end]
            if line.strip(" \t\r,;|-*\"'") == word or self._CLASSIFIED_CODE_DEFINITION.search(line):
                return True
        return False

    def _is_classified_rule_mention(self, content: str, match: re.Match) -> bool:
        """引号里的密级词 + 紧跟“标记/marker”名词 + 同句网关/拦截语境 → 在谈规则，不是标记。

        内容常是 JSON 再转义过的文本（\"CONFIDENTIAL\"、字面 \n），引号前后的反斜杠一并跳过。
        """
        start, end = match.start(), match.end()
        before = start - 1
        if before < 0 or content[before] not in self.classified_quote_chars:
            return False
        after = end
        if after < len(content) and content[after] == "\\":
            after += 1
        if after >= len(content) or content[after] not in self.classified_quote_chars:
            return False
        if not self.classified_mention_noun_after.search(content[after + 1:after + 40]):
            return False
        seps = ("\n", "\\n", "。", ". ", "! ", "? ", "！", "？")
        sentence_start = max(max(content.rfind(sep, 0, start) for sep in seps), start - 240, 0)
        ends = [i for i in (content.find(sep, end) for sep in seps) if i != -1]
        sentence_end = min(ends + [end + 240, len(content)])
        sentence = content[sentence_start:start] + " " + content[end:sentence_end]
        return bool(self.classified_rule_context.search(sentence))

    def _is_classified_header(self, content: str, match: re.Match) -> bool:
        """标头式密级标志：★+期限、行首括号式、整行大写英文。命中即是标志，不再要求文档词佐证。"""
        start, end = match.start(), match.end()
        star = self.classified_star_header.match(content, start)
        if star is not None and star.end() > end and content[start - 1:start] not in ("*", "＊"):
            return True
        line_start = content.rfind("\n", 0, start) + 1
        line_end = content.find("\n", end)
        if line_end == -1:
            line_end = len(content)
        line = content[line_start:line_end]
        bracket = self.classified_bracket_header.match(content, line_start)
        if bracket is not None and bracket.start() <= start < bracket.end():
            return True
        stripped = line.strip(" \t\r*#-_=[]()<>/\\|:;")
        # 单独一个 CONFIDENTIAL / CLASSIFIED 不算标头：讲这个标记本身、枚举取值、代码常量都长这样；
        # 要带修饰（STRICTLY…）、标头成分（DOCUMENT、DO NOT…）或分隔说明才算。它们仍可走文档词佐证的老路。
        return bool(
            stripped and len(stripped) <= 120
            and not re.search(r"[a-z\u4e00-\u9fff]", stripped)
            and stripped not in ("CONFIDENTIAL", "CLASSIFIED")
            and self.classified_en_header_line.fullmatch(stripped)
        )

    def _is_classified_marker_syntax(self, content: str, match: re.Match) -> bool:
        """机密/绝密/秘密 must sit in a marking position, not be a common noun.

        "证明存在秘密" and "保守商业机密" mention secrecy; "秘密★", "密级：机密",
        "【绝密】", "机密文件" and "绝密客户名单" mark data. Compound markers
        (内部文件/内部资料) and English markers keep the window corroboration only.
        """
        if not re.fullmatch(r"机密|绝密|秘密", match.group()):
            return True
        before = content[max(0, match.start()-12):match.start()]
        after = content[match.end():match.end()+8]
        return bool(self.classified_marker_syntax_after.match(after)
                    or self.classified_marker_syntax_before.search(before))

    def _has_strong_classified_corroboration(self, content: str, match: re.Match) -> bool:
        return bool(self.classified_strong_corroboration.search(
            self._classified_evidence_window(content, match)
        ))

    def _classified_evidence_window(self, content: str, match: re.Match) -> str:
        window_start = max(0, match.start() - 80)
        window_end = min(len(content), match.end() + 80)
        window = content[window_start:window_end]
        if self.classified_meta_context.search(window):
            evidence_window = self.classified_meta_fragment.sub(" ", window)
            return re.sub(r'涉密文件标记检测|数据泄露classified规则', ' ', evidence_window, flags=re.I)
        return window

    @staticmethod
    def _mask_preview(text: str) -> str:
        if len(text) <= 8:
            return "<MASKED>"
        return text[:4] + "****" + text[-4:]
