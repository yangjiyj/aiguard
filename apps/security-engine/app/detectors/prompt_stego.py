"""Unicode formatting observations and corroborated instruction obfuscation."""
import re
from app.detectors.evidence_context import observation
from app.detectors.prompt_injection import ACTIONABLE_INJECTION_HINTS
from typing import Dict, List

from app.detectors.ai_content_watermark import find_watermark_spans


class PromptStegoDetector:
    """保留格式特征，仅将有攻击指令佐证的混淆作为风险。"""

    def __init__(self):
        # 撇号格式变体；字符本身不能证明客户端环境或攻击意图
        # U+0027 是普通 ASCII 撇号；其他变体保留为格式观察
        self.stego_apostrophes: Dict[int, str] = {
            0x2019: "右单引号(U+2019)",
            0x02BC: "修饰字母撇号(U+02BC)",
            0x02B9: "修饰字母prime(U+02B9)",
        }

        # 检测 "Today's date" 句中的撇号变种
        # 匹配 Today 后紧跟一个字符再跟 s 的模式
        self.today_pattern = re.compile(r"Today(.)s\s+date\s+is", re.IGNORECASE)

        # 检测日期分隔符变种（YYYY/MM/DD 在 Today 句中）
        # 日期分隔符有多种合法格式，不据此推断时区或攻击
        self.date_slash_pattern = re.compile(
            r"Today.\s*s\s+date\s+is\s+(\d{4})/(\d{2})/(\d{2})", re.IGNORECASE
        )

        # 通用零宽字符隐写（覆盖更广的隐写手法）
        self.zero_width_chars: Dict[int, str] = {
            0x200B: "零宽空格(U+200B)",
            0x200C: "零宽非连接符(U+200C)",
            0x200D: "零宽连接符(U+200D)",
            0xFEFF: "字节顺序标记(U+FEFF)",
        }

        # 其他 Unicode 引号/撇号格式变体
        self.suspicious_quote_variants: Dict[int, str] = {
            0x2018: "左单引号(U+2018)",
            0x201A: "单低引号(U+201A)",
            0x201B: "单右引号反转(U+201B)",
            0x2032: "prime(U+2032)",
        }

    def detect(self, content: str) -> List[Dict]:
        findings: List[Dict] = []

        # 1. Today 句子里的撇号变种
        for m in self.today_pattern.finditer(content):
            ch = m.group(1)
            cp = ord(ch)
            if cp in self.stego_apostrophes:
                desc = self.stego_apostrophes[cp]
                findings.append({
                    "type": "prompt_stego",
                    "category": "apostrophe_variant",
                    "severity": "high",
                    "matched_text_preview": self._mask_preview(m.group()),
                    "rule_id": f"prompt_stego_apos_{cp:04x}",
                    "rule_name": f"Prompt隐写: {desc}",
                    "confidence": 0.95,
                    "matched_location": f"content[{m.start()}:{m.end()}]",
                    "redacted_evidence": f"Today{{U+{cp:04X}}}s date is ...",
                    "raw_evidence": m.group(0),
                    "evidence_kind": "literal",
                    "evidence_reason": f"Today 日期句使用非标准撇号 U+{cp:04X}",
                })

        # 2. 日期分隔符变种（斜杠代替连字符）
        for m in self.date_slash_pattern.finditer(content):
            findings.append({
                "type": "prompt_stego",
                "category": "date_separator_variant",
                "severity": "medium",
                "matched_text_preview": self._mask_preview(m.group()),
                "rule_id": "prompt_stego_date_slash",
                "rule_name": "Prompt格式: 日期分隔符变种(/)",
                "confidence": 0.85,
                "matched_location": f"content[{m.start()}:{m.end()}]",
                "redacted_evidence": f"date={m.group(1)}/{m.group(2)}/{m.group(3)}",
                "raw_evidence": m.group(0),
                "evidence_kind": "literal",
                "evidence_reason": "Today 日期句使用斜杠分隔日期",
            })

        # 3. 零宽字符隐写（P1-A：同类型合并为单 finding 计数，不再逐字符爆炸）
        zw_positions: Dict[int, List[int]] = {}
        # 网关给门户回复加的 AI 生成内容水印帧不是隐写；只排除格式完整的帧，帧外的零宽字符照旧检测。
        watermark_spans = find_watermark_spans(content)
        span_index = 0
        for i, ch in enumerate(content):
            while span_index < len(watermark_spans) and i >= watermark_spans[span_index][1]:
                span_index += 1
            if span_index < len(watermark_spans) and watermark_spans[span_index][0] <= i:
                continue
            cp = ord(ch)
            if cp in self.zero_width_chars:
                zw_positions.setdefault(cp, []).append(i)
        for cp, positions in zw_positions.items():
            desc = self.zero_width_chars[cp]
            finding = {
                "type": "prompt_stego",
                "category": "zero_width_char",
                "severity": "high",
                "matched_text_preview": f"{desc} ×{len(positions)}",
                "rule_id": f"prompt_stego_zw_{cp:04x}",
                "rule_name": f"Prompt隐写: {desc}",
                "confidence": 0.9,
                "matched_location": f"count={len(positions)}, first_offset={positions[0]}",
                "redacted_evidence": f"count={len(positions)}",
                "raw_evidence": chr(cp),
                "evidence_kind": "literal",
                "evidence_reason": f"检测到{desc}，共 {len(positions)} 处",
            }
            if (
                cp == 0xFEFF
                and len(positions) == 1
                and self._is_line_boundary(content, positions[0])
            ):
                # UTF-8 BOM 在文件拼接后常落在正文或 Markdown 行首。单个、边界位置
                # 只能证明编码格式残留，不能证明字符混淆；保留技术证据但不形成风险。
                finding.update({
                    "severity": "low",
                    "confidence": 0.2,
                    "action": "allow",
                    "counts_as_security_finding": False,
                    "evidence_reason": "检测到行首单个字节顺序标记(U+FEFF)，按文件编码残留留观",
                    "triage": {
                        "disposition": "observation",
                        "disposition_reason": "single_bom_at_text_boundary",
                    },
                })
            findings.append(finding)

        # 4. Today 句中的可疑引号变体（左单引号等，非标准）
        for m in self.today_pattern.finditer(content):
            ch = m.group(1)
            cp = ord(ch)
            if cp in self.suspicious_quote_variants:
                desc = self.suspicious_quote_variants[cp]
                findings.append({
                    "type": "prompt_stego",
                    "category": "quote_variant",
                    "severity": "medium",
                    "matched_text_preview": self._mask_preview(m.group()),
                    "rule_id": f"prompt_stego_quote_{cp:04x}",
                    "rule_name": f"Prompt隐写: 可疑引号变体({desc})",
                    "confidence": 0.7,
                    "matched_location": f"content[{m.start()}:{m.end()}]",
                    "redacted_evidence": f"Today{{U+{cp:04X}}}s date is ...",
                    "raw_evidence": m.group(0),
                    "evidence_kind": "literal",
                    "evidence_reason": f"Today 日期句使用可疑引号 U+{cp:04X}",
                })

        for finding in findings:
            if not finding.get("counts_as_security_finding", True):
                continue
            positions = zw_positions.get(int(finding["rule_id"].rsplit("_", 1)[-1], 16), []) if finding["category"] == "zero_width_char" else []
            suspicious = False
            for position in positions:
                local = content[max(0, position-160):position+160]
                normalized = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", local)
                if ACTIONABLE_INJECTION_HINTS.search(normalized):
                    suspicious = True
                    break
            if finding["category"] != "zero_width_char" or not suspicious:
                finding.update(severity="low", confidence=0.2)
                finding["triage"] = {**finding.get("triage", {}), "severity_downgrade_reason": "仅发现可疑 Unicode 字符变体，未见攻击指令佐证"}
                observation(finding, "unicode_formatting_without_attack_evidence")
            else:
                finding.setdefault("triage", {})["confidence_kind"] = "heuristic_rule_score"
        return findings

    @staticmethod
    def _is_line_boundary(content: str, position: int) -> bool:
        if position == 0:
            return True
        line_start = max(
            content.rfind("\n", 0, position),
            content.rfind("\r", 0, position),
        ) + 1
        return content[line_start:position].strip() == ""

    @staticmethod
    def _mask_preview(text: str) -> str:
        if len(text) <= 12:
            return text
        return text[:6] + "..." + text[-6:]
