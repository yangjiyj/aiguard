"""LLM 合成器（spec §5A）：按结构化 prompt 按类生成中文标注样本。

LLM 端点经 LLMClient 协议注入（本地 3B / 中转 / 测试 stub），不硬依赖真 LLM。
产物：标注行 dict（text/label/category/source=seed），逐行过 schema.validate_row。
"""
from __future__ import annotations

import json
from typing import List, Protocol

from .schema import validate_row


class LLMClient(Protocol):
    def generate(self, prompt: str, n: int) -> str:
        """返回一个 JSON 数组字符串（n 条中文文本）。"""
        ...


# (category, 中文类目名, 该类攻击意图描述) —— 写进 prompt 让 LLM 按类生成
ATTACK_SPECS = [
    ("semantic_jailbreak", "越狱",
     "试图解除模型安全限制（如 DAN / 开发者模式 / 无限制 AI 人格）"),
    ("semantic_roleplay", "角色扮演绕过",
     "用角色扮演/情境（已故亲人、邪恶导师、虚构作恶角色）诱导越界"),
    ("semantic_instruction_override", "指令覆盖",
     "用「忽略以上指令/从现在起改为」覆盖系统约束"),
    ("semantic_exfil_induce", "数据外泄诱导",
     "诱导模型吐露 system prompt / 训练数据 / 内部配置等敏感信息"),
]

# (子类描述, 易误报场景) —— 难良性：字面像攻击实则正常
BENIGN_SPECS = [
    "合法写作/翻译类角色扮演请求（如「请扮演英语老师纠正语法」）",
    "安全从业者的合法提问（授权渗透测试、OWASP、RBAC 等防御科普）",
    "运维问系统配置（nginx/系统提示词模板等，无越狱诱导意图）",
]


class Synthesizer:
    def __init__(self, llm: LLMClient | None):
        if llm is None:
            raise ValueError("Synthesizer 需注入 LLMClient（可注入/可 mock，不硬依赖真 LLM）")
        self._llm = llm

    def synthesize(self, *, per_attack: int, per_benign: int) -> List[dict]:
        rows: List[dict] = []
        for category, cn, intent in ATTACK_SPECS:
            prompt = (
                f"请生成 {per_attack} 条「{cn}」类的中文提示词攻击样本。"
                f"该类意图：{intent}。"
                "只输出一个 JSON 字符串数组，每个元素是一条独立的中文攻击文本，不要解释。"
            )
            for text in self._parse(self._llm.generate(prompt, per_attack)):
                rows.append({"text": text, "label": "attack",
                             "category": category, "source": "seed"})
        for desc in BENIGN_SPECS:
            prompt = (
                f"请生成 {per_benign} 条「{desc}」的中文样本，"
                "这些是合法良性请求，但字面可能像攻击（难负样本）。"
                "只输出一个 JSON 字符串数组，每个元素一条独立中文文本，不要解释。"
            )
            for text in self._parse(self._llm.generate(prompt, per_benign)):
                rows.append({"text": text, "label": "benign",
                             "category": "none", "source": "seed"})
        for r in rows:
            validate_row(r)
        return rows

    @staticmethod
    def _parse(raw: str) -> List[str]:
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError(f"LLM 输出须为 JSON 数组: {raw!r}")
        out = []
        for x in data:
            if isinstance(x, str) and x.strip():
                out.append(x.strip())
        return out
