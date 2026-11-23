"""编程智能体塞进 user 消息的上下文区段（非员工亲手输入）。

Claude Code / Codex 等客户端会把 <system-reminder>（CLAUDE.md、记忆、@ 引用的文件）、
本地命令输出、会话续接摘要、AGENTS.md 指令等拼进 user 消息。这些区段是数据，不是
员工的请求：意图类规则只看剩余文字，确定性 DLP 仍扫全文。

Codex 的格式逐字对照 openai/codex 源码（rust-v0.150.0 ~ rust-v0.170.0）：
AGENTS.md（core/src/context/user_instructions.rs）、<environment_context>、<skill>
（ext/skills/src/fragments.rs）、<user_shell_command>、<turn_aborted>、/review 结果
<user_action>（prompts/templates/review/exit_success.xml）、<subagent_notification>、
<codex_internal_context source="...">、会话压缩摘要（prompts/templates/compact/summary_prefix.md）。

只识别边界明确的结构：标签必须成对闭合，续接摘要必须带固定开头并能找到收尾句或
下一个智能体区段。识别不了的内容按员工输入处理（宁可多扫，不放过）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

# 成对标签：内容全部由客户端生成。<command-args>、<bash-input>、<user_query> 是员工
# 亲手输入，故意不在此列。
_AGENT_TAGS = (
    "system-reminder", "system_reminder",
    "command-name", "command-message",
    "local-command-stdout", "local-command-stderr", "local-command-caveat",
    "bash-stdout", "bash-stderr", "task-notification",
    "environment_context", "environment_details", "user_instructions",
    "turn_aborted", "skills_instructions", "available_skills", "tools_changed_notice",
    # Codex：选中的 skill 正文、/review 结果、子代理状态通知。
    "skill", "user_action", "subagent_notification",
)
_OPEN_TAG_RE = re.compile(
    r"<(" + "|".join(re.escape(tag) for tag in _AGENT_TAGS) + r")(?=[\s>])[^<>]{0,512}>",
    re.I,
)
# Codex 的 AGENTS.md：没有目录时标题只有 "# AGENTS.md instructions"。
_AGENTS_MD_RE = re.compile(
    r"(?im)^[ \t]*#[ \t]*AGENTS\.md instructions(?:[ \t]+for[ \t][^\n]{0,1024})?[ \t]*\n\s{0,16}<INSTRUCTIONS>"
)
_INSTRUCTIONS_CLOSE_RE = re.compile(r"</INSTRUCTIONS>", re.I)
# Codex 内部上下文：source 必须是协议规定的标识符。source="user_goal" 是员工用 /goal
# 设定的目标原话，按员工输入处理。
_INTERNAL_CONTEXT_OPEN_RE = re.compile(r'<codex_internal_context source="([a-z][a-z0-9_]*)">')
_INTERNAL_CONTEXT_CLOSE = "</codex_internal_context>"
_EMPLOYEE_INTERNAL_SOURCES = frozenset({"user_goal"})
# Codex 用户 ! 命令：<command> 是员工亲手敲的，只有 <result>（命令输出）是数据。
_SHELL_COMMAND_OPEN = "<user_shell_command>"
_SHELL_COMMAND_CLOSE = "</user_shell_command>"
_SHELL_RESULT_RE = re.compile(r"</command>\s{0,4}(<result>)")
# Codex 会话压缩摘要：整条 user 消息 = 固定前缀 + "\n" + 模型写的摘要（core/src/compact.rs
# format!("{SUMMARY_PREFIX}\n{summary}")，判定也用 starts_with(SUMMARY_PREFIX + "\n")）。
CODEX_SUMMARY_PREFIX = (
    "Another language model started to solve this problem and produced a summary of its thinking "
    "process. You also have access to the state of the tools that were used by that language model. "
    "Use this to build on the work that has already been done and avoid duplicating work. Here is the "
    "summary produced by the other language model, use the information in this summary to assist with "
    "your own analysis:\n"
)
_SUMMARY_START_RE = re.compile(
    r"(?i)(?:^|\n)[ \t]*(This session is being continued from a previous conversation "
    r"that ran out of context\.)"
)
_SUMMARY_MARKER_RE = re.compile(r"(?i)summar")
_SUMMARY_END_RES = (
    re.compile(r"(?i)Continue with the last task that you were asked to work on\.?"),
    re.compile(r"(?i)without asking the user any further questions\.?"),
)
_SUMMARY_MARKER_WINDOW = 400


@dataclass(frozen=True)
class AgentContextSplit:
    """``spans`` 为 [start, end) 的智能体区段，已排序合并。"""

    text: str
    spans: tuple[tuple[int, int], ...]

    def _blank(self, keep_agent: bool) -> str:
        chars = list(self.text)
        cursor = 0
        ranges = []
        for start, end in self.spans:
            ranges.append((cursor, start, not keep_agent))
            ranges.append((start, end, keep_agent))
            cursor = end
        ranges.append((cursor, len(chars), not keep_agent))
        for start, end, keep in ranges:
            if keep:
                continue
            for index in range(start, end):
                if chars[index] != "\n":
                    chars[index] = " "
        return "".join(chars)

    @property
    def employee_view(self) -> str:
        """与原文等长：智能体区段替换为空白（保留换行），偏移量不变。"""
        return self._blank(keep_agent=False)

    @property
    def agent_view(self) -> str:
        """与原文等长：只保留智能体区段。"""
        return self._blank(keep_agent=True)

    def employee_segments(self) -> list[tuple[int, int]]:
        segments = []
        cursor = 0
        for start, end in self.spans + ((len(self.text), len(self.text)),):
            piece = self.text[cursor:start]
            left = len(piece) - len(piece.lstrip())
            right = len(piece.rstrip())
            if right > left:
                segments.append((cursor + left, cursor + right))
            cursor = end
        return segments

    def compact(self) -> "CompactView":
        """员工输入片段用换行拼接，供语义层使用（不让大段空白挤占裁判预算）。"""
        parts = []
        mapping = []
        position = 0
        for start, end in self.employee_segments():
            if parts:
                parts.append("\n")
                position += 1
            parts.append(self.text[start:end])
            mapping.append((position, position + end - start, start))
            position += end - start
        return CompactView("".join(parts), tuple(mapping))


@dataclass(frozen=True)
class CompactView:
    text: str
    # (view_start, view_end, original_start)
    mapping: tuple[tuple[int, int, int], ...]

    def original_offset(self, value: int, *, end: bool = False) -> Optional[int]:
        for view_start, view_end, original_start in self.mapping:
            if view_start <= value < view_end or (end and value == view_end):
                return original_start + value - view_start
        return None


@lru_cache(maxsize=None)
def _close_tag_re(tag: str) -> re.Pattern:
    return re.compile(r"</" + re.escape(tag) + r"\s*>", re.I)


def _tag_spans(text: str) -> list[tuple[int, int]]:
    spans = []
    position = 0
    unclosed: set[str] = set()
    while True:
        match = _OPEN_TAG_RE.search(text, position)
        if match is None:
            break
        tag = match.group(1).lower()
        if tag in unclosed:
            position = match.end()
            continue
        close = _close_tag_re(tag).search(text, match.end())
        if close is None:
            # 没有闭合就不知道边界：剩余部分按员工输入扫描。
            unclosed.add(tag)
            position = match.end()
            continue
        spans.append((match.start(), close.end()))
        position = close.end()
    for match in _AGENTS_MD_RE.finditer(text):
        close = _INSTRUCTIONS_CLOSE_RE.search(text, match.end())
        if close is not None:
            spans.append((match.start(), close.end()))
    spans.extend(_internal_context_spans(text))
    spans.extend(_shell_result_spans(text))
    return spans


def _internal_context_spans(text: str) -> list[tuple[int, int]]:
    spans = []
    position = 0
    while True:
        match = _INTERNAL_CONTEXT_OPEN_RE.search(text, position)
        if match is None:
            return spans
        close = text.find(_INTERNAL_CONTEXT_CLOSE, match.end())
        if close < 0:
            return spans
        end = close + len(_INTERNAL_CONTEXT_CLOSE)
        if match.group(1) not in _EMPLOYEE_INTERNAL_SOURCES:
            spans.append((match.start(), end))
        position = end


def _shell_result_spans(text: str) -> list[tuple[int, int]]:
    spans = []
    position = 0
    while True:
        start = text.find(_SHELL_COMMAND_OPEN, position)
        if start < 0:
            return spans
        close = text.find(_SHELL_COMMAND_CLOSE, start)
        if close < 0:
            return spans
        block = text[start:close]
        result = _SHELL_RESULT_RE.search(block)
        result_close = block.rfind("</result>")
        if result is not None and result_close > result.start(1):
            spans.append((start + result.start(1), start + result_close + len("</result>")))
        position = close + len(_SHELL_COMMAND_CLOSE)


def _codex_summary_spans(text: str) -> list[tuple[int, int]]:
    """压缩摘要只认整条消息以完整前缀开头；摘要一直到消息结尾都是模型写的。"""
    start = len(text) - len(text.lstrip())
    if text.startswith(CODEX_SUMMARY_PREFIX, start):
        return [(start, len(text))]
    return []


def _summary_spans(text: str, block_spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    spans = []
    for match in _SUMMARY_START_RE.finditer(text):
        start = match.start(1)
        if any(a <= start < b for a, b in block_spans + spans):
            continue
        window = text[match.end(1):match.end(1) + _SUMMARY_MARKER_WINDOW]
        if not _SUMMARY_MARKER_RE.search(window):
            continue
        end = None
        for pattern in _SUMMARY_END_RES:
            found = pattern.search(text, match.end(1))
            if found is not None:
                end = found.end()
                break
        if end is None:
            following = [a for a, _ in block_spans if a > start]
            end = min(following) if following else len(text)
        spans.append((start, end))
    return spans


def _merge(spans: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return tuple((start, end) for start, end in merged)


def split_agent_context(text: str, limit: Optional[int] = None) -> AgentContextSplit:
    """识别 ``text[:limit]`` 中的智能体区段；limit 之后（如附件正文）不参与识别。"""
    region = text if limit is None else text[:max(0, limit)]
    lowered = region.lower()
    if (
        "<" not in region
        and "continued from a previous conversation" not in lowered
        and not region.lstrip().startswith(CODEX_SUMMARY_PREFIX)
    ):
        return AgentContextSplit(text, ())
    # 不用 str.lower() 后的偏移：个别 Unicode 字符小写后长度会变。
    blocks = _tag_spans(region)
    spans = blocks + _summary_spans(region, blocks) + _codex_summary_spans(region)
    return AgentContextSplit(text, _merge(spans))
