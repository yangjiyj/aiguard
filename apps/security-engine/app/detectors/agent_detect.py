"""
Agent 识别器 - 通过请求特征识别 AI 智能体类型
"""
import re
from typing import Dict, Optional


class AgentDetector:
    """识别 AI 智能体/IDE 插件类型"""

    AGENT_TYPE_ALIASES = {
        "claude-code": "claude_code",
        "github-copilot": "github_copilot",
        "roo-code": "cline",
        "continue": "continue_dev",
        "openai-codex": "openai_codex",
        "amazon-q": "amazon_q_developer",
        "amazon-q-developer": "amazon_q_developer",
        "gemini-code-assist": "gemini_code_assist",
        "sourcegraph-cody": "sourcegraph_cody",
        "replit-agent": "replit_ai",
        "replit-ai": "replit_ai",
        "auto-gpt": "autogpt_babyagi",
        "autogpt": "autogpt_babyagi",
        "autogpt-babyagi": "autogpt_babyagi",
        "babyagi": "autogpt_babyagi",
        "langchain": "langchain_llamaindex",
        "llama-index": "langchain_llamaindex",
        "llamaindex": "langchain_llamaindex",
        "langchain-llamaindex": "langchain_llamaindex",
        "crewai": "crewai_autogen",
        "autogen": "crewai_autogen",
        "crewai-autogen": "crewai_autogen",
        "dify": "dify_coze",
        "coze": "dify_coze",
        "dify-coze": "dify_coze",
    }

    AGENT_SIGNATURES: Dict[str, Dict] = {
        "claude_code": {
            "patterns": [re.compile(r'claude[-_]?code', re.I), re.compile(r'anthropic[-_]?cli', re.I)],
            "user_agent": [re.compile(r'ClaudeCode', re.I), re.compile(r'Anthropic', re.I)],
        },
        "cursor": {
            "patterns": [re.compile(r'cursor', re.I)],
            "user_agent": [re.compile(r'Cursor', re.I)],
        },
        "windsurf": {
            "patterns": [re.compile(r'windsurf', re.I), re.compile(r'cascade', re.I)],
            "user_agent": [re.compile(r'Windsurf', re.I), re.compile(r'Cascade', re.I)],
        },
        "github_copilot": {
            "patterns": [re.compile(r'github[-_]?copilot', re.I), re.compile(r'copilot', re.I)],
            "user_agent": [re.compile(r'GitHubCopilot', re.I)],
        },
        "openclaw": {
            "patterns": [re.compile(r'openclaw', re.I)],
            "user_agent": [re.compile(r'OpenClaw', re.I)],
        },
        "hermes": {
            "patterns": [re.compile(r'hermes', re.I)],
        },
        "opencode": {
            "patterns": [re.compile(r'opencode', re.I)],
        },
        "cline": {
            "patterns": [re.compile(r'cline', re.I), re.compile(r'roo[-_]?code', re.I)],
            "user_agent": [re.compile(r'Cline', re.I), re.compile(r'RooCode', re.I)],
        },
        "continue_dev": {
            "patterns": [re.compile(r'continue\.dev', re.I), re.compile(r'continue[-_]?plugin', re.I)],
        },
        "openai_codex": {
            "patterns": [re.compile(r'openai[-_\s]?codex', re.I), re.compile(r'codex[-_\s]?(?:desktop|cli)', re.I)],
            # 官方客户端 originator：codex_cli_rs / codex-tui / codex_vscode / codex_exec /
            # codex_sdk_ts / codex_atlas / codex_chatgpt_desktop / codex_work_*，与
            # packages/shared-go/aiadapters/adapters/agent-registry.json 保持一致。
            "user_agent": [
                re.compile(r'Codex Desktop', re.I), re.compile(r'codex-cli', re.I),
                re.compile(
                    r'(?:^|[\s(;])codex(?:_cli_rs|-tui|_vscode|_exec|_cli|_sdk_ts|_atlas|_chatgpt_desktop|_work_[a-z]+)/',
                    re.I,
                ),
            ],
        },
        "aider": {
            "patterns": [re.compile(r'aider(?:-chat)?', re.I)],
            "user_agent": [re.compile(r'aider(?:-chat)?', re.I)],
        },
        "amazon_q_developer": {
            "patterns": [re.compile(r'amazon\s+q\s+developer', re.I), re.compile(r'aws[-_\s]?q[-_\s]?developer', re.I)],
            "user_agent": [re.compile(r'Amazon Q Developer', re.I)],
        },
        "gemini_code_assist": {
            "patterns": [re.compile(r'gemini\s+code\s+assist', re.I)],
            "user_agent": [re.compile(r'Gemini Code Assist', re.I)],
        },
        "tabnine": {
            "patterns": [re.compile(r'tabnine', re.I)],
            "user_agent": [re.compile(r'Tabnine', re.I)],
        },
        "sourcegraph_cody": {
            "patterns": [re.compile(r'(?:sourcegraph\s+)?cody(?:\s+ai)?', re.I)],
            "user_agent": [re.compile(r'Sourcegraph Cody', re.I)],
        },
        "replit_ai": {
            "patterns": [re.compile(r'replit\s+(?:ai|agent)', re.I)],
            "user_agent": [re.compile(r'Replit Agent', re.I)],
        },
        "coderabbit": {
            "patterns": [re.compile(r'coderabbit(?:\.ai)?', re.I)],
            "user_agent": [re.compile(r'CodeRabbit', re.I)],
        },
        "autogpt_babyagi": {
            "patterns": [re.compile(r'auto[-_\s]?gpt', re.I), re.compile(r'baby\s*agi', re.I)],
            "user_agent": [re.compile(r'AutoGPT|BabyAGI', re.I)],
        },
        "langchain_llamaindex": {
            "patterns": [re.compile(r'langchain', re.I), re.compile(r'llama\s*index', re.I)],
            "user_agent": [re.compile(r'LangChain|LlamaIndex', re.I)],
        },
        "crewai_autogen": {
            "patterns": [re.compile(r'crewai', re.I), re.compile(r'(?:microsoft\s+)?autogen', re.I)],
            "user_agent": [re.compile(r'CrewAI|Microsoft AutoGen', re.I)],
        },
        "dify_coze": {
            "patterns": [re.compile(r'\bdify\b', re.I), re.compile(r'\bcoze\b', re.I)],
            "user_agent": [re.compile(r'Dify|Coze', re.I)],
        },
    }

    @classmethod
    def identify_type(cls, agent_type: Optional[str], confidence: float = 1.0) -> Optional[Dict]:
        """把网关已鉴别的 AgentType 转成策略能力使用的稳定类别。"""
        value = str(agent_type or "").strip().lower().replace(" ", "-")
        if not value:
            return None
        canonical = cls.AGENT_TYPE_ALIASES.get(value, value.replace("-", "_"))
        if canonical not in cls.AGENT_SIGNATURES:
            return None
        try:
            normalized_confidence = float(confidence)
        except (TypeError, ValueError):
            normalized_confidence = 1.0
        return {
            "agent_type": canonical,
            "confidence": max(0.0, min(normalized_confidence, 1.0)),
        }

    def identify(self, headers: Optional[Dict], session_context: Optional[Dict] = None) -> Optional[Dict]:
        """识别 Agent 类型，返回 agent_type 和 confidence"""
        if not headers:
            return None

        user_agent = headers.get("user-agent", "") or headers.get("User-Agent", "") or ""
        content_type = headers.get("content-type", "") or ""

        best_match = None
        best_score = 0.0

        for agent_name, sig in self.AGENT_SIGNATURES.items():
            score = 0.0

            # Check user-agent header
            ua_patterns = sig.get("user_agent", [])
            for ua_pattern in ua_patterns:
                if ua_pattern.search(user_agent):
                    score += 0.6

            # Check content patterns
            for pattern in sig.get("patterns", []):
                if pattern.search(user_agent):
                    score += 0.3
                if pattern.search(content_type):
                    score += 0.2

            if score > best_score:
                best_score = score
                best_match = agent_name

        if best_match and best_score >= 0.3:
            return {
                "agent_type": best_match,
                "confidence": min(best_score, 1.0),
            }

        return None
