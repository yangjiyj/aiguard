// Package aimsg 把 Anthropic Messages、OpenAI Chat Completions 与 Responses 请求体解析为
// 统一的结构化消息数组（设计文档模块 1a：messages: [{role, source, content, content_sha256}]）。
// C 路（proxy-server 正代解码器）与 B 路（gateway-core 反代检测/留证）复用本包，实现放 shared-go；
// A 路（网关 key 转发）已有原生结构化消息，不经本包（其 role→source 映射归 Plan A，契约 4）。
// 仅依赖标准库。
package aimsg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// source 取值（共享契约：与 security-engine CheckInputRequest.content_source 枚举一致）。
const (
	SourceSystemPrompt     = "system_prompt"
	SourceUser             = "user"
	SourceAssistantHistory = "assistant_history"
	SourceToolResult       = "tool_result"
	SourceToolDef          = "tool_def"
	SourceUnknown          = "unknown"
)

// ConvMessage 是结构化消息的统一产物（设计 1a：{role, source, content, content_sha256}）。
// Role 保留线上原始角色（system/user/assistant/tool），Source 是检测档位归类。
type ConvMessage struct {
	Role          string `json:"role"`
	Source        string `json:"source"`
	Content       string `json:"content"`
	ContentSHA256 string `json:"content_sha256"`
	// Original protocol position; synthetic system/tool definitions have no message index.
	MessageIndex        *int            `json:"message_index,omitempty"`
	SourcePath          string          `json:"source_path,omitempty"`
	HasAttachments      bool            `json:"-"`
	RawContent          json.RawMessage `json:"-"`
	InspectionIsHistory bool            `json:"inspection_is_history"`
	IsLatestUser        bool            `json:"is_latest_user"`
}

// InlineImage 是请求体内嵌的 base64 图片块（Claude Code 粘贴截图等），
// 由调用方（proxy-server）转成自己的附件类型落留证；gateway 侧忽略。
type InlineImage struct {
	MediaType  string
	DataBase64 string
}

// ParsedChat 是一次 chat 型 API 请求体的解析产物。
type ParsedChat struct {
	Model    string
	Messages []ConvMessage
	// SystemText 是原始 system 全文（多块以 \n 拼接），供 aiconvo.SystemDigest 使用。
	SystemText string
	// FirstUserSHA 是首条 Source==user 且非空消息的 ContentSHA256，供 aiconvo.ConversationKey。
	FirstUserSHA string
	// LastUserText/LastUserSHA 标识当前用户回合；留证只展示该文本，SHA 用作 section_id。
	// 找不到真实 user 来源时保持为空，调用方不得用 unknown 内容猜测用户回合。
	LastUserText string
	LastUserSHA  string
	// ToolsDigest 是全部 tool_def 消息内容按序拼接后的 sha256（设计 1a：统一产物附 tools_digest；
	// P2 运行环境卡用它判定"工具模板未改动/已变化"）。无 tool_def 时为空。
	ToolsDigest string
	Images      []InlineImage
	Artifacts   []retentionartifact.Candidate
	Projection  RetentionProjection
}

// ContentSHA256Hex 返回内容的 sha256 十六进制小写摘要。
func ContentSHA256Hex(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func newConvMessage(role, source, content string) ConvMessage {
	return ConvMessage{Role: role, Source: source, Content: content, ContentSHA256: ContentSHA256Hex(content)}
}

// FlattenMessages 把消息数组平铺为单段文本（双形态里的"平铺 Text"）：
// 各条 Content 按原序以 \n 连接、不加角色标记，与旧 collectJSONText
// "只收字符串值平铺"的行为对齐——旧消费方（留证写路径、C 路检测 content）零改动。
func FlattenMessages(msgs []ConvMessage) string {
	parts := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if s := strings.TrimSpace(m.Content); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n")
}

// firstUserSHA 取首条 user 来源非空消息的 sha。
func firstUserSHA(msgs []ConvMessage) string {
	for _, m := range msgs {
		content, status := retainedUserProjection(m)
		if status == ParseComplete && strings.TrimSpace(content) != "" {
			return ContentSHA256Hex(content)
		}
	}
	return ""
}

// finalizeParsedChat 统一填充解析后摘要，防止各协议解析器的回合口径漂移。
func finalizeParsedChat(out *ParsedChat) {
	if out == nil {
		return
	}
	out.FirstUserSHA = firstUserSHA(out.Messages)
	for i := len(out.Messages) - 1; i >= 0; i-- {
		message := out.Messages[i]
		content, status := retainedUserProjection(message)
		if status != ParseComplete || strings.TrimSpace(content) == "" {
			continue
		}
		out.LastUserText = content
		out.LastUserSHA = ContentSHA256Hex(content)
		break
	}
	out.ToolsDigest = toolsDigest(out.Messages)
	out.Artifacts = retentionartifact.Deduplicate(out.Artifacts)
	status := ParseAmbiguous
	if out.LastUserText != "" {
		status = ParseComplete
	}
	out.Projection = RetentionProjection{
		UserInput:       out.LastUserText,
		UserInputSHA256: out.LastUserSHA,
		TurnKey:         out.LastUserSHA,
		Model:           out.Model,
		ParserName:      "aimsg",
		ParserVersion:   "v1",
		Status:          status,
		Artifacts:       append([]retentionartifact.Candidate(nil), out.Artifacts...),
	}
}

// IsRetainedUserTurnCandidate 只影响客户内容留证的回合选取，不改变消息的
// SourceUser。平台编排信封仍按原来源进入安全链，不能凭可伪造文本获得检测白名单。
func IsRetainedUserTurnCandidate(message ConvMessage) bool {
	content := strings.TrimSpace(message.Content)
	return message.Source == SourceUser && content != "" && !isOrchestratorUserEnvelope(content)
}

// isOrchestratorUserEnvelope 识别 Codex 桌面端追加到 Responses 历史中的固定结构信封。
// 这些信封在协议上仍是 role=user，但不是人类输入；匹配要求完整的多段结构，
// 避免把普通讨论 checkpoint、AGENTS.md 或附件的用户文本误排除。
func isOrchestratorUserEnvelope(content string) bool {
	content = strings.TrimSpace(content)
	switch {
	case strings.HasPrefix(content,
		"You are performing a CONTEXT CHECKPOINT COMPACTION. Create a handoff summary for another LLM that will resume the task."):
		return strings.Contains(content, "Current progress and key decisions made") &&
			strings.Contains(content, "Important context, constraints, or user preferences") &&
			strings.Contains(content, "What remains to be done")
	case strings.HasPrefix(content,
		"Another language model started to solve this problem and produced a summary of its thinking process."):
		return strings.Contains(content, "avoid duplicating work") &&
			strings.Contains(content, "Here is the summary produced by the other language model")
	case strings.HasPrefix(content, "# AGENTS.md instructions"):
		return strings.Contains(content, "<INSTRUCTIONS>") &&
			strings.Contains(content, "</INSTRUCTIONS>") &&
			strings.Contains(content, "<environment_context>")
	case strings.HasPrefix(content, "# Overview"):
		return strings.Contains(content,
			"Generate 0 to 3 hyperpersonalized suggestions for what this user can do with Codex") &&
			strings.Contains(content,
				"Get an understanding of the user's intent and goals by deeply viewing their connected apps.")
	case agentFilesHeaderPattern.MatchString(content):
		// A file wrapper without a request section is still an orchestrator
		// envelope when it carries a generated local attachment path. It must not
		// become the latest user turn merely because the request was truncated.
		return strings.Contains(content, "\n\n## ") &&
			(strings.Contains(strings.ToLower(content), "appdata/local/temp/") ||
				strings.Contains(strings.ToLower(content), "appdata\\local\\temp\\"))
	case strings.HasPrefix(content, "<environment_context>"):
		return strings.HasSuffix(content, "</environment_context>")
	default:
		return false
	}
}

// toolsDigest 取全部 tool_def 消息内容按序拼接（\n 相接）后的 sha256；无 tool_def 返回空。
func toolsDigest(msgs []ConvMessage) string {
	var parts []string
	for _, m := range msgs {
		if m.Source == SourceToolDef {
			parts = append(parts, m.Content)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return ContentSHA256Hex(strings.Join(parts, "\n"))
}

// compactJSON 压缩 JSON 原文（tool 参数/schema 内联进消息内容用）；压缩失败原样裁剪返回。
func compactJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return strings.TrimSpace(string(raw))
	}
	return buf.String()
}
