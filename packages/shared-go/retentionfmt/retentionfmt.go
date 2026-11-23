// Package retentionfmt 提供留证文本的降噪/折叠格式化原语，供 proxy-server（正向代理结构化
// 解码留证 messagesToRetentionText）与 control-plane（结构化留证缺失时用 content_logs 现场
// 回退合成）共用。
//
// 单一真源的动机：这些规则最早只在 proxy 侧实现，control-plane 的 content_logs 回退路径漏抄，
// 导致巨型系统提示词按 \n\n 裂成多段、只有首段带角色前缀、其余被前端当正文展开＝满屏噪音。
// 抽到共享包后两条留证路径共用一套折叠规则，杜绝"只修一处"的漂移。
package retentionfmt

import (
	"regexp"
	"strings"
)

var blankLineRe = regexp.MustCompile(`\n[ \t]*\n+`)

// userQueryRe 匹配编码 agent（WorkBuddy/Claude Code/Codebuddy）包裹真实用户输入的标签。
// 抓包实证：user 消息里真实消息是 <user_query>行</user_query>，周围全是 <system-reminder> 上下文。
var userQueryRe = regexp.MustCompile(`(?s)<user_query[^>]*>(.*?)</user_query>`)

// workBuddyWorkspaceFolderRe 匹配 WorkBuddy 在受控 user_info 中提供的会话工作区。
// WorkBuddy 的同一会话任务会持续复用该目录；模型调用通常不携带 thread_id/task_id，
// 因此该字段可作为租户内稳定任务关联键。只匹配独立字段行，避免从普通用户正文误取路径。
var workBuddyWorkspaceFolderRe = regexp.MustCompile(`(?m)^Workspace Folder:\s*([^\r\n<]+)\s*$`)

// agentMetaMarkers 是编码 agent 系统提示词/工具指令的强特征串（WorkBuddy/Claude Code/opencode
// 等把这些塞进 user 消息发）。命中即视为机器噪音段。
var agentMetaMarkers = []string{
	"available agent types",
	"<available_skills>",
	"the agent tool launches",
	"<system-reminder",
	"you are claude code",
	"you are workbuddy",
	"you are codebuddy",
	"official cli for",
	"tools available to it",
	"available tools:",
}

// NormalizeNewlines 把 \r\n / \r 统一成 \n（Windows 客户端如 WorkBuddy 用 CRLF）。
func NormalizeNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// CollapseBlankLines 把连续空行归并成单换行（保留单换行，消除会被前端当段落分隔的 \n\n）。
// 先归一化 CRLF，否则 \r\n\r\n 不被 \n\n 正则命中。用于给系统/工具段加角色前缀前先压平，
// 使整段成为一个 paragraph——否则前端按 \n\n 分段折叠时，巨型系统提示词内部的空行会把它切成
// 多段、只有首段带前缀，后续无前缀段被当正文展开，折叠就破了。
func CollapseBlankLines(s string) string {
	return blankLineRe.ReplaceAllString(NormalizeNewlines(s), "\n")
}

// SplitUserQuery 从一条 user 消息里剥出真实用户输入：
//   - query：所有 <user_query>…</user_query> 内文（多轮则换行拼接），即员工真正打的字；
//   - rest：剥掉 user_query 后剩余的 <system-reminder> 上下文（工作目录/user_info/memory/skills）。
//
// WorkBuddyWorkspaceFolder 返回 WorkBuddy user_info 中的稳定会话工作区。
func WorkBuddyWorkspaceFolder(content string) string {
	matches := workBuddyWorkspaceFolderRe.FindStringSubmatch(NormalizeNewlines(content))
	if len(matches) != 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

// SplitUserQuery 没有 <user_query> 标签时返回空 query——调用方回退到 IsAgentMetaContent 老逻辑。
func SplitUserQuery(content string) (query, rest string) {
	matches := userQueryRe.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return "", ""
	}
	var queries []string
	for _, m := range matches {
		if q := strings.TrimSpace(m[1]); q != "" {
			queries = append(queries, q)
		}
	}
	if len(queries) == 0 {
		return "", ""
	}
	rest = strings.TrimSpace(userQueryRe.ReplaceAllString(content, ""))
	return strings.Join(queries, "\n"), rest
}

// ProjectAgentTaskTitle unwraps transport-only task containers in the agent
// task list. It is deliberately agent-aware: applying these rules to generic
// customer text would corrupt ordinary XML examples.
func ProjectAgentTaskTitle(agentType, content string, postgresTitleTruncated bool) (string, bool) {
	agentType = strings.ToLower(strings.TrimSpace(agentType))
	original := content
	normalized := strings.TrimSpace(NormalizeNewlines(content))
	var projected string
	var matched bool
	switch agentType {
	case "workbuddy":
		projected, matched = projectWorkBuddySessionTitle(normalized, postgresTitleTruncated)
	case "cline":
		projected, matched = projectClineTaskTitle(normalized)
	default:
		return original, false
	}
	if !matched {
		return original, false
	}
	return projected, true
}

func projectWorkBuddySessionTitle(content string, postgresTitleTruncated bool) (string, bool) {
	firstLineEnd := strings.IndexByte(content, '\n')
	if firstLineEnd < 0 || strings.TrimSpace(content[:firstLineEnd]) != "<session>" {
		return content, false
	}
	body := content[firstLineEnd+1:]
	lastLineStart := strings.LastIndexByte(body, '\n')
	if lastLineStart >= 0 && strings.TrimSpace(body[lastLineStart+1:]) == "</session>" {
		return strings.TrimSpace(body[:lastLineStart]), true
	}
	if strings.Contains(body, "</session>") {
		return content, false
	}
	// Evidence list SQL deliberately returns LEFT(title, 160). A longer complete
	// WorkBuddy wrapper therefore reaches this layer as exactly 160 characters
	// with its closing tag cut off. Short, user-authored "<session> ..." text is
	// not treated as a wrapper.
	if postgresTitleTruncated {
		return strings.TrimSpace(body), true
	}
	return content, false
}

func projectClineTaskTitle(content string) (string, bool) {
	if !strings.HasPrefix(content, "<task>") {
		return content, false
	}
	closeAt := strings.Index(content[len("<task>"):], "</task>")
	if closeAt < 0 {
		return content, false
	}
	closeAt += len("<task>")
	remainder := content[closeAt+len("</task>"):]
	if !strings.HasPrefix(remainder, "\n") {
		return content, false
	}
	remainder = strings.TrimSpace(remainder)
	const marker = "# task_progress RECOMMENDED"
	if !strings.HasPrefix(remainder, marker) || (len(remainder) > len(marker) && !isASCIISpace(remainder[len(marker)])) {
		return content, false
	}
	return strings.TrimSpace(content[len("<task>"):closeAt]), true
}

func isASCIISpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r'
}

// IsAgentMetaContent 判断一段 user/assistant 内容是否是编码 agent 的系统级指令噪音：
// 足够大（真实用户提问通常短）且命中 agent-meta 特征串。二者同时满足才算，避免误折真实长提问。
func IsAgentMetaContent(content string) bool {
	if len(content) < 400 {
		return false
	}
	lower := strings.ToLower(content)
	for _, m := range agentMetaMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
