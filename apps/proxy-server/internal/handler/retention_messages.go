package handler

import (
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionfmt"
)

// messagesToRetentionText 把结构化解码器（openai_compatible / anthropic_messages /
// yuanbao_web 等）产出的消息数组渲染成留证文本：
//   - system_prompt 段加【系统】前缀、tool_def / tool_result 段加【工具】前缀——
//     前端 collapseSystemSections 据此把这些"机器噪音"段默认折叠（折叠≠隐藏，可展开）；
//   - user / assistant 对话不加前缀，作为正文直接呈现。
//
// 关键：加前缀的段内部空行归并成单换行，整段成为一个 paragraph——否则前端按 \n\n 分段折叠时，
// 巨型系统提示词（如 WorkBuddy 652 行 tools 定义）内部的空行会把它切成多段、只有首段带前缀，
// 后续无前缀段被当正文展开，折叠就破了。段间用 \n\n 分隔，与前端分段规则对齐。
func messagesToRetentionText(messages []ConvMessage) string {
	// 真实对话与机器噪音分开收集，对话在前、噪音在后。原因：编码 agent（WorkBuddy/Claude Code）
	// 的系统提示词+工具定义动辄超 64KB，若按原始消息序渲染（系统在前、用户消息在末尾），留证的
	// 64KB 截断会把真实用户消息整段切掉，只剩系统噪音、且前端"全是系统段不折"守卫触发 → 满屏噪音。
	// 故把真实对话放最前（保证不被截断、且前端能显），系统/工具/agent-meta 噪音放后（前端折叠）。
	var convo, noise []string
	for _, m := range messages {
		// WorkBuddy 等 Windows 客户端用 \r\n 换行——先归一化，否则 collapseBlankLines 的
		// \n\n 归并对 \r\n\r\n 失效，system/tool 段会裂成多段、折叠在首段就断。
		content := strings.TrimSpace(normalizeNewlines(m.Content))
		if content == "" {
			continue
		}
		switch m.Source {
		case aimsg.SourceSystemPrompt:
			noise = append(noise, "【系统】"+collapseBlankLines(content))
		case aimsg.SourceToolDef, aimsg.SourceToolResult:
			noise = append(noise, "【工具】"+collapseBlankLines(content))
		default:
			// user/assistant 默认是真实对话。但 WorkBuddy / Claude Code 这类编码 agent 把真实用户
			// 消息包在 <user_query>...</user_query> 里发，周围塞满 <system-reminder> 上下文（工作
			// 目录、user_info、memory/skills）。抓包实证：一条 user 消息 = [system-reminder 上下文] +
			// <user_query>真实消息</user_query>。故优先提取 <user_query> 作真实对话，其余上下文折叠。
			if query, rest := splitUserQuery(content); query != "" {
				if rest != "" {
					noise = append(noise, "【系统】"+collapseBlankLines(rest))
				}
				convo = append(convo, query)
			} else if isAgentMetaContent(content) {
				// 无 <user_query> 但整段是 agent 系统提示词特征（塞在 user 里）→ 折叠。
				noise = append(noise, "【系统】"+collapseBlankLines(content))
			} else {
				convo = append(convo, content)
			}
		}
	}
	parts := make([]string, 0, len(convo)+len(noise))
	parts = append(parts, convo...)
	parts = append(parts, noise...)
	return strings.Join(parts, "\n\n")
}

// 留证折叠原语统一收敛到 shared-go/retentionfmt（单一真源）——control-plane 的 content_logs
// 回退合成共用同一套规则，杜绝"只修一处、另一处漂移"的历史坑。下面是薄委托，保持本文件与其
// 测试对这些名字的既有调用不变。
func normalizeNewlines(s string) string              { return retentionfmt.NormalizeNewlines(s) }
func collapseBlankLines(s string) string             { return retentionfmt.CollapseBlankLines(s) }
func splitUserQuery(content string) (string, string) { return retentionfmt.SplitUserQuery(content) }
func isAgentMetaContent(content string) bool         { return retentionfmt.IsAgentMetaContent(content) }
