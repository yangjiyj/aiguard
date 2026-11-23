package retentionfmt

import (
	"regexp"
	"strings"
)

// 内部角色标签。用 \u 转义写死，杜绝手打形近字：
//
//	【系统】= U+3010 U+7CFB U+7EDF U+3011
//	【工具】= U+3010 U+5DE5 U+5177 U+3011
//	【其它】= U+3010 U+5176 U+5B83 U+3011
//
// 这些字面值必须与 aimsg.hasInternalRolePrefix、proxy 侧 messagesToRetentionText 以及前端
// collapseSystemSections 的正则逐字节一致，否则折叠失效、机器噪音会漏成正文。
const (
	retainedSystemTag    = "\u3010\u7cfb\u7edf\u3011"
	retainedToolTag      = "\u3010\u5de5\u5177\u3011"
	retainedOtherTag     = "\u3010\u5176\u5b83\u3011"
	retainedSystemTagEN  = "\u3010system\u3011"
	retainedToolTagEN    = "\u3010tool\u3011"
	retainedDeveloperTag = "\u3010developer\u3011"
)

// RetainedSection 是留证文本按空行拆出的一段。Role 已归一化：默认角色由调用方给（请求侧
// "user"、响应侧 "assistant"），带内部角色标签的段落归到 system / tool / other。
type RetainedSection struct {
	Role    string
	Content string
}

// retainedRolePrefixes 是内部角色标签到归一化角色的映射。这些标签互不为前缀，顺序无关。
var retainedRolePrefixes = []struct {
	prefix string
	role   string
}{
	{retainedSystemTag, "system"},
	{retainedSystemTagEN, "system"},
	{retainedDeveloperTag, "system"},
	{retainedToolTag, "tool"},
	{retainedToolTagEN, "tool"},
	{retainedOtherTag, "other"},
}

var retainedSectionSepRe = regexp.MustCompile(`\n[ \t]*\n+`)

// SplitRetainedSections 把留证文本拆成带角色的段落。写入侧用 "\n\n" 分隔正文段与工具段
// （见 ToolSection / messagesToRetentionText），读侧据此还原结构：标签剥掉、role 归一化。
//
// 连续的默认角色段合并回一段——用户正文本身可能含空行（NormalizeRetainedUserText 保留
// "\n\n"），拆开后必须原样拼回去，否则前端会把同一句话显示成好几段。
func SplitRetainedSections(text, defaultRole string) []RetainedSection {
	out := []RetainedSection{}
	for _, paragraph := range retainedSectionSepRe.Split(NormalizeNewlines(text), -1) {
		trimmed := strings.TrimSpace(paragraph)
		if trimmed == "" {
			continue
		}
		role := defaultRole
		for _, candidate := range retainedRolePrefixes {
			if strings.HasPrefix(trimmed, candidate.prefix) {
				role = candidate.role
				trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, candidate.prefix))
				break
			}
		}
		if trimmed == "" {
			continue
		}
		if role == defaultRole && len(out) > 0 && out[len(out)-1].Role == defaultRole {
			out[len(out)-1].Content += "\n\n" + trimmed
			continue
		}
		out = append(out, RetainedSection{Role: role, Content: trimmed})
	}
	return out
}

// ToolSection 把一个工具轮证据段渲染成留证文本里的单段：带【工具】标签、内部空行归并成单换行。
//
// 标签与 messagesToRetentionText 的 tool_def / tool_result 段同口径——前端 collapseSystemSections
// 按 \n\n 分段后据标签整段默认折叠（折叠≠隐藏，可展开）。内部空行必须先归并：工具结果里常是
// 文件内容或命令输出，空行很多，不归并就会被前端切成多段、只有首段带标签，后续无标签段被当正文
// 展开，折叠就破了。
func ToolSection(content string) string {
	body := CollapseBlankLines(NormalizeNewlines(strings.TrimSpace(content)))
	if body == "" {
		return ""
	}
	return retainedToolTag + body
}
