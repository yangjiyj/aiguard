package aimsg

import (
	"strings"
)

// maxMentionedFilePaths 是单个 Codex 附件清单解析的路径上限。
const maxMentionedFilePaths = 32

// ExtractMentionedFilePaths 抽取 Codex 用户消息附件清单里的本地路径。
// 只在 codexFilesEnvelope(content) 为真（同时含 `# Files … by the user:` 头与
// `## My request:` 尾）时工作，否则返回 nil。支持两种条目：
//
//	## name:            （下一行是路径）
//	## "name": <path>   （同行路径）
//
// 最多 32 条，按出现顺序去重。
func ExtractMentionedFilePaths(content string) []string {
	if !codexFilesEnvelope(content) {
		return nil
	}
	// 只取 Files 头与 My request 尾之间的段落，避免误抓正文。
	section := content
	if loc := userRequestHeaderPattern.FindStringIndex(section); loc != nil {
		section = section[:loc[0]]
	}
	headLoc := agentFilesHeaderPattern.FindStringIndex(section)
	if headLoc == nil {
		return nil
	}
	section = section[headLoc[1]:]

	var out []string
	seen := make(map[string]struct{})
	lines := strings.Split(section, "\n")
	for i := 0; i < len(lines) && len(out) < maxMentionedFilePaths; i++ {
		line := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "##") {
			continue
		}
		entry := strings.TrimSpace(strings.TrimPrefix(trimmed, "##"))
		if entry == "" {
			continue
		}
		// ## My request: 已在 section 截取时排除；此处防御其它 ## 标题。
		var path string
		if idx := strings.Index(entry, ":"); idx >= 0 {
			rest := strings.TrimSpace(entry[idx+1:])
			if rest != "" {
				// ## "name": path 同行形式
				path = rest
			} else if i+1 < len(lines) {
				// ## name: 换行路径形式
				next := strings.TrimSpace(lines[i+1])
				if next != "" && !strings.HasPrefix(next, "#") {
					path = next
					i++
				}
			}
		}
		path = strings.Trim(strings.TrimSpace(path), `"'`)
		if path == "" {
			continue
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
