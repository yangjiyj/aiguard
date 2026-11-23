// Package aiconvo 提供 AI 编程工具会话归组的归一化与键计算（安全三视图重构 契约第 5 条）。
//
// 消费方：
//   - P1-D：gateway-core A 路写 security_events 时物化 conversation_key；
//   - P1-C（Plan C）：source 档位/归组链路复用同一套函数——四个导出函数签名不得擅改。
//
// 设计约束：conversation_key 只用于"独立事发次数"的会话口径去重与展示层归组，
// 不承担留证/权限语义；归一化宁可多剥（跨天不裂链）也不少剥。
package aiconvo

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// systemReminderRe 剥离 <system-reminder>...</system-reminder> 整段（含标签）。
// Claude Code 把动态注入（技能列表、日期、上下文提醒）放在该标签内，跨请求易变。
var systemReminderRe = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)

// volatileLineRes 按行剥离的易变行：日期声明行（多种常见表述）。
var volatileLineRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*today'?s\s+date\b`),
	regexp.MustCompile(`(?i)^\s*#?\s*currentDate\b`),
	regexp.MustCompile(`(?i)^\s*the\s+current\s+date\s+is\b`),
}

// gitStatusStartRe 命中 gitStatus 快照段起始行。Claude Code 的 gitStatus 快照
// （Current branch / Status / Recent commits）位于 system prompt 末尾，从该行起
// 剥到文本结束——宁可多剥不裂链（digest 只用于归组，不承担留证语义）。
var gitStatusStartRe = regexp.MustCompile(`(?i)^\s*gitStatus:`)

// NormalizeSystemPrompt 剥离 system prompt 中的易变内容（日期行、gitStatus 快照、
// <system-reminder> 动态段），使同一工具模板跨天/跨仓库产生稳定 digest。
func NormalizeSystemPrompt(s string) string {
	if s == "" {
		return ""
	}
	s = systemReminderRe.ReplaceAllString(s, "")
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if gitStatusStartRe.MatchString(line) {
			break // gitStatus 快照总在末尾：从这里剥到结束
		}
		volatile := false
		for _, re := range volatileLineRes {
			if re.MatchString(line) {
				volatile = true
				break
			}
		}
		if volatile {
			continue
		}
		out = append(out, strings.TrimRight(line, " \t"))
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// ContentSHA256 返回文本的 sha256 十六进制（64 字符小写）。
func ContentSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// SystemDigest 返回归一化后 system prompt 的内容摘要。
func SystemDigest(s string) string {
	return ContentSHA256(NormalizeSystemPrompt(s))
}

// ConversationKey 合成会话归组键：hash(tenant, key_id, agent_type, system_digest, 首条 user 消息 sha256)。
// tenantID 为空返回空串（无法归组，计数口径回退 request_id）。
func ConversationKey(tenantID, keyID, agentType, systemDigest, firstUserSHA string) string {
	if strings.TrimSpace(tenantID) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{tenantID, keyID, agentType, systemDigest, firstUserSHA}, "\n")))
	return "ck_" + hex.EncodeToString(sum[:])[:32]
}
