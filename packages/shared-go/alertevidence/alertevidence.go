// Package alertevidence 是告警命中原文入库的统一口径（2.9.22 起，用户 11-17 定：命中内容、证据、
// 前后文给原文，不打码）。网关和正向代理写 security_events.matched_summary 时按这里的规则存，
// 控制面按这里的字段名剔除（StripRaw），读写两侧共用同一组常量：
//
//   - 字面类命中存 raw_evidence 原文片段（单条上限 RawMaxRunes 字，超长截断并写 raw_evidence_truncated）
//     和不打码的 evidence_context（命中前后各 ContextRunes 字）。位置可用时两者都按位置从引擎前后文里取，
//     也就是内容里的实际原文，不是引擎给的归一化命中词；
//   - 语义类、运行类命中的 raw_evidence 是整段送检内容，不存原文，只存哈希；
//   - 每个事件原文总量不超过 MaxEventRawBytes（LimitEventRaw），主命中只引用 findings 里的位置（PrimaryReference）；
//   - 证据身份（迁移 850 的 _jjd_evidence_identity）不因为多了原文而改变：数据面按 2.9.22 之前
//     的口径算好写进 IdentityKey，迁移 1010 让生成列直接取它，升级前后同一命中归到同一份证据。
package alertevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 落库字段名。写入侧（网关、正向代理）、剔除（StripRaw）、读取侧都用这些常量。
const (
	FieldRawEvidence          = "raw_evidence"
	FieldEvidenceContext      = "evidence_context"
	FieldRawEvidenceTruncated = "raw_evidence_truncated"
	// FieldRawEvidenceOmitted 标明这条命中因事件原文总量超限没有存原文（哈希照存）。
	FieldRawEvidenceOmitted = "raw_evidence_omitted"
	// IdentityKey 是数据面写进 finding 的证据身份（2.9.22 之前口径的 sha256 十六进制）。
	// 迁移 1010 让读取元数据的生成列优先取它；空串表示旧口径下没有证据身份。带这个键即“新形态、可能带原文”。
	IdentityKey = "evidence_identity_sha256"
	// FieldFindingsIndex 是 primary_finding 指向 findings 数组的下标：主命中的原文只在 findings 里存一份。
	FieldFindingsIndex = "findings_index"
)

// RawFields 是没有内容证据权限的角色看不到的字段（StripRaw 的剔除名单）。
var RawFields = []string{FieldRawEvidence, FieldEvidenceContext, FieldRawEvidenceTruncated}

const (
	// RawMaxRunes 是单条命中原文入库的字数上限。
	RawMaxRunes = 4096
	// ContextRunes 是前后文在命中点前后各保留的字数，沿用 2.9.21 打码前后文的窗口。
	ContextRunes = 120
	// MaxEventRawBytes 是单个安全事件里原文（命中片段加前后文，UTF-8 字节）的总量上限。
	MaxEventRawBytes = 256 * 1024
	// engineContextRunes 与引擎 hit_display.CONTEXT_WINDOW 一致：引擎给的前后文是命中点前后各 500 字。
	engineContextRunes = 500
)

// StoresRaw 判断这条命中是否存原文。语义类（semantic_attack、类别 semantic_*）和运行类
// （AI 裁判、引擎运行事件、语义遥测）的 raw_evidence 是整段内容，只存哈希。
// 语义类的判定与迁移 850 计算证据身份时的语义分支一致。
func StoresRaw(findingType, category, evidenceKind string) bool {
	switch strings.ToLower(strings.TrimSpace(evidenceKind)) {
	case "semantic", "runtime", "observation", "telemetry":
		return false
	}
	switch strings.ToLower(strings.TrimSpace(findingType)) {
	case "semantic_attack", "llm_judge", "semantic_telemetry", "engine_runtime":
		return false
	}
	return !strings.HasPrefix(strings.ToLower(strings.TrimSpace(category)), "semantic_")
}

// Truncate 把原文截到 RawMaxRunes 字以内；第二个返回值表示是否截断。
// 按 Unicode 码点截断：可能切开由多个码点组成的字符（表情的 ZWJ 序列、国旗、带组合符的字），
// 截断处显示为半个字符；原文哈希按完整内容计算，不受影响。
func Truncate(raw string) (string, bool) {
	if utf8.RuneCountInString(raw) <= RawMaxRunes {
		return raw, false
	}
	return string([]rune(raw)[:RawMaxRunes]), true
}

// Stored 去掉 PostgreSQL jsonb 不接受的 NUL 字符（\u0000 会让整条安全事件写入失败）。
func Stored(text string) string {
	return strings.ReplaceAll(text, "\x00", "")
}

var contentLocation = regexp.MustCompile(`^content\[(\d+):(\d+)\]$`)

// Extract 从引擎给的前后文（命中点前后各 500 字）里取出命中原文和命中前后各 ContextRunes 字的前后文，不打码。
//
//   - matched_location 是 content[起:止] 且落在前后文范围内：按位置取，原文就是内容里的实际片段 content[起:止]；
//   - 按位置截出的文字与引擎命中词不一致时，先在前后文里查找命中词，找到就用找到的位置（位置可能是另一段
//     内容的偏移，例如流式输出分段检测改写过的位置）；查不到才信位置（关键字规则给的是全角转半角、
//     大小写折叠、去零宽后的词，在原文里本来就查不到）；
//   - 没有可用位置：命中文字用引擎给的 raw，前后文先在里面查找它，查不到取中段（引擎前后文以命中为中心）。
//
// 查找（含位置对不上时的后备）取第一次出现的位置：同词在前后文里多次出现时定位到第一处。
//
// 截断处加“…”；命中本身超长时前后文整段封顶。返回的前后文已去 NUL，命中原文由调用方截断后再 Stored。
func Extract(raw, context, matchedLocation string) (hit, window string) {
	if context == "" {
		return raw, ""
	}
	runes := []rune(context)
	at, length, located := positionInContext(runes, matchedLocation)
	if located && raw != "" && string(runes[at:at+length]) != raw {
		if index := strings.Index(context, raw); index >= 0 {
			at, length = utf8.RuneCountInString(context[:index]), utf8.RuneCountInString(raw)
		}
	}
	if located {
		hit = string(runes[at : at+length])
	} else {
		hit = raw
		length = utf8.RuneCountInString(raw)
		at = -1
		if raw != "" {
			if index := strings.Index(context, raw); index >= 0 {
				at = utf8.RuneCountInString(context[:index])
			}
		}
	}
	var start, end int
	if at < 0 {
		center := len(runes) / 2
		half := ContextRunes + length/2
		start, end = max(0, center-half), min(len(runes), center+half)
	} else {
		start, end = max(0, at-ContextRunes), min(len(runes), at+length+ContextRunes)
	}
	if limit := RawMaxRunes + 2*ContextRunes; end-start > limit {
		end = start + limit
	}
	prefix, suffix := "", ""
	if start > 0 {
		prefix = "…"
	}
	if end < len(runes) {
		suffix = "…"
	}
	return hit, Stored(prefix + string(runes[start:end]) + suffix)
}

// positionInContext 把 content[起:止] 换算成引擎前后文里的位置：引擎在起点超过 500 时开头加了一个“…”。
// 区间为空或超出前后文范围时不可用。
func positionInContext(runes []rune, matchedLocation string) (at, length int, ok bool) {
	m := contentLocation.FindStringSubmatch(strings.TrimSpace(matchedLocation))
	if m == nil {
		return 0, 0, false
	}
	start, errStart := strconv.Atoi(m[1])
	end, errEnd := strconv.Atoi(m[2])
	if errStart != nil || errEnd != nil || end <= start {
		return 0, 0, false
	}
	at, length = min(start, engineContextRunes), end-start
	if start > engineContextRunes {
		at++
	}
	if at+length > len(runes) {
		return 0, 0, false
	}
	return at, length, true
}

// LimitEventRaw 控制单个事件的原文总量：累计带原文命中的 raw_evidence 与 evidence_context 字节数，
// 放得下就保留；放不下的命中去掉原文和前后文、标 raw_evidence_omitted（哈希、证据身份照存）。
// reserved 是先占预算的命中下标（主命中、阻断依据的那条），其余命中再按顺序；越界、重复的下标忽略。
// 只处理带 IdentityKey 的命中（字面类新形态）；语义类的打码前后文不是原文，不计入。返回同一个切片。
func LimitEventRaw(findings []map[string]any, reserved ...int) []map[string]any {
	used := 0
	admit := func(finding map[string]any) {
		if finding == nil {
			return
		}
		if _, raw := finding[IdentityKey]; !raw {
			return
		}
		hit, _ := finding[FieldRawEvidence].(string)
		context, _ := finding[FieldEvidenceContext].(string)
		size := len(hit) + len(context)
		if size == 0 {
			return
		}
		if used+size <= MaxEventRawBytes {
			used += size
			return
		}
		for _, key := range RawFields {
			delete(finding, key)
		}
		finding[FieldRawEvidenceOmitted] = true
	}
	done := make(map[int]bool, len(reserved))
	for _, index := range reserved {
		if index >= 0 && index < len(findings) && !done[index] {
			done[index] = true
			admit(findings[index])
		}
	}
	for index, finding := range findings {
		if !done[index] {
			admit(finding)
		}
	}
	return findings
}

// PrimaryReference 生成 primary_finding：主命中那条 finding 去掉原文字段，加 findings_index 指向 findings 里的原条目。
func PrimaryReference(item map[string]any, index int) map[string]any {
	ref, _ := StripRaw(item).(map[string]any)
	if ref == nil {
		ref = map[string]any{}
	}
	ref[FieldFindingsIndex] = index
	return ref
}

// StripRaw 返回去掉 RawFields 后的深拷贝：根上、findings、raw_findings、observations、primary_finding
// 以及任意嵌套层级里的同名字段都去掉。原对象不改。
func StripRaw(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if isRawField(key) {
				continue
			}
			out[key] = StripRaw(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = StripRaw(item)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(typed))
		for i, item := range typed {
			out[i], _ = StripRaw(item).(map[string]any)
		}
		return out
	default:
		return value
	}
}

func isRawField(key string) bool {
	for _, field := range RawFields {
		if key == field {
			return true
		}
	}
	return false
}

// Identity 按 2.9.22 之前的口径算证据身份：取第一个非空的旧落库值（调用方按迁移 850 的顺序传入），
// 返回其 sha256 十六进制；都为空时返回空串（旧口径下没有证据身份）。
func Identity(basis ...string) string {
	for _, value := range basis {
		if value != "" {
			sum := sha256.Sum256([]byte(value))
			return hex.EncodeToString(sum[:])
		}
	}
	return ""
}
