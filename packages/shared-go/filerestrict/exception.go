package filerestrict

import (
	"path"
	"strings"
	"unicode/utf8"
)

// 文件类例外的路径口径，网关 agentguard 的文件类防护项（含受限文件、端侧内置文件规则）和独立代理
// 的受限文件共用这一份实现（2.9.22 合流时把网关那份并进来）：例外按路径层级比对，不做 URL 解码，
// 区分大小写。表驱动用例都在本包，网关只留端到端用例。

// ExceptionTarget 是例外比对用的路径：反斜杠转 /、按 path.Clean 折叠 . 与 ..。不做 URL 解码（shell 和
// 内核按字面读路径：a%2fb/../x 就是名为 a%2fb 的目录的上一层）。落不到确定文件时返回空串，只有不限
// 目标的例外能放开：
//   - 原始路径含 %，或折叠后越出根目录（以 .. 开头）；
//   - 只有写在开头的 ~/ 是家目录，在家目录里折叠；越过 ~ 的（~/../x、~/../~/.ssh/id_rsa）已不在家目录里；
//   - 相对路径折叠后才变成 ~/ 开头或等于 ~ 的（x/../~/a、./~/a）：中间的 ~ 是当前目录下一个叫 ~ 的目录。
func ExceptionTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "%") {
		return ""
	}
	slashed := strings.ReplaceAll(raw, `\`, "/")
	if rest, ok := strings.CutPrefix(slashed, "~/"); ok {
		rest = path.Clean(rest)
		if rest == "." || rest == ".." || strings.HasPrefix(rest, "../") {
			return ""
		}
		return "~/" + rest
	}
	cleaned := path.Clean(slashed)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	if cleaned == "~" || strings.HasPrefix(cleaned, "~/") {
		return ""
	}
	return cleaned
}

// ExceptionTargetMatches 判断例外目标 pattern 是否覆盖文件 target（target 须是 ExceptionTarget 的结果；
// 为空时只有不限目标的例外匹配）。区分大小写（Linux 上 Plan.docx 与 plan.docx 是两个文件）：
//   - 空写法匹配全部；
//   - 不含 / 的写法只与文件名精确比较（plan.docx 不匹配 myplan.docx、plan.docx.d/x）；
//   - 以 / 结尾的写法是目录：匹配目录本身（打包整个目录）和其下的路径，按路径段边界匹配
//     （/data/x/ 不匹配 /data/xy/a）；相对目录（x/）匹配任意层级上的同名目录；
//   - 其余含 / 的写法与完整路径相等，或（相对写法时）是以 / 为界的后缀（x/plan.docx 匹配
//     /data/x/plan.docx，不匹配 /data/xx/plan.docx）。
func ExceptionTargetMatches(pattern, target string) bool {
	pattern = strings.TrimSpace(strings.ReplaceAll(pattern, `\`, "/"))
	if pattern == "" {
		return true
	}
	if target == "" {
		return false
	}
	absolute := func(p string) bool { return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~/") }
	switch {
	case strings.HasSuffix(pattern, "/"):
		dir := path.Clean(pattern)
		if target == dir || strings.HasPrefix(target, dir+"/") {
			return true
		}
		return !absolute(dir) && (strings.HasSuffix(target, "/"+dir) || strings.Contains(target, "/"+dir+"/"))
	case strings.Contains(pattern, "/"):
		full := path.Clean(pattern)
		if target == full {
			return true
		}
		return !absolute(full) && strings.HasSuffix(target, "/"+full)
	default:
		return path.Base(target) == pattern
	}
}

// MaxLiteralPathBytes 是证据里字面路径的长度上限。
const MaxLiteralPathBytes = 1024

// LiteralPath 是文件类命中证据里的字面写法：不解码、不折叠，只去首尾空白，截到 MaxLiteralPathBytes
// 且不切断多字节字符。审计显示的规范化路径是解码后的，与内核实际读的可能不一致，两者都留。
func LiteralPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= MaxLiteralPathBytes {
		return raw
	}
	cut := MaxLiteralPathBytes
	for cut > 0 && !utf8.RuneStart(raw[cut]) {
		cut--
	}
	return raw[:cut]
}
