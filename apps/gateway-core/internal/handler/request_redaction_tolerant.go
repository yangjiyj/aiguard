package handler

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 响应还原的宽容匹配。上游模型可能改写网关发出的占位符：大小写、去掉或转义尖括号
// （&lt;…&gt;）、被 markdown 反斜杠/反引号/加粗包裹、内部被插入空格或零宽字符。
// 只匹配本请求登记过的占位符（含 32 位随机 nonce），别的文本哪怕长得像也不会被还原。

var redactionNoncePattern = regexp.MustCompile(`_([0-9a-f]{32})_[0-9]+>$`)

// 允许出现在占位符字符之间的噪声：空白、零宽字符、markdown 转义反斜杠。
const redactionNoise = `[\s\x{200b}-\x{200d}\x{2060}\x{feff}\\]*`

var (
	redactionOpenWrap  = `(?:(?:<|&lt;|&amp;lt;|&#60;|&#x3c;|＜)` + redactionNoise + `)?`
	redactionCloseWrap = `(?:` + redactionNoise + `(?:>|&gt;|&amp;gt;|&#62;|&#x3e;|＞))?`
)

// redactionCompact 去掉噪声并转小写，用来快速判断文本里是否出现了被改写的占位符。
func redactionCompact(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		switch {
		case unicode.IsSpace(r), r == '\\', r >= 0x200b && r <= 0x200d, r == 0x2060, r == 0xfeff:
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

func redactionTokenBody(token string) string {
	return strings.TrimSuffix(strings.TrimPrefix(token, "<"), ">")
}

type tolerantEntry struct {
	token, value, compactBody string
	re                        *regexp.Regexp
}

// redactionRestorer 对同一请求的多段文本复用已编译的匹配器，并累计无法还原的残留。
type redactionRestorer struct {
	entries []*tolerantEntry
	nonces  []string
	gap     bool
}

func newRedactionRestorer(mapping map[string]string) *redactionRestorer {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	r := &redactionRestorer{}
	seen := map[string]bool{}
	for _, key := range keys {
		r.entries = append(r.entries, &tolerantEntry{token: key, value: mapping[key], compactBody: redactionCompact(redactionTokenBody(key))})
		if m := redactionNoncePattern.FindStringSubmatch(key); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			r.nonces = append(r.nonces, m[1])
		}
	}
	return r
}

func (e *tolerantEntry) regex() *regexp.Regexp {
	if e.re == nil {
		parts := make([]string, 0, utf8.RuneCountInString(e.token))
		for _, r := range redactionTokenBody(e.token) {
			parts = append(parts, regexp.QuoteMeta(string(r)))
		}
		e.re = regexp.MustCompile(`(?i)` + redactionOpenWrap + strings.Join(parts, redactionNoise) + redactionCloseWrap)
	}
	return e.re
}

type restoreMatch struct {
	start, end int
	value      string
}

// Replace 单遍还原：把所有登记占位符的各种变体一次替换掉，替换进去的原值不会再被匹配。
func (r *redactionRestorer) Replace(text string) string {
	if r == nil || len(r.entries) == 0 || text == "" {
		return text
	}
	compact := redactionCompact(text)
	if !strings.Contains(compact, "jjd") {
		return text
	}
	var matches []restoreMatch
	for _, entry := range r.entries {
		if !strings.Contains(compact, entry.compactBody) {
			continue
		}
		for _, loc := range entry.regex().FindAllStringIndex(text, -1) {
			start, end := loc[0], loc[1]
			// 没有结尾括号时序号不能被更长的数字吞掉一半（_1 与 _10）。
			if last, _ := utf8.DecodeLastRuneInString(text[start:end]); unicode.IsDigit(last) && end < len(text) {
				if next, _ := utf8.DecodeRuneInString(text[end:]); unicode.IsDigit(next) {
					continue
				}
			}
			matches = append(matches, restoreMatch{start, end, entry.value})
		}
	}
	out := text
	if len(matches) > 0 {
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].start != matches[j].start {
				return matches[i].start < matches[j].start
			}
			return matches[i].end > matches[j].end
		})
		var b strings.Builder
		cursor := 0
		for _, m := range matches {
			if m.start < cursor {
				continue
			}
			b.WriteString(text[cursor:m.start])
			b.WriteString(m.value)
			cursor = m.end
		}
		b.WriteString(text[cursor:])
		out = b.String()
	}
	r.noteResidue(out, matches)
	return out
}

// noteResidue 还原后文本里仍有本请求的 nonce，说明模型把占位符改得超出可识别范围。
// 只在有匹配残留时才检查，原值里恰好带 nonce 的情形不会发生（nonce 只存在于网关发出的占位符中）。
func (r *redactionRestorer) noteResidue(restored string, matches []restoreMatch) {
	if r.gap || len(r.nonces) == 0 {
		return
	}
	compact := redactionCompact(restored)
	for _, nonce := range r.nonces {
		if strings.Contains(compact, nonce) {
			r.gap = true
			return
		}
	}
}
