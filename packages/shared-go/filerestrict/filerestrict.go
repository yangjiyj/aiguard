package filerestrict

import (
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Action 是命中受限文件模式后的处置动作，沿用策略中心动作词。
type Action string

const (
	ActionRecord     Action = "record"      // 仅记录
	ActionAlertAllow Action = "alert_allow" // 告警并放行
	ActionBlock      Action = "block"       // 阻断
)

// Policy 是租户级受限文件策略：模式列表 + 命中后的动作。空 Patterns = 功能关闭。
type Policy struct {
	Patterns []string
	Action   Action
}

const (
	maxPatterns     = 64
	maxPatternLen   = 128
	PrecisionExact  = "exact"
	PrecisionCoarse = "coarse"
)

// Hit 表示一次命中。Precision 区分精确层（词法切分后归一化路径）与粗略层（正则抓路径样片段）。
type Hit struct {
	Pattern   string
	Target    string
	Precision string
}

// Validate 校验模式列表，返回首个错误；错误信息可直接给前端。
func Validate(patterns []string) error {
	if len(patterns) > maxPatterns {
		return fmt.Errorf("受限文件模式最多 %d 条，当前 %d 条", maxPatterns, len(patterns))
	}
	for _, p := range patterns {
		if err := validatePattern(p); err != nil {
			return err
		}
	}
	return nil
}

func validatePattern(p string) error {
	if p == "" {
		return fmt.Errorf("模式不能为空字符串")
	}
	if len(p) > maxPatternLen {
		return fmt.Errorf("模式 %q 超过 %d 字符上限", p, maxPatternLen)
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return fmt.Errorf("模式 %q 含控制字符", p)
		}
		if unicode.IsSpace(r) {
			return fmt.Errorf("模式 %q 含空白字符", p)
		}
	}
	if isURL(p) {
		return fmt.Errorf("模式 %q 不能是 URL", p)
	}
	if strings.HasSuffix(p, "/") {
		// 目录模式：前缀匹配，不做 glob 语法校验，但不能含通配符。
		if strings.ContainsAny(p, "*?[") {
			return fmt.Errorf("目录模式 %q 不能含通配符", p)
		}
		return nil
	}
	// 必须含通配符（纯文件名不允许，避免误伤）。
	if !strings.ContainsAny(p, "*?[") {
		return fmt.Errorf("模式 %q 须含通配符（如 *.pdf、docs/**、~/x/**）或以 / 结尾作目录", p)
	}
	if _, err := path.Match(p, "probe"); err != nil {
		return fmt.Errorf("模式 %q glob 语法非法: %v", p, err)
	}
	return nil
}

func isURL(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ftp://") || strings.HasPrefix(lower, "file://")
}

// ValidateAction 校验动作词。
func ValidateAction(action string) (Action, error) {
	switch Action(strings.TrimSpace(action)) {
	case ActionRecord:
		return ActionRecord, nil
	case ActionAlertAllow:
		return ActionAlertAllow, nil
	case ActionBlock:
		return ActionBlock, nil
	default:
		return "", fmt.Errorf("受限文件动作须为 record|alert_allow|block，得到 %q", action)
	}
}

// patternKind 区分三种模式写法。
type patternKind int

const (
	kindExt  patternKind = iota // *.pdf（不区分大小写，比 basename 最后一个扩展名）
	kindGlob                    // docs/**/*.docx、~/Documents/**
	kindDir                     // /srv/contracts/（前缀匹配）
)

type compiledPattern struct {
	raw  string
	kind patternKind
	ext  string // kindExt：小写扩展名（不含点）
	glob string // kindGlob：归一化后的 glob
	dir  string // kindDir：目录前缀（含结尾 /）
}

// Matcher 是编译后的受限文件匹配器，可并发只读。
type Matcher struct {
	patterns []compiledPattern
}

// Compile 编译模式列表；非法模式返回错误（信息可直接给前端）。
func Compile(patterns []string) (*Matcher, error) {
	if err := Validate(patterns); err != nil {
		return nil, err
	}
	m := &Matcher{patterns: make([]compiledPattern, 0, len(patterns))}
	for _, p := range patterns {
		m.patterns = append(m.patterns, compilePattern(p))
	}
	return m, nil
}

func compilePattern(p string) compiledPattern {
	if strings.HasSuffix(p, "/") {
		return compiledPattern{raw: p, kind: kindDir, dir: normalizePath(p)}
	}
	if isExtPattern(p) {
		ext := strings.ToLower(strings.TrimPrefix(p, "*."))
		return compiledPattern{raw: p, kind: kindExt, ext: ext}
	}
	return compiledPattern{raw: p, kind: kindGlob, glob: normalizePath(p)}
}

// isExtPattern 判断 *.pdf 形态（单星号 + 点 + 纯扩展名，无路径分隔与其它通配）。
func isExtPattern(p string) bool {
	if !strings.HasPrefix(p, "*.") {
		return false
	}
	rest := p[2:]
	if rest == "" {
		return false
	}
	return !strings.ContainsAny(rest, "*/?[\\")
}

// normalizePath 归一化路径：反斜杠→正斜杠、去 ./ 前缀、按 path.Clean 语义折叠 . 与 ..、
// 保留 ~/ 与盘符、保留结尾的 /（目录型模式靠它）、剥离 file://。
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	p = strings.TrimPrefix(p, "@")
	if strings.HasPrefix(strings.ToLower(p), "file://") {
		p = p[len("file://"):]
	}
	p = strings.ReplaceAll(p, "\\", "/")
	// 去重复的斜杠
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	p = strings.TrimPrefix(p, "./")
	return cleanDotSegments(p)
}

// cleanDotSegments 按 path.Clean 语义折叠 . 与 ..（/tmp/../vault/x → /vault/x），
// 结尾的 / 保留；相对路径开头多出来的 .. 原样保留。
func cleanDotSegments(p string) string {
	if p == "" || !strings.Contains(p, ".") {
		return p
	}
	trailing := strings.HasSuffix(p, "/")
	cleaned := path.Clean(p)
	if trailing && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

// baseName 取归一化路径的最后一段。
func baseName(p string) string {
	if idx := strings.LastIndex(p, "/"); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

// lastExt 取 basename 的最后一个扩展名（小写，不含点）；无扩展名返回空。
func lastExt(base string) string {
	idx := strings.LastIndex(base, ".")
	if idx <= 0 || idx == len(base)-1 {
		return ""
	}
	return strings.ToLower(base[idx+1:])
}

// matchOne 用单个模式匹配已归一化路径。
func (cp compiledPattern) matchOne(normPath string) bool {
	switch cp.kind {
	case kindExt:
		return lastExt(baseName(normPath)) == cp.ext
	case kindDir:
		// 目录前缀命中其下文件，但不命中目录本身。
		return strings.HasPrefix(normPath, cp.dir) && len(normPath) > len(cp.dir)
	case kindGlob:
		return matchGlob(cp.glob, normPath)
	}
	return false
}

// matchGlob 支持 ** 任意层级；相对模式同时匹配 basename 与任意后缀路径。
func matchGlob(pattern, p string) bool {
	if globMatch(pattern, p) {
		return true
	}
	// 相对模式（不以 /、~/、盘符开头）：尝试匹配 basename 与任意后缀路径。
	if !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "~/") && !isWindowsAbs(pattern) {
		if globMatch(pattern, baseName(p)) {
			return true
		}
		// 任意后缀路径：把模式前补 **/
		if !strings.HasPrefix(pattern, "**/") {
			if globMatch("**/"+pattern, p) {
				return true
			}
		}
	}
	return false
}

func isWindowsAbs(p string) bool {
	return len(p) >= 3 && p[1] == ':' && (p[2] == '/' || p[2] == '\\')
}

// globMatch 实现 * ? [...] 与 ** 跨层匹配。
func globMatch(pattern, name string) bool {
	// ** 拆段：把 pattern 按 / 切成段，支持 ** 跨任意段。
	psegs := strings.Split(pattern, "/")
	nsegs := strings.Split(name, "/")
	return matchSegments(psegs, nsegs)
}

func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// ** 匹配 0..n 段
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], name[0])
		if err != nil || !ok {
			return false
		}
		pat = pat[1:]
		name = name[1:]
	}
	return len(name) == 0
}

// MatchPath 对单条路径做精确层匹配。
func (m *Matcher) MatchPath(p string) (Hit, bool) {
	if m == nil {
		return Hit{}, false
	}
	norm := normalizePath(p)
	for _, cp := range m.patterns {
		if cp.matchOne(norm) {
			return Hit{Pattern: cp.raw, Target: p, Precision: PrecisionExact}, true
		}
	}
	return Hit{}, false
}

// MatchPaths 对多条路径做精确层匹配，返回全部命中。
func (m *Matcher) MatchPaths(paths []string) []Hit {
	if m == nil {
		return nil
	}
	var hits []Hit
	for _, p := range paths {
		if hit, ok := m.MatchPath(p); ok {
			hits = append(hits, hit)
		}
	}
	return hits
}

// MatchCommand 对一条 shell 命令做精确层匹配；精确层无命中时对整段命令跑粗略层。
func (m *Matcher) MatchCommand(command string) []Hit {
	if m == nil {
		return nil
	}
	candidates := extractShellCandidates(command)
	var hits []Hit
	for _, cand := range candidates {
		if isURLCandidate(cand) {
			continue
		}
		if hit, ok := m.MatchPath(cand); ok {
			hits = append(hits, hit)
		}
	}
	if len(hits) > 0 {
		return hits
	}
	return m.MatchText(command)
}

// MatchText 粗略层：对整段文本抓路径样片段，只跑扩展名与 basename 级 glob。
// Go RE2 不支持 lookahead，候选边界由手工扫描判定（等价于 §3.3 的正则语义）。
func (m *Matcher) MatchText(text string) []Hit {
	if m == nil {
		return nil
	}
	var hits []Hit
	seen := make(map[string]struct{})
	for _, frag := range coarsePathCandidates(text) {
		if isURLCandidate(frag) || looksLikeURLContext(text, frag) {
			continue
		}
		norm := normalizePath(frag)
		base := baseName(norm)
		if _, dup := seen[base]; dup {
			continue
		}
		for _, cp := range m.patterns {
			// 粗略层只跑扩展名与 basename 级 glob（避免相对 glob 误伤）。
			if cp.kind == kindExt && lastExt(base) == cp.ext {
				if hit, ok := m.MatchPath(frag); ok {
					hit.Precision = PrecisionCoarse
					hits = append(hits, hit)
					seen[base] = struct{}{}
					break
				}
			}
		}
	}
	return hits
}

const (
	coarseLeadSet  = " \t\n\r\"'(=,:@<>|"
	coarseTrailSet = " \t\n\r\"'),;:|<>&"
	coarseCharSet  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./\\~-:"
)

// coarsePathCandidates 手工扫描出"路径样子"的片段：
// 前界是行首或 coarseLeadSet 字符，主体是 [盘符:] 字母数字 _./\~- 且含一个点+1~8位扩展名，
// 后界是行尾或 coarseTrailSet 字符。等价于 §3.3 的 lookahead 正则但兼容 RE2。
func coarsePathCandidates(text string) []string {
	var out []string
	runes := []rune(text)
	n := len(runes)
	isLead := func(i int) bool {
		if i == 0 {
			return true
		}
		return strings.ContainsRune(coarseLeadSet, runes[i-1])
	}
	i := 0
	for i < n {
		if !isCoarseChar(runes[i]) || !isLead(i) {
			i++
			continue
		}
		// 扫主体
		start := i
		for i < n && isCoarseChar(runes[i]) {
			i++
		}
		cand := string(runes[start:i])
		// 后界检查
		if i < n && !strings.ContainsRune(coarseTrailSet, runes[i]) {
			continue
		}
		if looksLikePathWithExt(cand) {
			out = append(out, cand)
		}
	}
	return out
}

func isCoarseChar(r rune) bool {
	return strings.ContainsRune(coarseCharSet, r) || r > 127 // 允许非 ASCII（中文文件名）
}

// looksLikePathWithExt 判断片段是否含一个"最后一个点 + 1~8 位扩展名"。
func looksLikePathWithExt(s string) bool {
	idx := strings.LastIndex(s, ".")
	if idx <= 0 || idx == len(s)-1 {
		return false
	}
	ext := s[idx+1:]
	if len(ext) > 8 {
		return false
	}
	for _, r := range ext {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isURLCandidate(s string) bool {
	return isURL(strings.TrimSpace(s))
}

// looksLikeURLContext 判断片段在原文中是否处于 http(s):// 之后。
func looksLikeURLContext(text, frag string) bool {
	idx := strings.Index(text, frag)
	if idx < 0 {
		return false
	}
	prefix := text[:idx]
	return strings.HasSuffix(prefix, "http://") || strings.HasSuffix(prefix, "https://") ||
		strings.HasSuffix(prefix, "ftp://") || strings.HasSuffix(prefix, "://")
}

// extractShellCandidates 对命令做 shell 词法切分，产出路径候选（含重定向目标、$(…) 一层）。
func extractShellCandidates(command string) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(w string) {
		w = strings.Trim(w, `"'`)
		if w == "" {
			return
		}
		if _, ok := seen[w]; ok {
			return
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	for _, tok := range shellTokens(command) {
		// 命令替换一层：$(cat a.pdf) → 递归切其内部
		if strings.HasPrefix(tok, "$(") && strings.HasSuffix(tok, ")") {
			for _, inner := range shellTokens(tok[2 : len(tok)-1]) {
				add(inner)
			}
			continue
		}
		add(tok)
	}
	return out
}

// shellTokens 简化 shell 词法切分：处理单/双引号、反斜杠转义、;/&&/||/| 分段、</>/2> 重定向。
func shellTokens(cmd string) []string {
	var tokens []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	runes := []rune(cmd)
	i := 0
	for i < len(runes) {
		r := runes[i]
		switch r {
		case '\\':
			if i+1 < len(runes) {
				cur.WriteRune(r)
				cur.WriteRune(runes[i+1])
				i += 2
				continue
			}
			cur.WriteRune(r)
			i++
		case '\'':
			// 单引号：原样到下一个单引号
			j := i + 1
			for j < len(runes) && runes[j] != '\'' {
				j++
			}
			cur.WriteString(string(runes[i+1 : j]))
			if j < len(runes) {
				j++
			}
			i = j
		case '"':
			// 双引号：处理反斜杠转义
			j := i + 1
			for j < len(runes) && runes[j] != '"' {
				if runes[j] == '\\' && j+1 < len(runes) {
					cur.WriteRune(runes[j+1])
					j += 2
					continue
				}
				cur.WriteRune(runes[j])
				j++
			}
			if j < len(runes) {
				j++
			}
			i = j
		case ' ', '\t', ';', '|', '&':
			flush()
			i++
		case '<', '>':
			flush()
			// 跳过重定向符号本身（含 2>、>>、>&）
			i++
			for i < len(runes) && (runes[i] == '>' || runes[i] == '&' || runes[i] == '<') {
				i++
			}
		case '$':
			// $(...) 命令替换：整体作为一个 token
			if i+1 < len(runes) && runes[i+1] == '(' {
				depth := 0
				j := i
				for j < len(runes) {
					if runes[j] == '(' {
						depth++
					} else if runes[j] == ')' {
						depth--
						if depth == 0 {
							j++
							break
						}
					}
					j++
				}
				cur.WriteString(string(runes[i:j]))
				i = j
			} else {
				// $VAR：跳过变量名（不作为路径候选）
				i++
				for i < len(runes) && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) || runes[i] == '_') {
					i++
				}
			}
		default:
			cur.WriteRune(r)
			i++
		}
	}
	flush()
	return tokens
}

// RedactTarget 脱敏目标：保留 basename 前 1 后（扩展名），中间打 ****；目录部分按原文保留。
func RedactTarget(target string) string {
	// 目录分隔按原文最后一个 / 或 \ 定位，保留原始分隔符风格。
	sepIdx := strings.LastIndexAny(target, "/\\")
	dir := ""
	base := target
	if sepIdx >= 0 {
		dir = target[:sepIdx+1]
		base = target[sepIdx+1:]
	}
	ext := lastExt(base)
	stem := base
	if ext != "" {
		stem = base[:len(base)-len(ext)-1]
	}
	first, _ := utf8.DecodeRuneInString(stem)
	redacted := string(first) + "****"
	if ext != "" {
		redacted += "." + ext
	}
	return dir + redacted
}
