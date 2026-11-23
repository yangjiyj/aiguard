package agentguard

import (
	"path"
	"strconv"
	"strings"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

const (
	maxDestructiveCommandBytes = 64 << 10
	maxDestructiveSyntaxNodes  = 4096
	maxDestructiveTargets      = 256
	maxDestructiveShellDepth   = 4
)

// 工作量上限（复审第八轮）：语法节点（maxDestructiveSyntaxNodes）、展开字面词时产生的候选值、
// 为证据打印的字节任一超出，解析标为不可靠，走现有 ParseRejected 路径。这些都是确定的计数，同一
// 输入在任何负载下结论相同。墙钟只作最后防线：做过的工作量（节点 + 候选值 + 打印字节/64 + 花括号
// 拆出的片段）超过 destructiveClockArmedWork 之后才开始计时，再过 maxDestructiveParseTime 仍未
// 结束才算不可靠。正常命令的工作量远低于这个门槛（测试逐条确认从不看时钟），结论与负载无关。
const (
	maxDestructiveCandidates   = 1 << 17
	maxDestructiveBraceOpens   = 1 << 10
	maxDestructivePrintedBytes = 1 << 20
	destructiveClockArmedWork  = 1 << 16
	maxDestructiveParseTime    = 2 * time.Second
)

// destructiveNow is the clock of the last-resort deadline (tests replace it).
var destructiveNow = time.Now

type destructiveParseBudget struct {
	nodes   int
	targets int
	// candidates: values built while expanding literal words; printed: bytes
	// printed for evidence; splitWork: parts the brace splits produced.
	candidates int
	printed    int
	splitWork  int
	// deadline is set once the work passes destructiveClockArmedWork.
	deadline  time.Time
	exhausted bool
	// split: the brace split of each word, done once per parse (the command
	// words, the evidence and the nested-script search all expand a word).
	split map[*syntax.Word][]syntax.WordPart
}

func newDestructiveParseBudget() *destructiveParseBudget {
	return &destructiveParseBudget{}
}

// work is the amount of work done so far, in deterministic units.
func (b *destructiveParseBudget) work() int {
	return b.nodes + b.candidates + b.printed/64 + b.splitWork
}

// spend counts candidates and printed bytes; it reports false once a limit is
// exceeded or, after the work passed destructiveClockArmedWork, the
// last-resort deadline has passed. A nil budget never runs out.
func (b *destructiveParseBudget) spend(candidates, printed int) bool {
	if b == nil {
		return true
	}
	b.candidates += candidates
	b.printed += printed
	if b.candidates > maxDestructiveCandidates || b.printed > maxDestructivePrintedBytes {
		b.exhausted = true
	}
	if !b.exhausted && b.work() > destructiveClockArmedWork {
		now := destructiveNow()
		if b.deadline.IsZero() {
			b.deadline = now.Add(maxDestructiveParseTime)
		} else if now.After(b.deadline) {
			b.exhausted = true
		}
	}
	return !b.exhausted
}

func parsePOSIXCommand(command string) ([]destructiveCommandSegment, bool) {
	return parsePOSIXScript(command, 0, newDestructiveParseBudget(), nil)
}

func parsePOSIXArgv(argv []string) ([]destructiveCommandSegment, bool) {
	outer := argvCommandSegment(argv)
	segments := []destructiveCommandSegment{outer}
	if script, ok := nestedShellScript(argv); ok {
		nested, reliable := parseNestedScript(script, 1, newDestructiveParseBudget(), nil, outer.Evidence)
		segments = append(segments, nested...)
		if !reliable {
			return segments, false
		}
	}
	return segments, true
}

// parseNestedScript 解析嵌套脚本：PowerShell 走词法兜底，其余按 POSIX。来自 -EncodedCommand 的脚本
// 证据用外层这条命令（outerEvidence），渲染时再解码，告警里不出现 base64 原文。
func parseNestedScript(nested nestedScript, depth int, budget *destructiveParseBudget, inherited *posixEnvLoader, outerEvidence []EvidenceWord) ([]destructiveCommandSegment, bool) {
	if !nested.Lexical {
		return parsePOSIXScript(nested.Script, depth, budget, inherited)
	}
	segments, reliable := parseShellCommand(nested.Script)
	for index := range segments {
		segments[index].EvidenceLexical = true
		if nested.Encoded {
			segments[index].Evidence = outerEvidence
			segments[index].EvidenceLexical = false
		}
	}
	return segments, reliable
}

// posixNestedCandidateWords 和 literalCallWords 一样取命令词，但含变量的词不丢，按源码写法保留
// （bash -c "rm -rf /srv/$Y" 的脚本），用来找嵌套脚本。
func posixNestedCandidateWords(p *posixPrinter, args []*syntax.Word) []string {
	words := make([]string, 0, len(args))
	for _, arg := range args {
		if !dynamicPOSIXWord(arg) {
			if values, _, ok := literalPOSIXFields(arg, maxDestructiveTargets, p.budgetOrNil()); ok {
				words = append(words, values...)
				continue
			}
		}
		words = append(words, posixScriptSource(p, arg.Parts, false))
	}
	return words
}

func posixScriptSource(p *posixPrinter, parts []syntax.WordPart, quoted bool) string {
	var builder strings.Builder
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.Lit:
			builder.WriteString(unescapePOSIXLiteral(part.Value, quoted))
		case *syntax.SglQuoted:
			if part.Dollar {
				builder.WriteString(p.print(part))
			} else {
				builder.WriteString(part.Value)
			}
		case *syntax.DblQuoted:
			builder.WriteString(posixScriptSource(p, part.Parts, true))
		default:
			builder.WriteString(p.print(part))
		}
	}
	return builder.String()
}

func parsePOSIXScript(script string, depth int, budget *destructiveParseBudget, inherited *posixEnvLoader) ([]destructiveCommandSegment, bool) {
	if depth > maxDestructiveShellDepth {
		return nil, false
	}
	reliable := true
	if len(script) > maxDestructiveCommandBytes {
		script = script[:maxDestructiveCommandBytes]
		reliable = false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "")
	if err != nil {
		if reliable || !syntax.IsIncomplete(err) {
			return nil, false
		}
		completed := completedPOSIXStatements(script)
		if len(completed) == 0 {
			return nil, false
		}
		file = &syntax.File{Stmts: completed}
	}

	envLoader := &posixEnvLoader{file: file, parent: inherited}
	printer := &posixPrinter{source: script, budget: budget}
	segments := make([]destructiveCommandSegment, 0, 4)
	walking := true
	var stack []syntax.Node
	enclosingStmt := func() *syntax.Stmt {
		for index := len(stack) - 2; index >= 0; index-- {
			if stmt, ok := stack[index].(*syntax.Stmt); ok {
				return stmt
			}
		}
		return nil
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if !walking {
			return false
		}
		stack = append(stack, node)
		budget.nodes++
		if budget.nodes > maxDestructiveSyntaxNodes || !budget.spend(0, 0) {
			reliable = false
			walking = false
			return false
		}
		switch node := node.(type) {
		case *syntax.CallExpr:
			words, dynamicArguments, rejected, ok := literalCallWords(node.Args, budget)
			if ok && len(words) > 0 {
				callSegment := destructiveCommandSegment{Words: words, DynamicArguments: dynamicArguments, ParseRejected: rejected}
				if stmt := enclosingStmt(); stmt != nil {
					callSegment.Evidence = posixStmtEvidence(printer, stmt)
				}
				segments = append(segments, callSegment)
				script, nested := nestedShellScript(words)
				fromDynamicWord := false
				if !nested && dynamicArguments {
					// 脚本本身含变量（bash -c "rm -rf $DIR"）：按源码写法解析，命中的段都算动态参数。
					script, nested = nestedShellScript(posixNestedCandidateWords(printer, node.Args))
					fromDynamicWord = nested
				}
				if nested {
					if depth >= maxDestructiveShellDepth {
						reliable = false
						walking = false
						return false
					}
					nestedSegments, nestedReliable := parseNestedScript(script, depth+1, budget, envLoader, callSegment.Evidence)
					if fromDynamicWord {
						for index := range nestedSegments {
							nestedSegments[index].DynamicArguments = true
						}
					}
					segments = append(segments, nestedSegments...)
					if !nestedReliable {
						reliable = false
						walking = false
						return false
					}
				}
			}
		case *syntax.Redirect:
			// >&文件 与 &> 文件相同（标准输出和错误都写进文件）；>&2、>&- 是复制、关闭描述符，不写文件。
			if !destructiveOutputRedirect(node.Op) && !(node.Op == syntax.DplOut && posixDupTargetIsFile(node.Word, budget)) {
				break
			}
			budget.targets++
			if budget.targets > maxDestructiveTargets {
				reliable = false
				walking = false
				return false
			}
			dynamicTarget := dynamicPOSIXWord(node.Word) || unsafeStaticPOSIXWord(node.Word)
			appendRedirect := node.Op == syntax.AppOut || node.Op == syntax.AppAll
			segment := destructiveCommandSegment{Redirect: true, AppendMode: appendRedirect, DynamicArguments: dynamicTarget, ParseRejected: dynamicTarget}
			segment.Evidence = posixRedirectSegmentEvidence(printer, enclosingStmt(), node)
			if dynamicTarget && appendRedirect && simplePOSIXParamWord(node.Word) {
				// 追加到 "$LOG" 这类简单参数展开目标：同一脚本里的纯字面赋值代入后按静态路径定级；
				// 外部环境变量只看字面片段；任何运行时赋值来源都回到解析不完整兜底。
				// 候选不在这里筛选：工作目录要到分析阶段才知道，由 analyzeDestructiveCommand 统一定级。
				env := envLoader.get()
				if candidates, external, ok := appendTargetCandidates(node.Word, env); ok && !(external && dynamicWordHasSensitiveLiteral(node.Word)) &&
					!(anyRelativeTarget(candidates) && env.cdOverflow()) {
					segment.DynamicArguments = false
					segment.ParseRejected = false
					segment.AppendRedirects = candidates
					segment.BaseDirs = env.cdTargets()
					segments = append(segments, segment)
					break
				}
			}
			if !segment.DynamicArguments {
				targets, exceeded, ok := literalPOSIXFields(node.Word, maxDestructiveTargets, budget)
				segment.DynamicArguments = !ok
				segment.ParseRejected = exceeded || !ok
				if ok {
					targets = nonEmptyStrings(targets)
					unresolved := false
					if anyTildeTarget(targets) {
						// 同脚本赋值过 HOME 时，~/ 一并按 HOME 的值展开；HOME 来自运行时取值则无法静态判断。
						var homeDynamic bool
						targets, homeDynamic = expandHomeTargets(targets, envLoader.get())
						unresolved = homeDynamic
					}
					if !unresolved && anyRelativeTarget(targets) {
						env := envLoader.get()
						unresolved = env.cdOverflow() // cd 目标太多，无法逐个拼接
						segment.BaseDirs = env.cdTargets()
					}
					if unresolved {
						targets = nil
						segment.BaseDirs = nil
						segment.DynamicArguments = true
						segment.ParseRejected = true
					}
					if appendRedirect {
						segment.AppendRedirects = targets
					} else {
						segment.Redirects = targets
					}
				}
			}
			segments = append(segments, segment)
		}
		if budget.exhausted {
			reliable = false
			walking = false
			return false
		}
		return true
	})
	return segments, reliable
}

func completedPOSIXStatements(script string) []*syntax.Stmt {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	statements := make([]*syntax.Stmt, 0, 4)
	_ = parser.Interactive(strings.NewReader(script+"\n"), func(completed []*syntax.Stmt) bool {
		statements = append(statements, completed...)
		if parser.Incomplete() {
			return false
		}
		return true
	})
	return statements
}

func literalCallWords(words []*syntax.Word, budget *destructiveParseBudget) ([]string, bool, bool, bool) {
	result := make([]string, 0, len(words))
	dynamicArguments := false
	rejected := false
	for index, word := range words {
		if dynamicPOSIXWord(word) {
			if index == 0 {
				return nil, false, false, false
			}
			dynamicArguments = true
			continue
		}
		values, exceeded, ok := literalPOSIXFields(word, maxDestructiveTargets, budget)
		if index == 0 && ok && len(values) != 1 {
			return nil, false, exceeded, false
		}
		if exceeded {
			dynamicArguments = true
			rejected = true
		}
		if !ok {
			if index == 0 {
				return nil, false, rejected, false
			}
			dynamicArguments = true
			continue
		}
		result = append(result, values...)
	}
	return result, dynamicArguments, rejected, true
}

func dynamicPOSIXWord(word *syntax.Word) bool {
	dynamic := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if node == nil || dynamic {
			return false
		}
		switch node.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
			dynamic = true
			return false
		default:
			return true
		}
	})
	return dynamic
}

// literalPOSIXFields expands a literal word (braces, quotes) into at most
// limit fields. Once budget runs out it gives up (not ok, exceeded).
func literalPOSIXFields(word *syntax.Word, limit int, budget *destructiveParseBudget) ([]string, bool, bool) {
	if limit <= 0 {
		return nil, true, true
	}
	if budget != nil && budget.exhausted {
		return nil, true, false
	}
	return evaluatePOSIXParts(budget.splitParts(word), limit, budget)
}

// splitParts returns the parts of word with its brace expressions split out,
// once per parse when a budget is given.
func (b *destructiveParseBudget) splitParts(word *syntax.Word) []syntax.WordPart {
	if b != nil {
		if parts, ok := b.split[word]; ok {
			return parts
		}
	}
	// mvdan's SplitBraces costs the square of the number of "{" when they do
	// not close ("cat " + 64000 "{": 31GB): past maxDestructiveBraceOpens the
	// word is not split and the budget runs out (the parse is unreliable).
	opens := 0
	for _, part := range word.Parts {
		if literal, ok := part.(*syntax.Lit); ok {
			opens += strings.Count(literal.Value, "{")
		}
	}
	if b != nil {
		b.splitWork += opens
		if opens > maxDestructiveBraceOpens {
			b.exhausted = true
			return word.Parts
		}
	}
	wordCopy := *word
	wordCopy.Parts = append([]syntax.WordPart(nil), word.Parts...)
	syntax.SplitBraces(&wordCopy)
	if b != nil {
		if b.split == nil {
			b.split = map[*syntax.Word][]syntax.WordPart{}
		}
		b.split[word] = wordCopy.Parts
		b.splitWork += len(wordCopy.Parts)
	}
	return wordCopy.Parts
}

func evaluatePOSIXParts(parts []syntax.WordPart, limit int, budget *destructiveParseBudget) ([]string, bool, bool) {
	return evaluatePOSIXQuotedParts(parts, limit, false, budget)
}

func evaluatePOSIXQuotedParts(parts []syntax.WordPart, limit int, quoted bool, budget *destructiveParseBudget) ([]string, bool, bool) {
	// 逐个片段做乘积时只记“前缀 + 本片段”，最后一次拼出字符串：改前每一步都把已有的值整串
	// 复制一遍，12000 个花括号片段的词要复制几十 GB。值、顺序、是否超出与改前逐一相同。
	values := []*posixProductValue{nil}
	exceeded := false
	for _, part := range parts {
		alternatives, partExceeded, ok := evaluatePOSIXPart(part, limit, quoted, budget)
		if !ok {
			return nil, exceeded || partExceeded, false
		}
		var productExceeded bool
		values, productExceeded = boundedValueProduct(values, alternatives, limit)
		exceeded = exceeded || partExceeded || productExceeded
		if !budget.spend(len(values), 0) {
			return nil, true, false
		}
	}
	return materializeProductValues(values), exceeded, true
}

func evaluatePOSIXPart(part syntax.WordPart, limit int, quoted bool, budget *destructiveParseBudget) ([]string, bool, bool) {
	switch part := part.(type) {
	case *syntax.Lit:
		return []string{unescapePOSIXLiteral(part.Value, quoted)}, false, true
	case *syntax.SglQuoted:
		return []string{part.Value}, false, true
	case *syntax.DblQuoted:
		return evaluatePOSIXQuotedParts(part.Parts, limit, true, budget)
	case *syntax.BraceExp:
		return evaluatePOSIXBrace(part, limit, budget)
	default:
		return nil, false, false
	}
}

func evaluatePOSIXBrace(brace *syntax.BraceExp, limit int, budget *destructiveParseBudget) ([]string, bool, bool) {
	if brace.Sequence {
		return evaluatePOSIXBraceSequence(brace, limit, budget)
	}
	values := make([]string, 0, min(len(brace.Elems), limit))
	exceeded := false
	for _, element := range brace.Elems {
		elementValues, elementExceeded, ok := evaluatePOSIXParts(element.Parts, limit, budget)
		if !ok {
			return nil, exceeded || elementExceeded, false
		}
		exceeded = exceeded || elementExceeded
		remaining := limit - len(values)
		if remaining <= 0 {
			exceeded = true
			break
		}
		if len(elementValues) > remaining {
			values = append(values, elementValues[:remaining]...)
			exceeded = true
			break
		}
		values = append(values, elementValues...)
	}
	return values, exceeded, true
}

func evaluatePOSIXBraceSequence(brace *syntax.BraceExp, limit int, budget *destructiveParseBudget) ([]string, bool, bool) {
	if len(brace.Elems) < 2 || len(brace.Elems) > 3 {
		return nil, false, false
	}
	elements := make([]string, 0, len(brace.Elems))
	for _, element := range brace.Elems {
		values, exceeded, ok := evaluatePOSIXParts(element.Parts, 1, budget)
		if !ok || exceeded || len(values) != 1 {
			return nil, exceeded, false
		}
		elements = append(elements, values[0])
	}

	charSequence := len(elements[0]) == 1 && len(elements[1]) == 1 &&
		isASCIILetter(elements[0][0]) && isASCIILetter(elements[1][0])
	var from, to int64
	var err error
	if charSequence {
		from, to = int64(elements[0][0]), int64(elements[1][0])
	} else {
		from, err = strconv.ParseInt(elements[0], 10, 64)
		if err != nil {
			return nil, false, false
		}
		to, err = strconv.ParseInt(elements[1], 10, 64)
		if err != nil {
			return nil, false, false
		}
	}
	step := int64(1)
	if from > to {
		step = -1
	}
	if len(elements) == 3 {
		requested, parseErr := strconv.ParseInt(elements[2], 10, 64)
		if parseErr != nil {
			return nil, false, false
		}
		if requested != 0 && (requested > 0) == (from <= to) {
			step = requested
		}
	}

	width := 0
	if !charSequence && (hasLeadingZero(elements[0]) || hasLeadingZero(elements[1])) {
		width = max(len(elements[0]), len(elements[1]))
	}
	values := make([]string, 0, limit)
	current := from
	for len(values) < limit && sequenceContains(current, to, step) {
		if charSequence {
			values = append(values, string(rune(current)))
		} else if width > 0 {
			values = append(values, leftPadNumber(current, width))
		} else {
			values = append(values, strconv.FormatInt(current, 10))
		}
		current += step
	}
	return values, sequenceContains(current, to, step), true
}

// posixProductValue is one value of a product of word parts: the value of
// the parts before (shared with the other values that extend it) and the text
// this part adds. nil is the empty value.
type posixProductValue struct {
	prefix *posixProductValue
	text   string
	size   int
}

// boundedValueProduct is the product of left and right in prefix-major order,
// at most limit values; exceeded when the full product would be larger.
func boundedValueProduct(left []*posixProductValue, right []string, limit int) ([]*posixProductValue, bool) {
	if len(left) == 0 || len(right) == 0 {
		return nil, false
	}
	exceeded := len(left) > limit/len(right)
	values := make([]*posixProductValue, 0, min(len(left)*len(right), limit))
	for _, prefix := range left {
		size := 0
		if prefix != nil {
			size = prefix.size
		}
		for _, suffix := range right {
			if len(values) >= limit {
				return values, true
			}
			values = append(values, &posixProductValue{prefix: prefix, text: suffix, size: size + len(suffix)})
		}
	}
	return values, exceeded
}

// materializeProductValues builds the strings of product values (nil for
// none, as before).
func materializeProductValues(values []*posixProductValue) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for index, value := range values {
		if value == nil {
			continue
		}
		buffer := make([]byte, value.size)
		at := value.size
		for node := value; node != nil; node = node.prefix {
			at -= len(node.text)
			copy(buffer[at:], node.text)
		}
		out[index] = string(buffer)
	}
	return out
}

func nonEmptyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func isASCIILetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func hasLeadingZero(value string) bool {
	value = strings.TrimPrefix(value, "-")
	return len(value) > 1 && value[0] == '0'
}

func leftPadNumber(value int64, width int) string {
	raw := strconv.FormatInt(value, 10)
	prefix := ""
	if strings.HasPrefix(raw, "-") {
		prefix = "-"
		raw = strings.TrimPrefix(raw, "-")
	}
	return prefix + strings.Repeat("0", max(0, width-len(prefix)-len(raw))) + raw
}

func sequenceContains(current, end, step int64) bool {
	if step > 0 {
		return current <= end
	}
	return current >= end
}

// unescapePOSIXLiteral 按 bash 规则还原字面量里的反斜杠转义。
// 双引号内只有 \$、\`、\"、\\ 和反斜杠换行是转义，其余反斜杠原样保留（"C:\Users\u" 不变）；
// 未加引号时反斜杠转义其后的任意字符。
func unescapePOSIXLiteral(value string, doubleQuoted bool) string {
	if !strings.Contains(value, "\\") {
		return value
	}
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+1 < len(value) {
			next := value[index+1]
			if doubleQuoted {
				switch next {
				case '$', '`', '"', '\\':
					index++
				case '\n':
					index++
					continue
				}
			} else {
				index++
			}
		}
		result.WriteByte(value[index])
	}
	return result.String()
}

func literalDockerExecShellScript(words []string) (string, bool) {
	if len(words) < 5 {
		return "", false
	}
	command := strings.ToLower(path.Base(strings.ReplaceAll(words[0], "\\", "/")))
	if command != "docker" {
		return "", false
	}
	index := 1
	for index < len(words) && strings.HasPrefix(words[index], "-") {
		if words[index] == "--" {
			index++
			break
		}
		if dockerOptionConsumesNext(words[index]) && index+1 < len(words) {
			index += 2
			continue
		}
		index++
	}
	if index >= len(words) || !strings.EqualFold(words[index], "exec") {
		return "", false
	}
	index++
	for index < len(words) && strings.HasPrefix(words[index], "-") {
		if words[index] == "--" {
			index++
			break
		}
		if dockerExecOptionConsumesNext(words[index]) && index+1 < len(words) {
			index += 2
			continue
		}
		index++
	}
	if index >= len(words) {
		return "", false
	}
	index++ // container name/id
	if index >= len(words) {
		return "", false
	}
	return literalShellScript(destructiveCommandWords(words[index:]))
}

func dockerOptionConsumesNext(option string) bool {
	if strings.Contains(option, "=") {
		return false
	}
	switch option {
	case "-c", "--config", "-H", "--host", "-l", "--log-level", "--context":
		return true
	default:
		return false
	}
}

func dockerExecOptionConsumesNext(option string) bool {
	if strings.Contains(option, "=") {
		return false
	}
	switch option {
	case "-d", "--detach", "-i", "--interactive", "-t", "--tty", "--privileged":
		return false
	case "-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir":
		return true
	default:
		return false
	}
}

func literalShellScript(words []string) (string, bool) {
	if len(words) < 3 {
		return "", false
	}
	command := strings.ToLower(path.Base(strings.ReplaceAll(words[0], "\\", "/")))
	switch command {
	case "sh", "bash", "dash", "zsh":
	default:
		return "", false
	}
	for index := 1; index+1 < len(words); index++ {
		if shellCommandFlag(words[index]) {
			return words[index+1], true
		}
	}
	return "", false
}

func shellCommandFlag(value string) bool {
	if value == "-c" {
		return true
	}
	return strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(value, "c")
}

// posixDupTargetIsFile 判断 >& 后面的字面词是不是文件名：数字（>&2）、-（>&-）和 3- 这类移动描述符的写法不是；
// 含变量的词运行时才知道是描述符还是文件，不当文件。
func posixDupTargetIsFile(word *syntax.Word, budget *destructiveParseBudget) bool {
	if word == nil || dynamicPOSIXWord(word) {
		return false
	}
	values, exceeded, ok := literalPOSIXFields(word, 2, budget)
	if !ok || exceeded || len(values) != 1 {
		return false
	}
	value := strings.TrimSuffix(values[0], "-")
	for _, r := range value {
		if r < '0' || r > '9' {
			return true
		}
	}
	return false
}

func destructiveOutputRedirect(operator syntax.RedirOperator) bool {
	switch operator {
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		return true
	default:
		return false
	}
}

// dynamicWordHasSensitiveLiteral 取动态词里变量以外的字面片段，判断是否指向敏感路径。
func dynamicWordHasSensitiveLiteral(word *syntax.Word) bool {
	sensitive := false
	var visit func(parts []syntax.WordPart, quoted bool)
	visit = func(parts []syntax.WordPart, quoted bool) {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				sensitive = sensitive || sensitiveLiteralFragment(unescapePOSIXLiteral(part.Value, quoted))
			case *syntax.SglQuoted:
				sensitive = sensitive || sensitiveLiteralFragment(part.Value)
			case *syntax.DblQuoted:
				visit(part.Parts, true)
			}
		}
	}
	visit(word.Parts, false)
	return sensitive
}

// simplePOSIXParamWord 判断词的动态部分是否全是不带运算符的简单参数展开（$VAR、${VAR}）。
// 命令替换、进程替换、算术展开和带运算符的参数展开（默认值、切片、替换、间接、长度等）
// 都可能在运行时拼出任意路径，不属于简单展开。
func simplePOSIXParamWord(word *syntax.Word) bool {
	var simple func(parts []syntax.WordPart) bool
	simple = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				if hasUnescapedGlob(part.Value) {
					return false
				}
			case *syntax.SglQuoted:
				if part.Dollar { // $'...' 的转义可拼出任意路径
					return false
				}
			case *syntax.DblQuoted:
				if part.Dollar || !simple(part.Parts) {
					return false
				}
			case *syntax.ParamExp:
				if part.Param == nil || positionalOrSpecialParam(part.Param.Value) || part.Excl || part.Length || part.Width || part.Index != nil ||
					part.Slice != nil || part.Repl != nil || part.Names != 0 || part.Exp != nil {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	return simple(word.Parts)
}

// hasUnescapedGlob 判断未加引号的字面量里是否含未转义的通配符，通配符目标可能匹配到任意文件。
func hasUnescapedGlob(value string) bool {
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\\':
			index++
		case '*', '?', '[':
			return true
		}
	}
	return false
}

// unsafeStaticPOSIXWord 判断没有变量展开的目标是否仍无法按字面路径判断：
// 未转义的通配符，或 $'...'、$"..." 这类带转义语义的引号。
func unsafeStaticPOSIXWord(word *syntax.Word) bool {
	var visit func(parts []syntax.WordPart, quoted bool) bool
	visit = func(parts []syntax.WordPart, quoted bool) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				if !quoted && hasUnescapedGlob(part.Value) {
					return true
				}
			case *syntax.SglQuoted:
				if part.Dollar {
					return true
				}
			case *syntax.DblQuoted:
				if part.Dollar || visit(part.Parts, true) {
					return true
				}
			}
		}
		return false
	}
	return visit(word.Parts, false)
}

func anyTildeTarget(targets []string) bool {
	for _, target := range targets {
		if target == "~" || strings.HasPrefix(target, "~/") {
			return true
		}
	}
	return false
}

func anyRelativeTarget(targets []string) bool {
	for _, target := range targets {
		if relativeWriteTarget(target) {
			return true
		}
	}
	return false
}
