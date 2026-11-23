package agentguard

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// EvidenceWordKind 区分触发段里每个词的角色，告警证据按角色决定显示什么。
type EvidenceWordKind uint8

const (
	// EvidenceArg 是可执行文件或命令参数（含选项）。
	EvidenceArg EvidenceWordKind = iota
	// EvidenceAssign 是前置赋值，Text 只有变量名，值不保留。
	EvidenceAssign
	// EvidenceRedirectOp 是重定向操作符。
	EvidenceRedirectOp
	// EvidenceRedirectTarget 是重定向的目标。
	EvidenceRedirectTarget
	// EvidenceHeredoc 是 heredoc，Text 是操作符加定界符，Lines 是正文行数，正文不保留。
	EvidenceHeredoc
	// EvidenceHereString 是 here-string，内容不保留。
	EvidenceHereString
)

// EvidenceWord 是触发段里的一个词。
type EvidenceWord struct {
	Kind EvidenceWordKind
	Text string
	// Target 表示分析器把这个词认定为破坏目标（删除或覆盖的对象）。
	Target bool
	// Dynamic 表示词里有变量、命令替换等，Text 是源码原文而不是求值结果。
	Dynamic bool
	// Source 是词在源码里的原始写法（POSIX 解析得到的词有，argv 和词法兜底没有），显示目标时用它保留原样。
	Source string
	Lines  int
}

// EvidenceSegment 是分析器判定为破坏性的那一段：POSIX 是一条简单命令连同它的前置赋值和重定向，
// 词法兜底（PowerShell、cmd）是一段 token，SQL 是一条语句。不含管道左侧、前后其它命令和 heredoc 正文。
type EvidenceSegment struct {
	Words []EvidenceWord
	// Lexical 表示这一段来自词法兜底（PowerShell、cmd），选项写法是 -Name、/x。
	Lexical bool
	// SQL 是触发的那条语句原文（未规范化）。
	SQL string
}

func (segment EvidenceSegment) key() string {
	if segment.SQL != "" {
		return "sql\x00" + segment.SQL
	}
	var builder strings.Builder
	for _, word := range segment.Words {
		builder.WriteByte(byte('0' + word.Kind))
		builder.WriteString(word.Text)
		builder.WriteByte(0)
	}
	return builder.String()
}

func appendEvidenceSegment(segments []EvidenceSegment, candidate EvidenceSegment) []EvidenceSegment {
	if len(candidate.Words) == 0 && candidate.SQL == "" {
		return segments
	}
	key := candidate.key()
	for index, existing := range segments {
		if existing.key() != key {
			continue
		}
		// 同一段被多个发现命中时合并“目标”标记。
		for position := range existing.Words {
			if position < len(candidate.Words) && candidate.Words[position].Target {
				segments[index].Words[position].Target = true
			}
		}
		return segments
	}
	return append(segments, candidate)
}

func plainEvidenceWords(values []string) []EvidenceWord {
	words := make([]EvidenceWord, 0, len(values))
	for _, value := range values {
		words = append(words, EvidenceWord{Kind: EvidenceArg, Text: value})
	}
	return words
}

func rawAt(raws []string, index int) string {
	if index < len(raws) {
		return raws[index]
	}
	return ""
}

func lexerEvidenceWords(segment destructiveCommandSegment) []EvidenceWord {
	words := plainEvidenceWords(segment.Words)
	for index := range words {
		words[index].Source = rawAt(segment.RawWords, index)
	}
	for index, target := range segment.Redirects {
		words = append(words, EvidenceWord{Kind: EvidenceRedirectOp, Text: ">"}, EvidenceWord{Kind: EvidenceRedirectTarget, Text: target, Source: rawAt(segment.RawRedirects, index)})
	}
	for index, target := range segment.AppendRedirects {
		words = append(words, EvidenceWord{Kind: EvidenceRedirectOp, Text: ">>"}, EvidenceWord{Kind: EvidenceRedirectTarget, Text: target, Source: rawAt(segment.RawAppendRedirects, index)})
	}
	return words
}

// markEvidenceTargets 复制一份词并标出分析器认定为破坏目标的词。
func markEvidenceTargets(words []EvidenceWord, targets []string) []EvidenceWord {
	marked := append([]EvidenceWord(nil), words...)
	if len(targets) == 0 {
		return marked
	}
	for index, word := range marked {
		if word.Kind != EvidenceArg || word.Dynamic {
			continue
		}
		if evidenceTargetMatches(word.Text, targets) {
			marked[index].Target = true
		} else if name, value, ok := strings.Cut(word.Text, "="); ok && !strings.HasPrefix(word.Text, "-") && name != "" && evidenceTargetMatches(value, targets) {
			marked[index].Target = true // dd of=/dev/sdb：name=value 词的值是目标
		}
	}
	return marked
}

func evidenceTargetMatches(text string, targets []string) bool {
	if text == "" || strings.HasPrefix(text, "-") {
		return false
	}
	cleaned := strings.ToLower(path.Clean(strings.ReplaceAll(text, `\`, "/")))
	trimmed := strings.TrimPrefix(cleaned, "./")
	for _, target := range targets {
		normalized := strings.ToLower(path.Clean(strings.ReplaceAll(target, `\`, "/")))
		if normalized == cleaned || normalized == trimmed || strings.HasSuffix(normalized, "/"+trimmed) {
			return true
		}
	}
	return false
}

func printPOSIXNode(node syntax.Node) string {
	var builder strings.Builder
	if err := syntax.NewPrinter().Print(&builder, node); err != nil {
		return ""
	}
	return strings.TrimRight(builder.String(), "\n")
}

// maxPrintedNodeBytes: a node whose source is longer is cut from the source
// instead of printed. Printing a node prints its whole subtree, so printing
// every level of $(echo $(echo ...)) costs the square of the depth.
const maxPrintedNodeBytes = 8 << 10

// posixPrinter prints the nodes of one parsed script for evidence and counts
// the printed bytes in the parse budget.
type posixPrinter struct {
	source string
	budget *destructiveParseBudget
	// printer is reused for every node of the parse: a new syntax.Printer
	// allocates its own 4KB buffer (13000 words: tens of MB per command).
	// Print resets it, so the output is the same as with a new one.
	printer *syntax.Printer
}

func (p *posixPrinter) budgetOrNil() *destructiveParseBudget {
	if p == nil {
		return nil
	}
	return p.budget
}

// print prints node as before (the printer normalizes spacing), or cuts a
// long node from the source as written.
func (p *posixPrinter) print(node syntax.Node) string {
	if p != nil && node.Pos().IsValid() && node.End().IsValid() {
		start, end := int(node.Pos().Offset()), int(node.End().Offset())
		if end-start > maxPrintedNodeBytes && start >= 0 && end <= len(p.source) {
			return p.source[start:end]
		}
		if end > start {
			p.budget.spend(0, end-start)
		}
	}
	if p == nil {
		return printPOSIXNode(node)
	}
	if p.printer == nil {
		p.printer = syntax.NewPrinter()
	}
	var builder strings.Builder
	if err := p.printer.Print(&builder, node); err != nil {
		return ""
	}
	return strings.TrimRight(builder.String(), "\n")
}

func posixEvidenceWord(p *posixPrinter, word *syntax.Word) EvidenceWord {
	if values, exceeded, ok := literalPOSIXFields(word, 1, p.budgetOrNil()); ok && !exceeded && len(values) == 1 {
		return EvidenceWord{Kind: EvidenceArg, Text: values[0], Source: p.print(word)}
	}
	return EvidenceWord{Kind: EvidenceArg, Text: p.print(word), Dynamic: true}
}

// posixStmtEvidence 取一条语句里的命令词、前置赋值（只留变量名）和重定向，不含 heredoc 正文。
func posixStmtEvidence(p *posixPrinter, stmt *syntax.Stmt) []EvidenceWord {
	var words []EvidenceWord
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
		for _, assign := range call.Assigns {
			name := ""
			if assign.Name != nil {
				name = assign.Name.Value
			}
			words = append(words, EvidenceWord{Kind: EvidenceAssign, Text: name})
		}
		for _, arg := range call.Args {
			words = append(words, posixEvidenceWord(p, arg))
		}
	}
	for _, redirect := range stmt.Redirs {
		words = append(words, posixRedirectEvidence(p, redirect)...)
	}
	return words
}

func posixRedirectEvidence(p *posixPrinter, redirect *syntax.Redirect) []EvidenceWord {
	operator := redirect.Op.String()
	if redirect.N != nil {
		operator = redirect.N.Value + operator
	}
	target := EvidenceWord{Kind: EvidenceRedirectTarget}
	if redirect.Word != nil {
		target = posixEvidenceWord(p, redirect.Word)
		target.Kind = EvidenceRedirectTarget
	}
	switch redirect.Op {
	case syntax.Hdoc, syntax.DashHdoc:
		delimiter := ""
		if redirect.Word != nil {
			delimiter = p.print(redirect.Word)
		}
		return []EvidenceWord{{Kind: EvidenceHeredoc, Text: operator + delimiter, Lines: heredocLines(redirect.Hdoc)}}
	case syntax.WordHdoc:
		return []EvidenceWord{{Kind: EvidenceHereString, Text: operator}}
	case syntax.DplIn, syntax.DplOut:
		if redirect.Op == syntax.DplOut && posixDupTargetIsFile(redirect.Word, p.budgetOrNil()) {
			return []EvidenceWord{{Kind: EvidenceRedirectOp, Text: operator}, target} // >& 文件
		}
		return []EvidenceWord{{Kind: EvidenceRedirectOp, Text: operator + target.Text}}
	}
	return []EvidenceWord{{Kind: EvidenceRedirectOp, Text: operator}, target}
}

func heredocLines(body *syntax.Word) int {
	if body == nil {
		return 0
	}
	lines, total := 0, 0
	for _, part := range body.Parts {
		if lit, ok := part.(*syntax.Lit); ok {
			lines += strings.Count(lit.Value, "\n")
			total += len(lit.Value)
		} else {
			total++
		}
	}
	if lines == 0 && total > 0 {
		lines = 1
	}
	return lines
}

// posixRedirectSegmentEvidence 给重定向段写证据：重定向挂在简单命令上时写整条命令（cat a > b），
// 挂在复合命令（花括号、循环、子 shell）上时只写这个重定向。
func posixRedirectSegmentEvidence(p *posixPrinter, stmt *syntax.Stmt, redirect *syntax.Redirect) []EvidenceWord {
	if stmt != nil {
		if _, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			return posixStmtEvidence(p, stmt)
		}
	}
	return posixRedirectEvidence(p, redirect)
}

// sqlEvidenceStatements 按引号、美元引用、注释切分原始 SQL，用于从原文里取出触发的那条语句。
func sqlEvidenceStatements(query string) []string {
	var statements []string
	start := 0
	flush := func(end int) {
		if statement := strings.TrimSpace(query[start:end]); statement != "" {
			statements = append(statements, statement)
		}
		start = end + 1
	}
	for index := 0; index < len(query); index++ {
		switch ch := query[index]; {
		case ch == '\'' || ch == '"' || ch == '`':
			for index++; index < len(query); index++ {
				if query[index] == '\\' && ch != '`' {
					index++
					continue
				}
				if query[index] == ch {
					if index+1 < len(query) && query[index+1] == ch {
						index++
						continue
					}
					break
				}
			}
		case ch == '$':
			end := index + 1
			for end < len(query) && (query[end] == '_' || query[end] >= 'a' && query[end] <= 'z' || query[end] >= 'A' && query[end] <= 'Z' || query[end] >= '0' && query[end] <= '9') {
				end++
			}
			if end < len(query) && query[end] == '$' {
				tag := query[index : end+1]
				if close := strings.Index(query[end+1:], tag); close >= 0 {
					index = end + 1 + close + len(tag) - 1
				} else {
					index = len(query)
				}
			}
		case ch == '-' && index+1 < len(query) && query[index+1] == '-':
			for index < len(query) && query[index] != '\n' {
				index++
			}
		case ch == '/' && index+1 < len(query) && query[index+1] == '*':
			if close := strings.Index(query[index+2:], "*/"); close >= 0 {
				index += 2 + close + 1
			} else {
				index = len(query)
			}
		case ch == ';':
			flush(index)
		}
	}
	flush(len(query))
	return statements
}

// ParsedEvidenceSegments 返回命令里解析出的每一段（不论是否判定为破坏性，也不带目标标记），
// 供证据渲染规则的回归逐条验证；告警证据本身只用 DestructiveAnalysis.EvidenceSegments。
func ParsedEvidenceSegments(input DestructiveInput) []EvidenceSegment {
	var result []EvidenceSegment
	for _, executable := range executableInputs(input.Arguments) {
		segments, _ := executableCommandSegments(input, executable)
		for _, segment := range segments {
			result = appendEvidenceSegment(result, EvidenceSegment{Words: segment.Evidence, Lexical: segment.EvidenceLexical})
		}
	}
	return result
}
