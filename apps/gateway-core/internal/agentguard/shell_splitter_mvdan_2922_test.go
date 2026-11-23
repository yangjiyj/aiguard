package agentguard

import (
	"fmt"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// 手写分词与 mvdan.cc/sh 语法树对照（代码质量审查重要项 1，只在测试里跑）：对 mvdan 能解析的输入
// （本包与 handler 包测试文件里的全部字符串字面量，含各条测试的命令和语料），语法树里每个
// here-document 的定界符（去引号后）与正文原文，都要在手写分词的结果里找到（顺着命令替换往里找）；
// 每个词里最外层的 $(...)、`...` 的正文，都要被 commandSubstitutions 找到。手写的可以多找（偏严），
// 不能少。
//
// mvdan 与 bash 不同、手写分词照 bash 的三处不比：
//   - 定界符行末尾带 "\r"（"EOF\r"）：bash 不认它结束 heredoc，mvdan 认；
//   - $(...) 里的 "EOF)"：bash 5.3 认它结束 heredoc 并闭合替换，mvdan 不认；
//   - 反引号替换末尾的 "\`"：bash 是转义的反引号（替换没闭合），mvdan 当作闭合。
func TestSplitterAgreesWithMvdanAST2922(t *testing.T) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	checked, heredocs, substitutions := 0, 0, 0
	for _, command := range testStringLiterals(t, ".", "../handler") {
		file, err := parser.Parse(strings.NewReader(command), "")
		if err != nil {
			continue
		}
		if mvdanDiffersFromBash(file, command) {
			continue
		}
		checked++
		found := handWrittenHeredocs(command)
		syntax.Walk(file, func(node syntax.Node) bool {
			switch node := node.(type) {
			case *syntax.Redirect:
				if node.Op != syntax.Hdoc && node.Op != syntax.DashHdoc {
					return true
				}
				delim, ok := astHeredocDelimiter(node.Word)
				if !ok {
					return true
				}
				// mvdan's Hdoc spans the body and the delimiter line; the body
				// is the text up to that last line.
				body := ""
				if node.Hdoc != nil {
					span := command[node.Hdoc.Pos().Offset():node.Hdoc.End().Offset()]
					body = span[:strings.LastIndexByte(span, '\n')+1]
				}
				heredocs++
				if !found[delim+"\x00"+body] {
					t.Errorf("heredoc %q with body %q not found by the splitter in %q", delim, body, command)
				}
			case *syntax.Word:
				raw := command[node.Pos().Offset():node.End().Offset()]
				hand := map[string]bool{}
				for _, body := range commandSubstitutions(raw, nil) {
					hand[body] = true
				}
				for _, substitution := range outermostSubstitutions(node) {
					var body string
					if substitution.Backquotes {
						raw := command[substitution.Left.Offset()+1 : substitution.Right.Offset()]
						if strings.HasSuffix(raw, "\\") {
							continue // "\`": bash 里替换没闭合
						}
						body = backquoteBody(raw)
					} else {
						body = command[substitution.Left.Offset()+2 : substitution.Right.Offset()]
					}
					substitutions++
					if !hand[body] {
						t.Errorf("substitution %q not found by commandSubstitutions in %q", body, raw)
					}
				}
			}
			return true
		})
	}
	if checked < 10000 || heredocs < 100 || substitutions < 100 {
		t.Fatalf("too little compared: %d inputs, %d heredocs, %d substitutions", checked, heredocs, substitutions)
	}
	t.Logf("%d inputs, %d heredocs, %d substitutions", checked, heredocs, substitutions)
}

// handWrittenHeredocs collects delimiter+"\x00"+body of every here-document
// the splitter finds in command and, recursively, in the substitutions of
// its words, redirections and expanding here-document bodies.
func handWrittenHeredocs(command string) map[string]bool {
	found := map[string]bool{}
	var collect func(text string, depth int)
	collect = func(text string, depth int) {
		if depth > maxShellNesting+2 {
			return
		}
		for _, simple := range splitShellSimpleCommands(text) {
			texts := append(append(append([]string(nil), simple.Words...), simple.InputRedirects...), simple.OutputRedirects...)
			for _, doc := range simple.Heredocs {
				found[doc.Delimiter+"\x00"+doc.Body] = true
				texts = append(texts, doc.Body)
			}
			for _, text := range texts {
				for _, body := range commandSubstitutions(text, nil) {
					collect(body, depth+1)
				}
			}
		}
	}
	collect(command, 0)
	return found
}

// astHeredocDelimiter is the delimiter of a here-document after quote
// removal; false for words with expansions.
func astHeredocDelimiter(word *syntax.Word) (string, bool) {
	var b strings.Builder
	var add func(parts []syntax.WordPart, quoted bool) bool
	add = func(parts []syntax.WordPart, quoted bool) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				b.WriteString(unescapePOSIXLiteral(part.Value, quoted))
			case *syntax.SglQuoted:
				if part.Dollar {
					for i := 0; i < len(part.Value); i++ {
						if part.Value[i] == '\\' && i+1 < len(part.Value) {
							decoded, width := decodeANSICEscape(part.Value[i+1:])
							b.WriteString(decoded)
							i += width
							continue
						}
						b.WriteByte(part.Value[i])
					}
				} else {
					b.WriteString(part.Value)
				}
			case *syntax.DblQuoted:
				if !add(part.Parts, true) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	ok := add(word.Parts, false)
	return b.String(), ok
}

// outermostSubstitutions returns the command substitutions of word that are
// not inside another one (nor inside a process substitution).
func outermostSubstitutions(word *syntax.Word) []*syntax.CmdSubst {
	var out []*syntax.CmdSubst
	syntax.Walk(word, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CmdSubst:
			out = append(out, node)
			return false
		case *syntax.ProcSubst:
			return false
		}
		return true
	})
	return out
}

// mvdanDiffersFromBash reports an input where mvdan reads a here-document
// differently from bash: a delimiter line ending in "\r", or bash 5.3's
// "EOF)" inside $(...).
func mvdanDiffersFromBash(file *syntax.File, command string) bool {
	differs := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok && (redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc) {
			if delim, ok := astHeredocDelimiter(redirect.Word); ok {
				differs = differs || strings.Contains(command, delim+"\r") || strings.Contains(command, delim+")")
			}
		}
		return !differs
	})
	return differs
}

// readHeredocDelimiter 由分词器与 substitutionSpanEnd 共用：后者原来不认 $'EOF'、$"EOF"，把定界符
// 当成 "$EOF"，正文里的 ")" 就把替换提前闭合了。
func TestHeredocDelimiterReadAlike2922(t *testing.T) {
	for word, want := range map[string]string{
		"EOF": "EOF", "'EOF'": "EOF", `"EOF"`: "EOF", `$'EOF'`: "EOF", `$"EOF"`: "EOF", `$'E\x4fF'`: "EOF",
		`E\OF`: "EOF", `'E'"O"F`: "EOF", "  EOF;": "EOF", `"E\"F"`: `E"F`, `"E\qF"`: `E\qF`,
	} {
		delim, _, _, ok := readHeredocDelimiter(word, 0)
		if !ok || delim != want {
			t.Errorf("%q: got %q %v, want %q", word, delim, ok, want)
		}
		for _, command := range []string{"cat <<" + word + "\nx\n" + want + "\n", "cat <<-" + word + "\n\tx\n\t" + want + "\n"} {
			commands := splitShellSimpleCommands(command)
			if len(commands) == 0 || len(commands[0].Heredocs) != 1 || commands[0].Heredocs[0].Delimiter != want || !commands[0].Heredocs[0].Terminated {
				t.Errorf("splitter on %q: %+v", command, commands)
			}
		}
	}
	for _, quoted := range []string{`$'EOF'`, `$"EOF"`} {
		text := "$(cat <<" + quoted + "\na)b\nEOF\n)"
		if end, ok := substitutionSpanEnd(text, 1, nil); !ok || end != len(text) {
			t.Errorf("%q: substitution ends at %d %v, want %d", text, end, ok, len(text))
		}
	}
}

// substitutionSpanEnd 认 $'…'（里面的 \' 不结束引号）和 case 的模式（模式后的 ")" 不闭合替换）：
// 这两类原来在 $(…) 里提前结束或一直不闭合，与 mvdan 的语法树对不上（探针里的写法）。
func TestSubstitutionSpanReadsANSIQuotesAndCasePatterns2922(t *testing.T) {
	for _, text := range []string{
		"$(echo $'\\'' ; cat ~/.ssh/id_rsa )",
		"$(case x in x) cat ~/.ssh/id_rsa;; esac)",
		"$(case x in (x|y) cat a;; z) cat b;& *) :;;& esac)",
		"$(case $(echo x) in x) echo $(cat c);; esac)",
	} {
		if end, ok := substitutionSpanEnd(text, 1, nil); !ok || end != len(text) {
			t.Errorf("%q: ends at %d %v, want %d", text, end, ok, len(text))
		}
		quoted := "\"" + text + "\""
		if bodies := commandSubstitutions(quoted, nil); len(bodies) != 1 || bodies[0] != text[2:len(text)-1] {
			t.Errorf("%q: substitutions %q", quoted, bodies)
		}
	}
}

// fuzz 找到的：$'\c' 里的 \c 后面是结束引号时，bash 保留 \c 两个字符（实测），不把引号当控制字符的
// 参数吞掉；原来手写分词把引号吞了，后面的文字都算进了引号里。
func TestANSICControlBeforeClosingQuote2922(t *testing.T) {
	for text, want := range map[string][]string{
		"echo $'\\c' x": {"echo", "\\c", "x"},
		"echo $'a\\cb'": {"echo", "a\x02"},
	} {
		if got := splitShellSimpleCommands(text); len(got) != 1 || fmt.Sprintf("%q", got[0].Words) != fmt.Sprintf("%q", want) {
			t.Errorf("%q: got %+v, want %q", text, got, want)
		}
	}
}
