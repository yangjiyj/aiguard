package agentguard

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// 手写分词与 mvdan 的词序列对照（代码质量复审重要项）：对 mvdan 能解析、只含简单命令（含 &&、||、
// 管道连起来的）、词里只有字面、单双引号、$'…' 的输入，逐条命令比对“去引号后的词序列”（前置赋值
// 写成 名=值）。mvdan 与 bash 读法不同的几类字符不比（见 requireSplitterWordsAgree）。两种来源：Go fuzz（种子是本包与 handler 包测试文件里的全部字符串字面量，普通
// go test 跑种子）；按语法随机拼出的命令行（固定随机数种子，2 万条）。

func FuzzSplitterWordsAgreeWithMvdan2922(f *testing.F) {
	for _, literal := range testStringLiterals(f, ".", "../handler") {
		f.Add(literal)
	}
	f.Fuzz(func(t *testing.T, text string) {
		requireSplitterWordsAgree(t, text)
	})
}

func TestSplitterWordsAgreeWithMvdanRandom2922(t *testing.T) {
	random := rand.New(rand.NewSource(2922))
	compared := 0
	for round := 0; round < 20000; round++ {
		if requireSplitterWordsAgree(t, randomSimpleCommandLine(random)) {
			compared++
		}
	}
	if compared < 10000 {
		t.Fatalf("only %d random lines were simple enough to compare", compared)
	}
}

// requireSplitterWordsAgree compares the word sequences and reports whether
// the input was simple enough to compare.
func requireSplitterWordsAgree(t *testing.T, text string) bool {
	t.Helper()
	// mvdan 把 "\r" 当空白、丢掉 NUL、在非法 UTF-8 与 C1 控制字符（U+0080–U+009F）上会吞掉后面的
	// 字符；bash 按字节读（手写分词照 bash），命令串里也不会有 NUL。这几种输入不比。
	if strings.ContainsAny(text, "\r\x00") || !utf8.ValidString(text) || strings.ContainsFunc(text, isC1Control) {
		return false
	}
	if (strings.Contains(text, "$'") || strings.Contains(text, "$\"")) && (strings.Contains(text, "'#") || strings.Contains(text, "\"#")) {
		return false // mvdan 把 $'…'、$"…" 后紧跟的 # 当注释；bash 里它接着同一个词（实测 echo $''#0 输出 #0）
	}
	if commentEndsWithBackslash(text) {
		return false // mvdan 把注释里行末的 \ 当续行；bash 的注释到换行为止（实测 echo x #\ 换行后是第二条命令）
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return false
	}
	want, ok := astSimpleCommandWords(file)
	if !ok || len(want) == 0 {
		return false
	}
	var got [][]string
	for _, simple := range splitShellSimpleCommands(text) {
		if len(simple.Heredocs) > 0 || len(simple.InputRedirects) > 0 || len(simple.OutputRedirects) > 0 {
			return false
		}
		got = append(got, simple.Words)
	}
	if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", want) {
		t.Errorf("%q: splitter %q, mvdan %q", text, got, want)
	}
	return true
}

// astSimpleCommandWords returns the unquoted words of every simple command of
// file, false when it holds anything else.
func astSimpleCommandWords(file *syntax.File) ([][]string, bool) {
	var out [][]string
	var command func(cmd syntax.Command) bool
	command = func(cmd syntax.Command) bool {
		switch cmd := cmd.(type) {
		case *syntax.CallExpr:
			var words []string
			for _, assign := range cmd.Assigns {
				if assign.Naked || assign.Append || assign.Index != nil || assign.Array != nil || assign.Name == nil {
					return false
				}
				value := ""
				if assign.Value != nil {
					var ok bool
					if value, ok = astUnquotedWord(assign.Value); !ok {
						return false
					}
				}
				words = append(words, assign.Name.Value+"="+value)
			}
			for _, arg := range cmd.Args {
				word, ok := astUnquotedWord(arg)
				if !ok {
					return false
				}
				words = append(words, word)
			}
			out = append(out, words)
			return true
		case *syntax.BinaryCmd:
			switch cmd.Op {
			case syntax.AndStmt, syntax.OrStmt, syntax.Pipe, syntax.PipeAll:
				return stmt(cmd.X, command) && stmt(cmd.Y, command)
			}
		}
		return false
	}
	for _, s := range file.Stmts {
		if !stmt(s, command) {
			return nil, false
		}
	}
	return out, true
}

func stmt(s *syntax.Stmt, command func(syntax.Command) bool) bool {
	return !s.Negated && !s.Coprocess && len(s.Redirs) == 0 && s.Cmd != nil && command(s.Cmd)
}

// astUnquotedWord is a word after quote removal, for words made of literals,
// single quotes ($'...' decoded) and double quotes holding only literals.
func astUnquotedWord(word *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			// Outside quotes a backslash escapes the next character; before a
			// newline it is a line continuation and both go away.
			for i := 0; i < len(part.Value); i++ {
				if part.Value[i] == '\\' && i+1 < len(part.Value) {
					i++
					if part.Value[i] == '\n' {
						continue
					}
				}
				b.WriteByte(part.Value[i])
			}
		case *syntax.SglQuoted:
			if !part.Dollar {
				b.WriteString(part.Value)
				continue
			}
			for i := 0; i < len(part.Value); i++ {
				if part.Value[i] == '\\' && i+1 < len(part.Value) {
					decoded, width := decodeANSICEscape(part.Value[i+1:])
					b.WriteString(decoded)
					i += width
					continue
				}
				b.WriteByte(part.Value[i])
			}
		case *syntax.DblQuoted:
			if part.Dollar {
				return "", false
			}
			for _, inner := range part.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(unescapePOSIXLiteral(lit.Value, true))
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// commentEndsWithBackslash reports a line holding a comment (a "#" at the
// start of a word) that ends with a backslash.
func commentEndsWithBackslash(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasSuffix(line, "\\") {
			continue
		}
		for i := 0; i < len(line); i++ {
			if line[i] == '#' && (i == 0 || strings.IndexByte(" \t;|&(", line[i-1]) >= 0) {
				return true
			}
		}
	}
	return false
}

// isC1Control reports U+0080..U+009F.
func isC1Control(r rune) bool { return r >= 0x80 && r <= 0x9f }

// randomSimpleCommandLine builds a command line of simple commands whose
// words mix plain text, escapes, line continuations, single quotes, double
// quotes and $'...', some commands followed by a "#" comment.
func randomSimpleCommandLine(random *rand.Rand) string {
	pick := func(set string) byte { return set[random.Intn(len(set))] }
	piece := func() string {
		var b strings.Builder
		switch random.Intn(7) {
		case 0, 1:
			for n := random.Intn(5) + 1; n > 0; n-- {
				b.WriteByte(pick("abcxyz019./_-~:=@%+,*?"))
			}
		case 6:
			// A line continuation outside quotes: both characters go away.
			b.WriteByte(pick("abc"))
			b.WriteString("\\\n")
			b.WriteByte(pick("xyz"))
		case 2:
			b.WriteByte('\\')
			b.WriteByte(pick("a $;|&'\"\\()<>#*"))
		case 3:
			b.WriteByte('\'')
			for n := random.Intn(5); n > 0; n-- {
				b.WriteByte(pick("ab $;|&\"\\()<>#`*\n"))
			}
			b.WriteByte('\'')
		case 4:
			b.WriteByte('"')
			for n := random.Intn(5); n > 0; n-- {
				switch random.Intn(4) {
				case 0:
					b.WriteByte('\\')
					b.WriteByte(pick("\"\\$`ab"))
				default:
					b.WriteByte(pick("ab ;|&'()<>#*\n"))
				}
			}
			b.WriteByte('"')
		case 5:
			b.WriteString("$'")
			for n := random.Intn(5); n > 0; n-- {
				switch random.Intn(3) {
				case 0:
					b.WriteByte('\\')
					b.WriteByte(pick("ntr\\'ab"))
				case 1:
					b.WriteString("\\x4")
					b.WriteByte(pick("1aF"))
				default:
					b.WriteByte(pick("ab ;|&\"()<>#*"))
				}
			}
			b.WriteByte('\'')
		}
		return b.String()
	}
	var line strings.Builder
	for commands := random.Intn(3) + 1; commands > 0; commands-- {
		for words := random.Intn(4) + 1; words > 0; words-- {
			for pieces := random.Intn(3) + 1; pieces > 0; pieces-- {
				line.WriteString(piece())
			}
			line.WriteByte(' ')
		}
		if random.Intn(4) == 0 {
			// A comment runs to the end of the line, so a newline follows it.
			line.WriteString("# ")
			for n := random.Intn(6); n > 0; n-- {
				line.WriteByte(pick("ab $;|&'\"()<>#`*\\"))
			}
			line.WriteByte('\n')
			continue
		}
		if commands > 1 {
			line.WriteString([]string{"; ", "&& ", "|| ", "| ", "& ", "\n"}[random.Intn(6)])
		}
	}
	return line.String()
}
