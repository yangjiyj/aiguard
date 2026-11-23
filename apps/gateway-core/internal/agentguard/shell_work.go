package agentguard

import "strings"

// 敏感目标 shell 扫描的工作量上限（代码质量审查严重项）：手写分词的前瞻扫描、逐词判定、写入比对在
// 病态输入上会退化（"${" 两万个、末尾才有一个 "}"）。扫描按确定的计数记工作量：解析过的行长、前瞻
// 扫描看过的字节、判定过的词长、记下的写入；超过 shellWorkPerByte×命令长度+shellWorkBase 就放弃逐条
// 解析，整条命令按 2.9.21 的方式逐词按读判定（词去重）。偏严、线性，同一输入在任何负载下结论相同。
const (
	shellWorkPerByte = 32
	shellWorkBase    = 1 << 16
)

// shellWork is the work meter of one shell analysis.
type shellWork struct {
	spent, limit int
	// fellBack: the limit was passed and the command was judged word by word.
	fellBack bool
	// noLookahead turns the splitter's lookahead scans off: $(, ${, $((, $[,
	// (( and `...` inside quotes are all taken as unclosed, so splitting is
	// linear (the fallback splits this way).
	noLookahead bool
}

// shellWorkLimitOverride, when not negative, replaces the limit (tests force
// the fallback with 0).
var shellWorkLimitOverride = -1

func newShellWork(command string) *shellWork {
	if shellWorkLimitOverride >= 0 {
		return &shellWork{limit: shellWorkLimitOverride}
	}
	return &shellWork{limit: shellWorkPerByte*len(command) + shellWorkBase}
}

// add counts n units and reports whether the meter is still within its
// limit. A nil meter never runs out.
func (w *shellWork) add(n int) bool {
	if w == nil {
		return true
	}
	w.spent += n
	return w.spent <= w.limit
}

func (w *shellWork) over() bool {
	return w != nil && w.spent > w.limit
}

// scanned charges a lookahead scan from open: up to its end when it
// closed, to the end of the text when it did not. Only the outermost scan
// charges: the nested scans it makes cover bytes inside its own span.
func (w *shellWork) scanned(text string, open, end int, closed bool) {
	if !closed {
		end = len(text)
	}
	if end > open {
		w.add(end - open)
	}
}

// overflowWordSeparators end a word for the word-by-word judgments.
const overflowWordSeparators = " \t\n\r;&|()<>`'\""

// overflowTailStart returns where the part of text beyond the parse limit
// (maxDestructiveCommandBytes) starts: at the word that crosses the limit.
// The sensitive-target scan and the destructive analysis judge from there.
func overflowTailStart(text string) int {
	if len(text) <= maxDestructiveCommandBytes {
		return len(text)
	}
	return strings.LastIndexAny(text[:maxDestructiveCommandBytes], overflowWordSeparators) + 1
}
