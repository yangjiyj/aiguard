package agentguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 复审第八轮收尾第 2 条：工作量上限只按确定的计数判定（语法节点、展开候选、证据字节），同一输入在
// 任何负载下结论相同。墙钟只作最后防线：做过的工作量超过 destructiveClockArmedWork 才看时间，
// 再过 maxDestructiveParseTime 仍未结束才算不可靠。

func withDestructiveClock(t *testing.T, clock func() time.Time) {
	t.Helper()
	saved := destructiveNow
	destructiveNow = clock
	t.Cleanup(func() { destructiveNow = saved })
}

// testStringLiterals returns every string literal of the *_test.go files in
// dirs: the commands of all tests, the corpus and the probes.
func testStringLiterals(t testing.TB, dirs ...string) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
		for _, file := range files {
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					if value, err := strconv.Unquote(literal.Value); err == nil && len(value) > 1 && !seen[value] {
						seen[value] = true
						out = append(out, value)
					}
				}
				return true
			})
		}
	}
	return out
}

// 正常输入一次也不看时钟：本包和 handler 包测试文件里的全部字符串字面量（各条测试的命令、语料）
// 逐条分析，时钟调用次数为 0，所以它们的结论与负载无关。
func TestDestructiveClockNotConsultedForNormalInputs2922(t *testing.T) {
	calls := 0
	withDestructiveClock(t, func() time.Time { calls++; return time.Now() })
	literals := testStringLiterals(t, ".", "../handler")
	if len(literals) < 10000 {
		t.Fatalf("only %d literals found", len(literals))
	}
	for _, command := range literals {
		AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}})
		if calls > 0 {
			t.Fatalf("the clock was consulted for a normal input (%d bytes): %.80q", len(command), command)
		}
	}
}

// 病态输入不靠时钟也标为不可靠：时钟停住（永不到期）或每看一次就过去一小时，结论相同。
func TestDestructiveBudgetIsDeterministic2922(t *testing.T) {
	commands := []string{
		"rm -rf " + strings.Repeat("{a,b}", 12000),
		strings.Repeat("$(echo ", 2000) + "x" + strings.Repeat(")", 2000),
		strings.Repeat("$(echo ", 600) + "x" + strings.Repeat(")", 600),
		"echo " + strings.Repeat("{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}{o,p} ", 600),
	}
	frozen := time.Now()
	for name, clock := range map[string]func() time.Time{
		"停住的时钟": func() time.Time { return frozen },
		"飞快的时钟": func() time.Time { frozen = frozen.Add(time.Hour); return frozen },
	} {
		withDestructiveClock(t, clock)
		for _, command := range commands {
			if analysis := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}}); !analysis.ParseRejected {
				t.Errorf("%s: %.40q… must be ParseRejected", name, command)
			}
		}
	}
	// 最后防线：工作量过了门槛才开始计时，计时开始后超过 maxDestructiveParseTime 才算不可靠。
	now := time.Now()
	withDestructiveClock(t, func() time.Time { return now })
	budget := newDestructiveParseBudget()
	if !budget.spend(destructiveClockArmedWork, 0) || !budget.deadline.IsZero() {
		t.Fatal("the clock must not be armed at the threshold")
	}
	if !budget.spend(1, 0) || budget.deadline.IsZero() {
		t.Fatal("the clock must be armed beyond the threshold")
	}
	now = now.Add(maxDestructiveParseTime - time.Millisecond)
	if !budget.spend(0, 0) {
		t.Fatal("not yet expired")
	}
	now = now.Add(2 * time.Millisecond)
	if budget.spend(0, 0) {
		t.Fatal("expired after the last-resort deadline")
	}
}

// “大量单词 64KB”：证据打印每次新建打印器（各带一个 4KB 缓冲），13000 个词单次分配六七十 MB。
// 同一次解析复用一个打印器。
func TestDestructiveManyWordsAllocation2922(t *testing.T) {
	command := "echo " + strings.Repeat("word ", 13000)
	input := DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}}
	AnalyzeDestructiveOperation(input)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	AnalyzeDestructiveOperation(input)
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 24<<20 {
		t.Fatalf("one analysis allocated %d MB", allocated>>20)
	}
}
