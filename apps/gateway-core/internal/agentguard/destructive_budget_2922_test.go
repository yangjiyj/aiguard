package agentguard

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// 破坏性命令分析的三处热点（复审第八轮追加）：花括号/引号片段的乘积、证据逐层重新打印、
// 没有工作量上限。正常输入的结果不变，只允许病态输入从“跑很久”变成“不可靠”。

// oldBoundedStringProduct 是改前的乘积写法，用来对照新写法的结果。
func oldBoundedStringProduct(left, right []string, limit int) ([]string, bool) {
	if len(left) == 0 || len(right) == 0 {
		return nil, false
	}
	exceeded := len(left) > limit/len(right)
	values := make([]string, 0, min(len(left)*len(right), limit))
	for _, prefix := range left {
		for _, suffix := range right {
			if len(values) >= limit {
				return values, true
			}
			values = append(values, prefix+suffix)
		}
	}
	return values, exceeded
}

// 第 1 处：共享前缀的乘积和逐步拼字符串的乘积，值、顺序、是否超出逐一相同。
func TestPOSIXProductSharesPrefixes2922(t *testing.T) {
	random := rand.New(rand.NewSource(2922))
	for round := 0; round < 3000; round++ {
		limit := []int{1, 2, 3, 7, 256}[random.Intn(5)]
		oldValues, oldExceeded := []string{""}, false
		newValues, newExceeded := []*posixProductValue{nil}, false
		for part := random.Intn(12); part >= 0; part-- {
			alternatives := make([]string, random.Intn(5))
			for index := range alternatives {
				alternatives[index] = fmt.Sprintf("p%d.%d", part, index)
			}
			var exceeded bool
			oldValues, exceeded = oldBoundedStringProduct(oldValues, alternatives, limit)
			oldExceeded = oldExceeded || exceeded
			newValues, exceeded = boundedValueProduct(newValues, alternatives, limit)
			newExceeded = newExceeded || exceeded
		}
		got := materializeProductValues(newValues)
		if fmt.Sprint(got) != fmt.Sprint(oldValues) || (got == nil) != (oldValues == nil) || newExceeded != oldExceeded {
			t.Fatalf("round %d limit %d: got %q/%v, want %q/%v", round, limit, got, newExceeded, oldValues, oldExceeded)
		}
	}
}

// 第 1 处：12000 个花括号的词展开不再随长度平方增长（改前单个词要几秒、分配几十 GB）。
func TestPOSIXBraceProductIsLinear2922(t *testing.T) {
	// 只看分配量，不看墙钟：4000 个 {a,b} 的词展开到 256 个值，共享前缀约分配四十几 MB；改前每步把
	// 已有的值整串复制，约 2GB。
	file, err := syntax.NewParser().Parse(strings.NewReader("echo "+strings.Repeat("{a,b}", 4000)), "")
	if err != nil {
		t.Fatal(err)
	}
	word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	values, exceeded, ok := literalPOSIXFields(word, maxDestructiveTargets, nil)
	runtime.ReadMemStats(&after)
	if !ok || !exceeded || len(values) != maxDestructiveTargets {
		t.Fatalf("got %d values exceeded=%v ok=%v", len(values), exceeded, ok)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 128<<20 {
		t.Fatalf("expanding 4000 brace groups allocated %d MB", allocated>>20)
	}
}

// 第 2 处：证据里很长的节点按源码截取，不再逐层重新打印；短节点照旧用打印器（结果不变）。
func TestPOSIXEvidenceCutsLongNodesFromSource2922(t *testing.T) {
	short := "rm -rf \"$( echo  build )\""
	segments := ParsedEvidenceSegments(DestructiveInput{ToolName: "Bash", Arguments: map[string]any{"command": short}})
	if len(segments) == 0 || segments[0].Words[2].Text != "\"$(echo build)\"" {
		t.Fatalf("short node must still be printed: %+v", segments)
	}
	inner := strings.Repeat("x", maxPrintedNodeBytes)
	long := "rm -rf \"$( echo  " + inner + " )\""
	segments = ParsedEvidenceSegments(DestructiveInput{ToolName: "Bash", Arguments: map[string]any{"command": long}})
	if len(segments) == 0 || segments[0].Words[2].Text != "\"$( echo  "+inner+" )\"" {
		t.Fatalf("long node must be cut from the source")
	}
	// 2000 层嵌套：外层节点都超过 8KB，按源码截取，打印器只印几 KB（改前逐层重印，几十 MB）。
	deep := strings.Repeat("$(echo ", 2000) + "x" + strings.Repeat(")", 2000)
	budget := newDestructiveParseBudget()
	parsePOSIXScript(deep, 0, budget, nil)
	if budget.printed > 16<<10 {
		t.Fatalf("2000 nested $() printed %d bytes", budget.printed)
	}
}

// 第 3 处：解析节点数、展开候选数、打印字节数、耗时任一超出上限，解析标为不可靠，走现有
// ParseRejected 路径（由 agent.parse_rejected 处置），不会静默放行。
func TestDestructiveWorkBudgetMarksUnreliable2922(t *testing.T) {
	for name, command := range map[string]string{
		"12000 个花括号":  "rm -rf " + strings.Repeat("{a,b}", 12000),
		"2000 层 $()":  strings.Repeat("$(echo ", 2000) + "x" + strings.Repeat(")", 2000),
		"600 层 $()":   strings.Repeat("$(echo ", 600) + "x" + strings.Repeat(")", 600),
		"5000 个短花括号词": "echo " + strings.Repeat("{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}{o,p} ", 600),
	} {
		analysis := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}})
		if !analysis.ParseRejected {
			t.Errorf("%s: want ParseRejected, got %+v", name, analysis)
		}
		// 工作量有上限：各项计数的上限之和加上与长度成正比的花括号拆分，不看墙钟。
		budget := newDestructiveParseBudget()
		parsePOSIXScript(command, 0, budget, nil)
		if bound := 2*len(command) + maxDestructiveCandidates + maxDestructiveSyntaxNodes + maxDestructivePrintedBytes/64 + 1024; budget.work() > bound {
			t.Errorf("%s: work %d > %d", name, budget.work(), bound)
		}
	}
}

// 同一次解析里，同一个词的花括号拆分只做一次（取命令词、写证据、找嵌套脚本都要展开它）；
// 预算用完以后不再拆分和展开（12000 个花括号的词，SplitBraces 本身就要十几毫秒）。
func TestLiteralFieldsReuseSplitAndStopWhenExhausted2922(t *testing.T) {
	file, err := syntax.NewParser().Parse(strings.NewReader("echo {a,b}{c,d}x"), "")
	if err != nil {
		t.Fatal(err)
	}
	word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
	budget := newDestructiveParseBudget()
	first, _, ok := literalPOSIXFields(word, maxDestructiveTargets, budget)
	if !ok || fmt.Sprint(first) != "[acx adx bcx bdx]" {
		t.Fatalf("got %v %v", first, ok)
	}
	parts := budget.splitParts(word)
	if again := budget.splitParts(word); &again[0] != &parts[0] {
		t.Fatal("the brace split of a word must be reused within one parse")
	}
	if second, _, _ := literalPOSIXFields(word, maxDestructiveTargets, budget); fmt.Sprint(second) != fmt.Sprint(first) {
		t.Fatalf("reused split must give the same fields: %v", second)
	}
	budget.exhausted = true
	if values, exceeded, ok := literalPOSIXFields(word, maxDestructiveTargets, budget); values != nil || !exceeded || ok {
		t.Fatalf("an exhausted budget must stop expanding: %v %v %v", values, exceeded, ok)
	}
}

// mvdan 的 SplitBraces 在大量 "{" 上是平方级（64000 个 "{" 单条要 31GB、16 秒）。一个词里的 "{" 超过
// maxDestructiveBraceOpens 时不再拆分，解析标为不可靠；只看计数与分配，不看墙钟。
func TestDestructiveBraceSplitIsBounded2922(t *testing.T) {
	for _, command := range []string{"cat " + strings.Repeat("{", 64000), "cat " + strings.Repeat("{", 64000) + "}"} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		analysis := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}})
		runtime.ReadMemStats(&after)
		if !analysis.ParseRejected {
			t.Errorf("%d bytes of braces: want ParseRejected", len(command))
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
			t.Errorf("%d bytes of braces: allocated %d MB", len(command), allocated>>20)
		}
	}
}
