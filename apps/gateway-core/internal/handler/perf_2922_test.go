package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// Bash 判定耗时（复审第八轮第 3 条）：典型命令、语料、病态输入各测一遍。
// 报表：R2922_PERF=1 go test -run TestBashJudgementLatency2922 ./internal/handler/
// 基准：go test -run '^$' -bench BenchmarkBashJudgement2922 -benchmem ./internal/handler/

// 典型命令与病态输入的清单与 agentguard 包共用：../agentguard/testdata/shell_cases_2922.json。
type r2922ShellCaseFile struct {
	Typical      []string `json:"typical"`
	Pathological []struct {
		Name  string `json:"name"`
		Parts []struct {
			Text    string `json:"text"`
			Repeat  int    `json:"repeat"`
			Indexed bool   `json:"indexed"`
		} `json:"parts"`
	} `json:"pathological"`
}

func loadR2922ShellCases(tb testing.TB) ([]string, [][2]string) {
	tb.Helper()
	raw, err := os.ReadFile("../agentguard/testdata/shell_cases_2922.json")
	if err != nil {
		tb.Fatal(err)
	}
	var file r2922ShellCaseFile
	if err := json.Unmarshal(raw, &file); err != nil {
		tb.Fatal(err)
	}
	var pathological [][2]string
	for _, item := range file.Pathological {
		var b strings.Builder
		for _, part := range item.Parts {
			for i := 0; i < max(part.Repeat, 1); i++ {
				if part.Indexed {
					fmt.Fprintf(&b, part.Text, i)
				} else {
					b.WriteString(part.Text)
				}
			}
		}
		pathological = append(pathological, [2]string{item.Name, b.String()})
	}
	return file.Typical, pathological
}

type r2922Latency struct {
	name                string
	calls               int
	p50, p99, max       time.Duration
	bytesPerCall, perOp uint64
}

func measureR2922(name string, cases []r2922Case, rounds int) r2922Latency {
	policy := r2922BlockAllPolicy()
	for _, c := range cases { // 预热
		r2922Evaluate(c, policy)
	}
	var durations []time.Duration
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for round := 0; round < rounds; round++ {
		for _, c := range cases {
			start := time.Now()
			r2922Evaluate(c, policy)
			durations = append(durations, time.Since(start))
		}
	}
	runtime.ReadMemStats(&after)
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	at := func(q float64) time.Duration { return durations[int(q*float64(len(durations)-1))] }
	n := uint64(len(durations))
	return r2922Latency{name: name, calls: len(durations), p50: at(0.50), p99: at(0.99), max: durations[len(durations)-1],
		bytesPerCall: (after.TotalAlloc - before.TotalAlloc) / n, perOp: (after.Mallocs - before.Mallocs) / n}
}

func r2922TypicalCases(tb testing.TB) []r2922Case {
	typical, _ := loadR2922ShellCases(tb)
	var out []r2922Case
	for i, command := range typical {
		out = append(out, r2922Bash(fmt.Sprintf("t%02d", i), r2922B, command))
	}
	return out
}

func r2922CorpusCases() []r2922Case {
	var out []r2922Case
	for _, c := range r2922Corpus() {
		if c.Group != r2922X {
			out = append(out, c)
		}
	}
	return out
}

func TestBashJudgementLatency2922(t *testing.T) {
	if os.Getenv("R2922_PERF") == "" {
		t.Skip("R2922_PERF not set")
	}
	rows := []r2922Latency{
		measureR2922("典型命令", r2922TypicalCases(t), 50),
		measureR2922("语料", r2922CorpusCases(), 10),
	}
	_, pathological := loadR2922ShellCases(t)
	for _, p := range pathological {
		rows = append(rows, measureR2922("病态："+p[0], []r2922Case{r2922Bash("p", r2922M, p[1])}, 5))
	}
	for _, row := range rows {
		fmt.Printf("PERF\t%s\t%d\t%v\t%v\t%v\t%dKB\t%d\n", row.name, row.calls,
			row.p50.Round(time.Microsecond), row.p99.Round(time.Microsecond), row.max.Round(time.Microsecond),
			row.bytesPerCall>>10, row.perOp)
	}
}

func BenchmarkBashJudgement2922(b *testing.B) {
	policy := r2922BlockAllPolicy()
	run := func(name string, cases []r2922Case) {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r2922Evaluate(cases[i%len(cases)], policy)
			}
		})
	}
	run("typical", r2922TypicalCases(b))
	run("corpus", r2922CorpusCases())
	_, pathological := loadR2922ShellCases(b)
	for index, p := range pathological {
		run(fmt.Sprintf("pathological-%02d", index), []r2922Case{r2922Bash("p", r2922M, p[1])})
	}
}

// 复审第八轮追加：病态输入在解析阶段超出工作量上限，标为不可靠，走现有的 ParseRejected 路径
// （原因 destructive_parse_rejected_fail_safe，文字里没有破坏性信号时记为
// destructive_parse_incomplete_no_signal），不会静默放行；默认口径不拦。工作量上限本身由
// agentguard 包按计数验证（TestDestructiveWorkBudgetMarksUnreliable2922），这里不看墙钟。
func TestPathologicalBashTakesParseRejectedPath2922(t *testing.T) {
	for name, command := range map[string]string{
		"rm 加 12000 个花括号": "rm -rf " + strings.Repeat("{a,b}", 12000),
		"12000 个花括号":      "echo " + strings.Repeat("{a,b}", 12000),
		"2000 层 $()":      strings.Repeat("$(echo ", 2000) + "x" + strings.Repeat(")", 2000),
	} {
		c := r2922Bash("p", r2922M, command)
		decision, _ := r2922Evaluate(c, r2922Policy(true))
		if !strings.Contains(decision.EffectiveReason+";"+decision.ReasonSummary, "destructive_parse") {
			t.Errorf("%s: want the parse-rejected path, got %s/%s/%s", name, decision.EffectiveDecision, decision.EffectiveReason, decision.ReasonSummary)
		}
		if r2922Blocked(decision) {
			t.Errorf("%s: default config must not block, got %s/%s", name, decision.EffectiveDecision, decision.EffectiveReason)
		}
	}
}

// 复审第八轮收尾第 1 条：64KB 之后才出现的破坏性命令，整条判定走 destructive_parse_rejected_fail_safe，
// 不再被记成“解析不完整但没有破坏性信号”；尾部没有信号的照旧。
func TestOversizeTailDestructiveSignalFailSafe2922(t *testing.T) {
	strict := &agentguard.EffectivePolicy{ID: "r2922-strict", Mode: agentguard.ModeStrict, DefaultAction: agentguard.DecisionAllow, RuleMode: agentguard.ModeStrict}
	pad := strings.Repeat("a", 70<<10)
	for command, want := range map[string]string{
		"echo " + pad + "; rm -rf /": "destructive_parse_rejected_fail_safe",
		"echo " + pad + "\nrm -rf ~": "destructive_parse_rejected_fail_safe",
		"echo " + pad + "; ls -la":   "destructive_parse_incomplete_no_signal",
	} {
		decision, _ := r2922Evaluate(r2922Bash("t", r2922X, command), strict)
		if got := decision.EffectiveReason + ";" + decision.ReasonSummary; !strings.Contains(got, want) {
			t.Errorf("%q: want %s, got %s/%s", command[len(command)-10:], want, decision.EffectiveDecision, got)
		}
	}
}
