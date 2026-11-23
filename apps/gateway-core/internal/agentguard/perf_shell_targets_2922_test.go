package agentguard

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"
)

// 敏感目标的 shell 判定（analyzeShellCommandTargets）单独计时（复审第八轮第 3 条）。整条 Bash 判定
// 的耗时见 handler 包的 TestBashJudgementLatency2922。用例清单见 testdata/shell_cases_2922.json。
// 报表：R2922_PERF=1 go test -run TestShellTargetScanLatency2922 ./internal/agentguard/

type shellTargetLatency struct {
	p50, p99, max time.Duration
	bytes, allocs uint64
	calls         int
}

func measureShellTargets(commands []string, rounds int) shellTargetLatency {
	for _, command := range commands {
		analyzeShellCommandTargets(command)
	}
	var durations []time.Duration
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for round := 0; round < rounds; round++ {
		for _, command := range commands {
			start := time.Now()
			analyzeShellCommandTargets(command)
			durations = append(durations, time.Since(start))
		}
	}
	runtime.ReadMemStats(&after)
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	at := func(q float64) time.Duration { return durations[int(q*float64(len(durations)-1))] }
	n := uint64(len(durations))
	return shellTargetLatency{p50: at(0.5), p99: at(0.99), max: durations[len(durations)-1],
		bytes: (after.TotalAlloc - before.TotalAlloc) / n, allocs: (after.Mallocs - before.Mallocs) / n, calls: len(durations)}
}

func TestShellTargetScanLatency2922(t *testing.T) {
	if os.Getenv("R2922_PERF") == "" {
		t.Skip("R2922_PERF not set")
	}
	print := func(name string, l shellTargetLatency) {
		fmt.Printf("SCAN\t%s\t%d\t%v\t%v\t%v\t%dKB\t%d\n", name, l.calls, l.p50.Round(time.Microsecond),
			l.p99.Round(time.Microsecond), l.max.Round(time.Microsecond), l.bytes>>10, l.allocs)
	}
	typical, pathological := loadShellCases2922(t)
	print("典型命令", measureShellTargets(typical, 200))
	for _, item := range pathological {
		print("病态："+item.name, measureShellTargets([]string{item.command}, 5))
	}
}

func BenchmarkShellTargetScan2922(b *testing.B) {
	typical, pathological := loadShellCases2922(b)
	b.Run("typical", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			analyzeShellCommandTargets(typical[i%len(typical)])
		}
	})
	for index, item := range pathological {
		command := item.command
		b.Run(fmt.Sprintf("pathological-%02d", index), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				analyzeShellCommandTargets(command)
			}
		})
	}
}
