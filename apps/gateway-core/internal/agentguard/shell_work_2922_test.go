package agentguard

import (
	"runtime"
	"strings"
	"testing"
)

// 代码质量审查严重项：敏感目标 shell 扫描的工作量与输入长度成正比。不受环境变量门控、不用墙钟，只看
// 确定的工作量计数（shell_work.go）与分配量：每条病态输入的工作量（含超限后关掉前瞻重新分词、逐词判定的
// 部分）不超过 (shellWorkPerByte+8)×长度+shellWorkBase；典型命令和本包、handler 包测试文件里的全部字符串字面量
// （各条测试的命令、语料）都不触发逐词兜底，它们的结论与改前相同。
func TestShellTargetScanWorkIsLinear2922(t *testing.T) {
	typical, pathological := loadShellCases2922(t)
	for _, item := range pathological {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, _, work := analyzeShellCommandTargetsWork(item.command)
		runtime.ReadMemStats(&after)
		if bound := (shellWorkPerByte+8)*len(item.command) + shellWorkBase; work.spent > bound {
			t.Errorf("%s: work %d > %d (length %d)", item.name, work.spent, bound, len(item.command))
		}
		// 分配也与长度成正比：不超过每字节 2KB。
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2048*uint64(len(item.command)) {
			t.Errorf("%s: allocated %d MB for %d bytes", item.name, allocated>>20, len(item.command))
		}
	}
	for _, command := range append(typical, testStringLiterals(t, ".", "../handler")...) {
		if _, _, work := analyzeShellCommandTargetsWork(command); work.fellBack {
			t.Fatalf("a normal input fell back to word-by-word judgment: %.80q", command)
		}
	}
}

// 超限后整条逐词判定：末尾才闭合的 20000 个 "${" 后面接一个读取，读取照样被拦（偏严）；
// 前面的逐条解析找到的命中也保留。
func TestShellTargetScanFallbackStillJudgesWords2922(t *testing.T) {
	for _, command := range []string{
		"cat ~/.ssh/id_rsa; " + strings.Repeat("${", 20000) + "}",
		strings.Repeat("${", 20000) + "} ~/.ssh/id_rsa",
	} {
		decision, found, work := analyzeShellCommandTargetsWork(command)
		if !work.fellBack || !found || decision.Reason != targetReasonSSHPrivateKey {
			t.Errorf("%.20q…: fellBack=%v found=%v reason=%s", command, work.fellBack, found, decision.Reason)
		}
	}
}
