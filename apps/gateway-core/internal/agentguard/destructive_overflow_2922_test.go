package agentguard

import (
	"strings"
	"testing"
)

// 复审第八轮收尾第 1 条：破坏性分析只解析前 64KB，检查文本（SignalText）也截在 64KB，
// "echo <70KB>; rm -rf /" 被当成“解析不完整但没有破坏性信号”。超出部分（从跨过边界的那个词
// 开始）也做信号检测（与解析不完整时同一套词表，外加 isDestructiveCommand 的正则），有信号时
// 标 OverflowSignal，交给 handler 走 destructive_parse_rejected_fail_safe。
func TestDestructiveOverflowTailSignal2922(t *testing.T) {
	pad := strings.Repeat("a", 70<<10)
	// "rm" 跨过 64KB 边界：r 是第 65536 个字节，m 在边界之后。
	straddle := "echo " + strings.Repeat("a", 65528) + "; rm -rf /"
	for command, want := range map[string]bool{
		"echo " + pad + "; rm -rf /":           true,
		"echo " + pad + "\nrm -rf ~":           true,
		"echo " + pad + "\nmkfs.ext4 /dev/sdb": true,
		"echo " + pad + " > /etc/passwd":       true,
		straddle:                               true,
		"echo " + pad + "; ls -la":             false,
		"echo " + pad + "\ngit status":         false,
	} {
		analysis := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}})
		if !analysis.ParseRejected || analysis.OverflowSignal != want {
			t.Errorf("%q…%q: ParseRejected=%v OverflowSignal=%v, want overflow signal %v", command[:12], command[len(command)-12:], analysis.ParseRejected, analysis.OverflowSignal, want)
		}
	}
	argv := []any{"sh", "-c", "echo " + pad + "; rm -rf /"}
	if analysis := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": argv}}); !analysis.OverflowSignal {
		t.Errorf("argv form: OverflowSignal=%v", analysis.OverflowSignal)
	}
	if analysis := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": "rm -rf /"}}); analysis.OverflowSignal {
		t.Error("a command within the limit has no overflow")
	}
}
