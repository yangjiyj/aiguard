package alert

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const (
	consoleAlertReadable         = "../../../../apps/web-console/src/utils/alertReadable.ts"
	consoleWS8ActionLabels       = "../../../../apps/web-console/src/utils/ws8ActionLabels.ts"
	consoleSecurityExecutionMode = "../../../../apps/web-console/src/services/securityExecutionMode.ts"
)

var (
	consoleActionConst     = regexp.MustCompile(`(?m)^const ([A-Z_]+) = '([^']*)'$`)
	consoleActionEntry     = regexp.MustCompile(`([a-z_]+)\s*:\s*([A-Za-z_]+|'[^']*')`)
	consoleRecordPassLabel = regexp.MustCompile("(?m)^export const RECORD_MODE_PASS_LABEL = `\\$\\{securityModeLabel\\('record'\\)\\}([^`$]*)`$")
	consoleRecordModeLabel = regexp.MustCompile(`mode === 'record' \? '([^']*)'`)
)

// consoleRecordModePassLabel 按前端的拼法得出观察留痕模式下的放行叫法：ws8ActionLabels.ts 的
// RECORD_MODE_PASS_LABEL = `${securityModeLabel('record')}放行`，模式名取 securityExecutionMode.ts
// 的 securityModeLabel('record')。两处任一处改了叫法，比对都会跟着变。
func consoleRecordModePassLabel(t *testing.T) string {
	t.Helper()
	ws8, err := os.ReadFile(consoleWS8ActionLabels)
	if err != nil {
		t.Fatalf("read console ws8ActionLabels.ts: %v", err)
	}
	suffix := consoleRecordPassLabel.FindStringSubmatch(string(ws8))
	if suffix == nil {
		t.Fatal("the console no longer builds RECORD_MODE_PASS_LABEL from securityModeLabel('record')")
	}
	mode, err := os.ReadFile(consoleSecurityExecutionMode)
	if err != nil {
		t.Fatalf("read console securityExecutionMode.ts: %v", err)
	}
	name := consoleRecordModeLabel.FindStringSubmatch(string(mode))
	if name == nil || name[1] == "" {
		t.Fatal("the console no longer names the record mode in securityModeLabel")
	}
	return name[1] + suffix[1]
}

// 处置名两端一致：控制面标题与外部通知用 actionLabelsCN，控制台用 ACTION_RESULTS，
// 同一个处置值必须是同一个叫法。读前端文件逐键比对，任何一端漂移都会失败。
func TestActionLabelsMatchTheConsoleActionResults(t *testing.T) {
	raw, err := os.ReadFile(consoleAlertReadable)
	if err != nil {
		t.Fatalf("read console alertReadable.ts: %v", err)
	}
	source := string(raw)
	consts := map[string]string{"RECORD_MODE_PASS_LABEL": consoleRecordModePassLabel(t)}
	for _, m := range consoleActionConst.FindAllStringSubmatch(source, -1) {
		consts[m[1]] = m[2]
	}
	const decl = "const ACTION_RESULTS: Record<string, string> = {"
	start := strings.Index(source, decl)
	if start < 0 {
		t.Fatal("the console no longer declares ACTION_RESULTS where this test looks")
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatal("unterminated ACTION_RESULTS in the console")
	}
	entries := consoleActionEntry.FindAllStringSubmatch(source[start+len(decl):start+end], -1)
	if len(entries) < 30 {
		t.Fatalf("only %d action labels parsed; the console map changed shape", len(entries))
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		key, value := entry[1], entry[2]
		label := strings.Trim(value, "'")
		if !strings.HasPrefix(value, "'") {
			var ok bool
			if label, ok = consts[value]; !ok {
				t.Fatalf("console action %s uses unknown constant %s", key, value)
			}
		}
		seen[key] = true
		got, ok := actionLabelsCN[key]
		if !ok {
			t.Errorf("console labels action %s=%q but the control plane has no entry", key, label)
			continue
		}
		if got != label {
			t.Errorf("action label drift for %s: console=%q control-plane=%q", key, label, got)
		}
		if actionLabelCN(key) != label {
			t.Errorf("actionLabelCN(%q)=%q want %q", key, actionLabelCN(key), label)
		}
	}
	for key := range actionLabelsCN {
		if !seen[key] {
			t.Errorf("the control plane labels action %s, which the console does not", key)
		}
	}
}

// 网关 mcp_proxy_audit.go 实际写入 security_events.action_taken 的 MCP 处置值都要有中文叫法。
func TestMCPGatewayActionsAreLabelled(t *testing.T) {
	for key, want := range map[string]string{
		"mcp_tools_list_alerted": "告警放行", "mcp_tools_list_filtered": "已过滤工具列表",
		"mcp_tool_result_alerted": "告警放行", "mcp_tool_result_blocked": "已阻断",
		"mcp_server_request_blocked": "已阻断", "mcp_server_request_alerted": "告警放行",
		"quarantine": "已隔离", "blocked": "已阻断", "agentguard_policy_load_failed": "策略加载失败",
	} {
		if got := actionLabelCN(key); got != want {
			t.Errorf("actionLabelCN(%q)=%q want %q", key, got, want)
		}
	}
}

func TestSeverityLabelsCoverWarningInfoAndNeverLeakEnglish(t *testing.T) {
	for in, want := range map[string]string{
		"warning": "提醒", "info": "提示", "WARNING": "提醒", "": "未知", "unknown": "未知", "catastrophic": "未知",
	} {
		if got := severityLabelCN(in); got != want {
			t.Errorf("severityLabelCN(%q)=%q want %q", in, got, want)
		}
	}
}
