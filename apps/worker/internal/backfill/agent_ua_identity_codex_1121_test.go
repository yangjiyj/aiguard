package backfill

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 客户现场：codex-tui / codex_vscode 的历史行被内容兜底错判成 dify-coze（2511 行）。
// 升级后由 agent_ua_identity_v2（迁移 1011）按存储的 User-Agent / Originator 改正。
const (
	siteCodexTUIUA    = "codex-tui/0.155.0 (Windows 10.0.19045; x86_64) WindowsTerminal (codex-tui; 0.155.0)"
	siteCodexVSCodeUA = "codex_vscode/0.164.0-alpha.11.1 (Windows 10.0.19045; x86_64) unknown (VS Code; 26.1021.22027)"
	siteCodexExecUA   = "codex_exec/0.167.0-alpha.3.2 (Windows 10.0.19045; x86_64) unknown (codex_exec; 0.167.0-alpha.3.2)"
	siteCodexDeskUA   = "Codex Desktop/0.169.0-alpha.11.1 (Windows 10.0.19045; x86_64) unknown (Codex Desktop; 26.1111.21308)"
	siteCherryUA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) CherryStudio/1.9.6 Chrome/146.0.7680.188 Electron/41.2.1 Safari/537.36"
)

func TestAgentUAIdentityCodexV2FixesSiteRows(t *testing.T) {
	spec, ok := agentUAIdentitySpecFor(AgentUAIdentityCodexTask)
	if !ok {
		t.Fatal("agent_ua_identity_v2 must be a registered backfill task")
	}
	cases := []struct {
		name string
		row  agentUAIdentityRow
	}{
		{"codex-tui misjudged dify-coze by content", agentUAIdentityRow{UserAgent: siteCodexTUIUA, AgentType: "dify-coze", Source: "content"}},
		{"codex-tui misjudged via message_protocol", agentUAIdentityRow{UserAgent: siteCodexTUIUA, AgentType: "dify-coze", Source: "message_protocol"}},
		{"codex-tui with no product", agentUAIdentityRow{UserAgent: siteCodexTUIUA, AgentType: "", Source: "user_agent_runtime"}},
		{"codex-tui empty source", agentUAIdentityRow{UserAgent: siteCodexTUIUA, AgentType: "agent-tool-call", Source: ""}},
		{"codex_vscode taken as vscode runtime", agentUAIdentityRow{UserAgent: siteCodexVSCodeUA, AgentType: "vscode", Source: "user_agent_runtime"}},
		{"codex_vscode misjudged dify-coze", agentUAIdentityRow{UserAgent: siteCodexVSCodeUA, AgentType: "dify-coze", Source: "content"}},
		{"originator header only", agentUAIdentityRow{UserAgent: "node", Originator: "codex_vscode", AgentType: "dify-coze", Source: "content"}},
		{"originator Codex Desktop", agentUAIdentityRow{Originator: "Codex Desktop", AgentType: "trae", Source: "content"}},
	}
	for _, tc := range cases {
		detection, ok := detectAgentUAIdentity(tc.row, spec)
		if !ok || detection.Product != "openai-codex" || detection.Source != "user_agent" || detection.Confidence != 0.85 {
			t.Fatalf("%s: got ok=%v %+v, want openai-codex/user_agent/0.85", tc.name, ok, detection)
		}
	}
}

func TestAgentUAIdentityCodexV2LeavesOtherRowsAlone(t *testing.T) {
	spec, _ := agentUAIdentitySpecFor(AgentUAIdentityCodexTask)
	cases := []struct {
		name string
		row  agentUAIdentityRow
	}{
		// 来源只限 content / message_protocol / user_agent_runtime / 空
		{"client_header generic declared", agentUAIdentityRow{UserAgent: siteCodexTUIUA, DeclaredType: "main", AgentType: "main", Source: "client_header"}},
		{"client_header concrete", agentUAIdentityRow{UserAgent: siteCodexTUIUA, DeclaredType: "cursor", AgentType: "cursor", Source: "client_header"}},
		{"explicit_header", agentUAIdentityRow{UserAgent: siteCodexTUIUA, AgentType: "cursor", Source: "explicit_header"}},
		{"product_identity", agentUAIdentityRow{UserAgent: siteCodexTUIUA, AgentType: "workbuddy", Source: "product_identity"}},
		{"user_agent already", agentUAIdentityRow{UserAgent: siteCodexTUIUA, AgentType: "cursor", Source: "user_agent"}},
		// 已经是 Codex
		{"already codex", agentUAIdentityRow{UserAgent: siteCodexDeskUA, AgentType: "openai-codex", Source: "content"}},
		{"already codex exec", agentUAIdentityRow{UserAgent: siteCodexExecUA, AgentType: "openai-codex", Source: "user_agent_runtime"}},
		// 不是 Codex 的 UA
		{"node-fetch", agentUAIdentityRow{UserAgent: "node-fetch", AgentType: "dify-coze", Source: "content"}},
		{"cherry studio", agentUAIdentityRow{UserAgent: siteCherryUA, AgentType: "dify-coze", Source: "content"}},
		{"codex word in a different tool", agentUAIdentityRow{UserAgent: "mycodex_tool/1.0", AgentType: "dify-coze", Source: "content"}},
		{"originator not codex", agentUAIdentityRow{UserAgent: "node", Originator: "codexify", AgentType: "dify-coze", Source: "content"}},
		// v2 只改 Codex；别的产品的 UA 改正归 v1，不在这次回填里扩大范围
		{"workbuddy is v1 scope", agentUAIdentityRow{UserAgent: wbUA, AgentType: "openai-codex", Source: "message_protocol"}},
		{"deepseek is v1 scope", agentUAIdentityRow{UserAgent: ds1UA, AgentType: "dify-coze", Source: "content"}},
	}
	for _, tc := range cases {
		if detection, ok := detectAgentUAIdentity(tc.row, spec); ok {
			t.Fatalf("%s: must not be rewritten, got %+v", tc.name, detection)
		}
	}
}

// v1 已在现场跑完；拆成按任务的规格后行为不能变（client_header 通用声明仍可改、窗口 30 天、迁移号 991）。
func TestAgentUAIdentityV1SpecUnchanged(t *testing.T) {
	spec, ok := agentUAIdentitySpecFor(AgentUAIdentityTask)
	if !ok || spec.Migration != "991" || spec.WindowDays != 30 || !spec.AllowGenericClientHeader || spec.Products != nil {
		t.Fatalf("v1 spec changed: %+v", spec)
	}
	v2, _ := agentUAIdentitySpecFor(AgentUAIdentityCodexTask)
	if v2.Migration != "1011" || v2.AllowGenericClientHeader || !v2.Products["openai-codex"] || len(v2.Products) != 1 {
		t.Fatalf("v2 spec: %+v", v2)
	}
	if v2.WindowDays < 30 {
		t.Fatalf("v2 window %d must cover at least the 30-day v1 window", v2.WindowDays)
	}
}

func TestAgentUAIdentityCodexMigrationRegistersTask(t *testing.T) {
	spec, _ := agentUAIdentitySpecFor(AgentUAIdentityCodexTask)
	matches, _ := filepath.Glob("../../../../deploy/migrations/" + spec.Migration + "_*.sql")
	if len(matches) != 1 {
		t.Fatalf("want exactly one migration %s_*.sql, got %v", spec.Migration, matches)
	}
	body, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "'"+AgentUAIdentityCodexTask+"'") {
		t.Fatalf("%s does not register %s", matches[0], AgentUAIdentityCodexTask)
	}
}

// Codex 的 UA 特征只来自 agent-registry.json（经 agentdetect）；SQL 里不得再手写只认
// codex_exec / codex_cli 的正则，避免再次和网关识别漂移。
func TestCodexUserAgentSQLHasSingleSource(t *testing.T) {
	stale := regexp.MustCompile(`codex_\(exec\|cli\)|\^codex_exec|\^codex_cli`)
	for _, root := range []string{"../../../worker", "../../../control-plane", "../../../gateway-core", "../../../proxy-server"} {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr == nil && stale.Match(body) {
				t.Errorf("%s hard-codes a partial Codex User-Agent regex; use agentdetect.ProductPatterns", path)
			}
			return nil
		})
	}
	if strings.Contains(requestLogCompatibilityBatchSQL, "codex_") {
		t.Fatal("request_log_compatibility SQL must take Codex patterns as a parameter")
	}
}
