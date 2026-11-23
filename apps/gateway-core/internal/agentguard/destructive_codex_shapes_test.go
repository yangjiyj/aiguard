package agentguard

import (
	"encoding/json"
	"testing"
)

func TestAnalyzeDestructiveOperation_CodexShapes(t *testing.T) {
	js := func(cmd string) string {
		b, _ := json.Marshal(cmd)
		return "const r = await tools.exec_command({cmd:" + string(b) + ",workdir:\"/w\"})"
	}
	direct := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "exec", ToolType: "shell", Arguments: map[string]any{"command": "rm -rf /tmp/x"}})
	for _, tt := range []struct {
		name        string
		args        map[string]any
		destructive bool
	}{
		{"js_pwd", map[string]any{"input": js("pwd")}, false},
		{"js_rm", map[string]any{"input": js("rm -rf /tmp/x")}, true},
		{"js_pdf", map[string]any{"input": js("pdftotext 合同.pdf -")}, false},
		{"command_argv", map[string]any{"command": []any{"bash", "-lc", "rm -rf /tmp/x"}}, true},
		{"write_stdin", map[string]any{"input": `const s = await tools.write_stdin({session_id:1, chars:""})`}, false},
		{"js_without_command", map[string]any{"input": `const s = await tools.read_resource({uri:"local"})`}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "exec", ToolType: "shell", Arguments: tt.args})
			if got.ParseRejected {
				t.Errorf("unexpected ParseRejected: %+v", got)
			}
			if tt.destructive {
				if got.Category == "" || got.Subcategory != direct.Subcategory {
					t.Errorf("got %s/%s want %s/%s", got.Category, got.Subcategory, direct.Category, direct.Subcategory)
				}
			} else if got.Category != "" || (got.Reason != "command_not_deterministically_destructive" && got.Reason != "no_deterministic_destructive_operation") {
				t.Errorf("unexpected non-destructive result: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperation_CodexMultipleCommands(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		rejected    bool
		category    string
	}{
		{"strongest", `await tools.exec_command({cmd:"pwd"}); await tools.exec_command({cmd:"rm -rf /tmp/x"}); await tools.exec_command({cmd:"pwd"})`, false, "filesystem_delete"},
		{"parse_failure_last", `await tools.exec_command({cmd:"rm -rf /tmp/x"}); await tools.exec_command({cmd:"echo '"})`, true, "filesystem_delete"},
		{"parse_failure_first", `await tools.exec_command({cmd:"echo '"}); await tools.exec_command({cmd:"rm -rf /tmp/x"})`, true, "filesystem_delete"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "exec", ToolType: "shell", Arguments: map[string]any{"input": tt.input}})
			if got.ParseRejected != tt.rejected || got.Subcategory != tt.category {
				t.Fatalf("unexpected analysis: %+v", got)
			}
		})
	}
}
