package agentguard

import "testing"

func TestCodexMultipleCommandsCannotHideRiskBehindDiscardablePath(t *testing.T) {
	for _, script := range []string{
		`await tools.exec_command({cmd:"rm -rf /repo/app/dist"});await tools.exec_command({cmd:"rm -rf /repo/app/src"})`,
		`await tools.exec_command({cmd:"rm -rf /repo/app/src"});await tools.exec_command({cmd:"rm -rf /repo/app/dist"})`,
	} {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "exec", ToolType: "shell", WorkingDirectory: "/repo/app", RepositoryRoot: "/repo", Arguments: map[string]any{"input": script}})
		if !got.HighConfidence || got.DiscardablePathMatched {
			t.Fatalf("later real destruction must not inherit discardable downgrade: %+v", got)
		}
	}
}
