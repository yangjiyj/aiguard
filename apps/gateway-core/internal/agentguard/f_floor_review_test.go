package agentguard

import "testing"

func TestFReviewRequestedCommandsWithStandardCLIOptions(t *testing.T) {
	for _, command := range []string{
		"git -C /srv/deploy/production push --force origin main",
		"helm --namespace production uninstall production-api",
		"pulumi --cwd /srv/deploy/production destroy --yes",
		"docker --host unix:///var/run/docker.sock compose down -v",
		"git push -fu origin main",
		"docker compose down -vt0",
	} {
		t.Run(command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell.execute", ToolType: "system", WorkingDirectory: "/srv/deploy/production", RepositoryRoot: "/srv/deploy/production", Arguments: map[string]any{"command": command}})
			if got.Category != destructiveCategory {
				t.Fatalf("executable requested command escaped destructive analysis: %+v", got)
			}
		})
	}
}
