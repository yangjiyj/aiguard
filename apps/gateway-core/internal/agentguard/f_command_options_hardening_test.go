package agentguard

import "testing"

func TestFCommandOptionParsingKeepsExecutionAndOptionValuesDistinct(t *testing.T) {
	for _, tc := range []struct {
		command     string
		destructive bool
	}{
		{"git -C /srv/deploy/production push --force origin main", true},
		{"git -C/srv/deploy/production push -uf origin main", true},
		{"git push --force -o --dry-run origin main", true},
		{"git push -o --force origin main", false},
		{"git push --force --dry-run origin main", false},
		{"git push -fnu origin main", false},
		{"helm --namespace production uninstall production-api", true},
		{"helm --namespace uninstall list", false},
		{"helm --namespace production uninstall production-api --dry-run", false},
		{"pulumi --cwd /srv/deploy/production destroy --yes", true},
		{"pulumi --cwd destroy preview", false},
		{"pulumi --cwd /srv/deploy/production destroy --preview-only", false},
		{"docker --host unix:///var/run/docker.sock compose down -vt0", true},
		{"docker --host compose info", false},
		{"docker --host unix:///var/run/docker.sock compose down -vt0 --dry-run", false},
		{"docker compose down --volumes=false", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell.execute", ToolType: "system", WorkingDirectory: "/srv/deploy/production", RepositoryRoot: "/srv/deploy/production", Arguments: map[string]any{"command": tc.command}})
			if (got.Category == destructiveCategory) != tc.destructive {
				t.Fatalf("destructive=%v want=%v: %+v", got.Category == destructiveCategory, tc.destructive, got)
			}
		})
	}
}
