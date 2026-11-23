package agentguard

import "testing"

func TestHardeningFMissingDestructiveCommandsMatchSignalVocabulary(t *testing.T) {
	for _, test := range []struct {
		command, subcategory string
		highConfidence       bool
	}{
		{"shred -u /srv/data/report.txt", "filesystem_delete", true},
		{"fdisk /dev/sda", "block_device_destroy", true},
		{"parted /dev/sda mklabel gpt", "block_device_destroy", true},
		{"diskpart /s erase.txt", "block_device_destroy", false},
		{"helm uninstall production-api", "cluster_destroy", true},
		{"pulumi destroy --yes", "infrastructure_destroy", true},
		{"docker compose down -v", "storage_destroy", true},
		{"git push --force origin main", "vcs_destroy", true},
	} {
		t.Run(test.command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell.execute", ToolType: "system", WorkingDirectory: "/srv/deploy/production", RepositoryRoot: "/srv/deploy/production", Arguments: map[string]any{"command": test.command}})
			if got.Category != destructiveCategory || got.Subcategory != test.subcategory || got.HighConfidence != test.highConfidence {
				t.Fatalf("destructive command and target completeness must be recognized: %+v", got)
			}
			if !test.highConfidence && got.Reason != "destructive_target_incomplete" {
				t.Fatalf("a script filename is not a verified disk target: %+v", got)
			}
			if !DestructiveSignalPresent(test.command) {
				t.Fatalf("parse-rejected signal vocabulary must align with analyzer for %q", test.command)
			}
		})
	}
}

func TestHardeningFDestructiveCommandTargetsAndInspectionVariants(t *testing.T) {
	for _, command := range []string{"git push --force origin main", "pulumi destroy --yes", "docker compose down -v"} {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell.execute", Arguments: map[string]any{"command": command}})
		if got.Category != destructiveCategory || got.HighConfidence || got.Reason != "destructive_target_incomplete" {
			t.Fatalf("missing runtime target must preserve incomplete-target semantics for %q: %+v", command, got)
		}
	}
	for _, command := range []string{"fdisk -l /dev/sda", "parted /dev/sda print", "helm list", "helm uninstall production-api --dry-run", "pulumi preview", "pulumi destroy --preview-only", "docker compose exec api echo down -v", "docker compose --dry-run down -v", "git push origin main"} {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell.execute", Arguments: map[string]any{"command": command}})
		if got.Category != "" {
			t.Fatalf("inspection or non-destructive variant must remain safe for %q: %+v", command, got)
		}
	}
	for _, command := range []string{"docker compose -p production down --volumes", "sudo docker compose down -v", "docker-compose down -v", "git push -f origin main"} {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell.execute", WorkingDirectory: "/srv/deploy/production", RepositoryRoot: "/srv/deploy/production", Arguments: map[string]any{"command": command}})
		if got.Category != destructiveCategory || !got.HighConfidence {
			t.Fatalf("supported executable option variant must be detected for %q: %+v", command, got)
		}
	}
}

func TestHardeningFAmbiguousToolNamesUseExecutionParameters(t *testing.T) {
	for _, name := range []string{"preview_delete_files", "list_destroy_resources", "file.delete_preview", "resources.delete.query"} {
		t.Run(name, func(t *testing.T) {
			for _, arguments := range []map[string]any{{"action": "delete", "path": "/srv/data"}, {"operation": "destroy", "target": "production-api"}, {"path": "/srv/data"}} {
				got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: name, Arguments: arguments})
				if got.Category != destructiveCategory || !got.HighConfidence {
					t.Fatalf("preview token cannot hide executable parameters: %+v", got)
				}
			}
			for _, arguments := range []map[string]any{{"action": "preview", "path": "/srv/data"}, {"action": "delete", "dry_run": true, "path": "/srv/data"}} {
				if got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: name, Arguments: arguments}); got.Category != "" {
					t.Fatalf("explicit nonexecution must remain safe: %+v", got)
				}
			}
		})
	}
}

func TestHardeningFMixedQueryToolNameWithoutPreviewParameter(t *testing.T) {
	got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "resources.delete.query", Arguments: map[string]any{"path": "/srv/data"}})
	if got.Category != destructiveCategory || !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
		t.Fatalf("a query word in the name cannot exempt a concrete deletion target without a nonexecution parameter: %+v", got)
	}
}
