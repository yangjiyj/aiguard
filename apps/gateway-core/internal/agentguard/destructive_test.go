package agentguard

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeDestructiveOperationDeterministic(t *testing.T) {
	tests := []struct{ name, tool, field, value, want string }{
		{"linux rm", "shell", "command", "rm -rf /srv/data", "filesystem_delete"},
		{"nested sh lc", "shell", "command", "sh -lc 'rm -rf /tmp/jjdguard-loop-victim'", "filesystem_delete"},
		{"docker exec shell delete", "shell_command", "command", "docker exec jjdguard-loop-sandbox-a6b09bcb sh -lc 'rm -rf /tmp/jjdguard-loop-victim'", "filesystem_delete"},
		{"linux truncate", "shell", "command", "truncate -s 0 /var/log/app.log", "filesystem_overwrite"},
		{"linux overwrite", "shell", "command", "printf x > /etc/app.conf", "filesystem_overwrite"},
		{"powershell remove", "powershell", "command", "Remove-Item -Recurse -Force C:\\data\\archive", "filesystem_delete"},
		{"powershell clear content", "powershell", "command", "Clear-Content C:\\data\\important.txt", "filesystem_overwrite"},
		{"powershell format volume", "powershell", "command", "Format-Volume -DriveLetter D", "storage_destroy"},
		{"powershell clear disk", "powershell", "command", "Clear-Disk -Number 2 -RemoveData", "storage_destroy"},
		{"powershell partition", "powershell", "command", "Remove-Partition -DriveLetter D", "storage_destroy"},
		{"windows del", "cmd", "command", "del /s /q C:\\data\\*", "filesystem_delete"},
		{"windows rmdir", "cmd", "command", "rmdir /s /q C:\\data", "filesystem_delete"},
		{"windows format", "cmd", "command", "format D: /Q", "storage_destroy"},
		{"sql drop", "database.query", "query", "DROP TABLE customers", "database_destroy"},
		{"sql truncate", "database.query", "query", "TRUNCATE TABLE audit_log", "database_destroy"},
		{"sql delete no where", "database.query", "query", "DELETE FROM sessions", "database_unscoped_mutation"},
		{"sql update no where", "database.query", "query", "UPDATE accounts SET active=false", "database_unscoped_mutation"},
		{"docker rm", "shell", "command", "docker rm -f prod-api", "container_destroy"},
		{"docker volume", "shell", "command", "docker volume rm prod-data", "storage_destroy"},
		{"kubectl", "shell", "command", "kubectl delete namespace production", "cluster_destroy"},
		{"mkfs", "shell", "command", "mkfs.ext4 /dev/sdb1", "block_device_destroy"},
		{"wipefs", "shell", "command", "wipefs -a /dev/sdb", "block_device_destroy"},
		{"dd", "shell", "command", "dd if=/dev/zero of=/dev/sdb bs=1M", "block_device_destroy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: tt.tool, Arguments: map[string]any{tt.field: tt.value}})
			assertDestructive(t, got, tt.want)
		})
	}
}

func TestAnalyzeDestructiveOperationRiskLevelTracksImpact(t *testing.T) {
	tests := []struct {
		name, command, want string
	}{
		// 客户A 11-21：只删临时目录下的路径降为中危（处置仍按策略），普通数据目录仍是高危。
		{"workspace cleanup", "sudo rm -rf /tmp/build-cache", "medium"},
		{"data directory", "sudo rm -rf /srv/data", "high"},
		{"root filesystem", "sudo rm -rf /", "critical"},
		{"block device", "sudo mkfs.ext4 /dev/sdb1", "critical"},
		{"database destroy", "DROP DATABASE production", "critical"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": tt.command}}
			if tt.name == "database destroy" {
				input = DestructiveInput{ToolName: "database.query", Arguments: map[string]any{"query": tt.command}}
			}
			got := AnalyzeDestructiveOperation(input)
			if got.RiskLevel != tt.want {
				t.Fatalf("risk level=%q want %q: %+v", got.RiskLevel, tt.want, got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationPowerShellStorageOptions(t *testing.T) {
	incomplete := []string{
		"Format-Volume -FileSystem NTFS",
		"Clear-Disk -PartitionStyle GPT",
	}
	for _, command := range incomplete {
		t.Run("incomplete/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "powershell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("non-target option value must not become a target: %+v", got)
			}
		})
	}

	explicit := []string{
		"Format-Volume -FileSystem NTFS -DriveLetter D",
		"Clear-Disk -PartitionStyle GPT -RemoveData -DiskNumber 2",
	}
	for _, command := range explicit {
		t.Run("explicit/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "powershell", Arguments: map[string]any{"command": command}})
			assertDestructive(t, got, "storage_destroy")
		})
	}
}

func TestAnalyzeDestructiveOperationPowerShellFileOptions(t *testing.T) {
	incomplete := []string{
		"Remove-Item -Filter foo",
		"Clear-Content -Include bar",
		"Remove-Item -Exclude old -Stream data",
	}
	for _, command := range incomplete {
		t.Run("incomplete/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "powershell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("non-target option value must not become a path: %+v", got)
			}
		})
	}

	explicit := []struct {
		command, subcategory string
	}{
		{"Remove-Item -Filter foo -Path C:\\data\\old.txt", "filesystem_delete"},
		{"Clear-Content -Include bar -LiteralPath C:\\data\\important.txt", "filesystem_overwrite"},
		{"Remove-Item C:\\data\\old.txt -Exclude archived", "filesystem_delete"},
	}
	for _, tt := range explicit {
		t.Run("explicit/"+tt.command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "powershell", Arguments: map[string]any{"command": tt.command}})
			assertDestructive(t, got, tt.subcategory)
		})
	}
}
func TestAnalyzeDestructiveOperationConservativeStorageOptions(t *testing.T) {
	incomplete := []string{
		"mkfs -d /tmp/rootfs",
		"mkfs -M /mnt",
		"wipefs --output TYPE",
	}
	for _, command := range incomplete {
		t.Run("incomplete/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("option value must not become a storage target: %+v", got)
			}
		})
	}

	explicit := []string{
		"mkfs -F /dev/sda",
		"mkfs --type=ext4 /dev/sdb",
		"wipefs -a /dev/sdc",
		"wipefs --types=ext4 /dev/sdd",
	}
	for _, command := range explicit {
		t.Run("explicit/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			assertDestructive(t, got, "block_device_destroy")
		})
	}
}

func TestAnalyzeDestructiveOperationStorageCommandTargets(t *testing.T) {
	explicit := []struct {
		command, want string
	}{
		{"mkfs -L DATA -t ext4 /dev/sdb1", "block_device_destroy"},
		{"wipefs -L DATA -t ext4 -a /dev/sdb", "block_device_destroy"},
		{"FORMAT D: /FS:NTFS", "storage_destroy"},
		{"format \\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\ /FS:NTFS", "storage_destroy"},
	}
	for _, tt := range explicit {
		t.Run("explicit/"+tt.command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": tt.command}})
			assertDestructive(t, got, tt.want)
		})
	}

	incomplete := []string{
		"mkfs -L DATA -t ext4",
		"wipefs -L DATA -t ext4 -a",
		"format /FS:NTFS",
	}
	for _, command := range incomplete {
		t.Run("incomplete/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("storage command without a real target must audit: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationContextTargets(t *testing.T) {
	commands := []string{
		"git reset --hard HEAD~1",
		"git clean -fdx",
		"terraform destroy -auto-approve",
		"docker system prune -af",
	}
	for _, command := range commands {
		t.Run("missing/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("implicit pseudo target must not gate: %+v", got)
			}
		})
	}

	explicit := []struct {
		name, subcategory string
		input             DestructiveInput
	}{
		{"git reset", "vcs_destroy", DestructiveInput{ToolName: "shell", WorkingDirectory: "/repo/app", RepositoryRoot: "/repo", Arguments: map[string]any{"command": "git reset --hard HEAD~1"}}},
		{"git clean", "vcs_destroy", DestructiveInput{ToolName: "shell", WorkingDirectory: "C:\\repo\\app", RepositoryRoot: "C:\\repo", Arguments: map[string]any{"command": "git clean -fdx"}}},
		{"terraform", "infrastructure_destroy", DestructiveInput{ToolName: "shell", WorkingDirectory: "/repo/infra", RepositoryRoot: "/repo", Arguments: map[string]any{"command": "terraform destroy -auto-approve"}}},
		{"terraform target", "infrastructure_destroy", DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": "terraform destroy -auto-approve", "target": "module.api"}}},
		{"docker context", "container_destroy", DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": "docker system prune -af", "context": "production-daemon"}}},
	}
	for _, tt := range explicit {
		t.Run("explicit/"+tt.name, func(t *testing.T) {
			assertDestructive(t, AnalyzeDestructiveOperation(tt.input), tt.subcategory)
		})
	}
}

func TestAnalyzeDestructiveOperationShellLexerAndArgvBoundaries(t *testing.T) {
	benign := []DestructiveInput{
		{ToolName: "shell", Arguments: map[string]any{"command": `echo "a > b"`}},
		{ToolName: "shell", Arguments: map[string]any{"command": "echo 'a > b'"}},
		{ToolName: "shell", Arguments: map[string]any{"command": `echo a \> b`}},
		{ToolName: "exec", Arguments: map[string]any{"argv": []any{"echo", ">", "/tmp/not-a-redirection"}}},
		{ToolName: "exec", Arguments: map[string]any{"argv": []any{"echo", "a > b"}}},
	}
	for index, input := range benign {
		got := AnalyzeDestructiveOperation(input)
		if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
			t.Fatalf("quoted/argv case %d must not become shell syntax: %+v", index, got)
		}
	}

	for _, command := range []string{": > ./output", "cat input > ./output"} {
		t.Run("redirect/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			assertDestructive(t, got, "filesystem_overwrite")
		})
	}

	argvDelete := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName: "exec", Arguments: map[string]any{"argv": []any{"rm", "-rf", "/srv/data", "--dry-run"}},
	})
	if !argvDelete.HighConfidence || argvDelete.TargetSummary != "filesystem_delete:1-targets" {
		t.Fatalf("argv atoms must preserve rm target and must not infer kubectl dry-run semantics: %+v", argvDelete)
	}
}

func TestAnalyzeDestructiveOperationPOSIXSyntaxTree(t *testing.T) {
	destructive := []DestructiveInput{
		{ToolName: "shell", Arguments: map[string]any{"command": `echo "$(rm -rf /srv/data)"`}},
		{ToolName: "shell", Arguments: map[string]any{"command": "echo `rm -rf /srv/data`"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "(rm -rf /srv/data)"}},
		{ToolName: "shell", Arguments: map[string]any{"command": `bash -c 'rm -rf /srv/data'`}},
		{ToolName: "exec", Arguments: map[string]any{"argv": []any{"bash", "-c", "rm -rf /srv/data"}}},
		{ToolName: "shell", Arguments: map[string]any{"command": `r\m -rf /srv/data`}},
	}
	for index, input := range destructive {
		got := AnalyzeDestructiveOperation(input)
		if !got.HighConfidence || got.Subcategory != "filesystem_delete" {
			t.Fatalf("POSIX AST destructive case %d must be detected: %+v", index, got)
		}
	}

	benign := []DestructiveInput{
		{ToolName: "shell", Arguments: map[string]any{"command": `echo 'rm -rf /srv/data'`}},
		{ToolName: "shell", Arguments: map[string]any{"command": `echo "a > b"`}},
		{ToolName: "powershell", Arguments: map[string]any{"command": `echo "$(rm -rf /srv/data)"`}},
		{ToolName: "cmd", Arguments: map[string]any{"command": "(rm -rf /srv/data)"}},
	}
	for index, input := range benign {
		got := AnalyzeDestructiveOperation(input)
		if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
			t.Fatalf("non-executing or non-POSIX case %d must not gate: %+v", index, got)
		}
	}

	parseError := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": "rm -rf /srv/data && ("}})
	if parseError.HighConfidence || parseError.Confidence != "medium" || parseError.SuggestedAction != DecisionAudit || !parseError.ParseRejected {
		t.Fatalf("POSIX syntax error without a reliable AST must reject at medium confidence: %+v", parseError)
	}

	for name, command := range map[string]string{
		"input limit":  "rm -rf /srv/data #" + strings.Repeat("x", 70<<10),
		"target limit": "echo x " + strings.Repeat("> ./output ", 300),
	} {
		t.Run(name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			if !got.HighConfidence || got.SuggestedAction != DecisionConfirm || !got.ParseRejected {
				t.Fatalf("budget rejection must preserve confirmed POSIX finding: %+v", got)
			}
			if got.DiscardablePathMatched {
				t.Fatalf("budget rejection must block discardable downgrade: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationDynamicPOSIXTargetBlocksDiscardableDowngrade(t *testing.T) {
	input := DestructiveInput{
		ToolName:         "shell",
		WorkingDirectory: "/repo/app",
		RepositoryRoot:   "/repo",
		Arguments: map[string]any{
			"command": `rm -rf /repo/app/dist "$TARGET"`,
		},
	}
	got := AnalyzeDestructiveOperation(input)
	if !got.HighConfidence || got.Subcategory != "filesystem_delete" {
		t.Fatalf("destructive command with dynamic target must remain high confidence: %+v", got)
	}
	if got.DiscardablePathMatched {
		t.Fatalf("dynamic target must block discardable-path downgrade: %+v", got)
	}

	input.Arguments["command"] = `echo "$(rm -rf /repo/app/dist)"`
	got = AnalyzeDestructiveOperation(input)
	if got.HighConfidence || got.Subcategory != "filesystem_delete" || !got.DiscardablePathMatched {
		t.Fatalf("fully parsed command substitution must retain its discardable-path analysis: %+v", got)
	}
}

func TestAnalyzeDestructiveOperationBraceExpansionIsBounded(t *testing.T) {
	if os.Getenv("AGENTGUARD_BRACE_BUDGET_HELPER") == "1" {
		command := "rm -rf /tmp/" + strings.Repeat("{a,b}", 14)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "shell",
			Arguments: map[string]any{"command": command},
		})
		if !got.HighConfidence || got.TargetSummary != "filesystem_delete:256-targets" {
			t.Fatalf("over-budget brace finding must stay bounded and destructive: %+v", got)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", `ulimit -v 2097152; exec "$1" -test.run=^TestAnalyzeDestructiveOperationBraceExpansionIsBounded$`, "brace-budget", os.Args[0])
	cmd.Env = append(os.Environ(), "AGENTGUARD_BRACE_BUDGET_HELPER=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			t.Fatalf("brace expansion exceeded bounded runtime: %v", ctx.Err())
		}
		t.Fatalf("brace expansion helper failed: %v\n%s", err, output)
	}
}

func TestAnalyzeDestructiveOperationBoundedBraceTargets(t *testing.T) {
	got := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName:  "shell",
		Arguments: map[string]any{"command": "rm -rf /{etc,var}"},
	})
	if !got.HighConfidence || got.Subcategory != "filesystem_delete" {
		t.Fatalf("bounded brace targets must remain deterministic: %+v", got)
	}
	if got.TargetSummary != "filesystem_delete:2-targets" {
		t.Fatalf("brace targets must be expanded exactly once: %+v", got)
	}
}

func TestAnalyzeDestructiveOperationBudgetPreservesConfirmedFinding(t *testing.T) {
	t.Run("truncated incomplete statement after sensitive target", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "shell",
			Arguments: map[string]any{"command": "rm -rf /etc; printf '" + strings.Repeat("x", maxDestructiveCommandBytes)},
		})
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
			t.Fatalf("complete statement must survive a truncated incomplete suffix: %+v", got)
		}
		if got.TargetSummary != "filesystem_delete:1-targets" || got.DiscardablePathMatched {
			t.Fatalf("incomplete suffix must not alter the confirmed target: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("quoted and commented separators before truncated suffix", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName: "shell",
			Arguments: map[string]any{
				"command": "printf ';'; # ignored ;\nrm -rf /etc; printf '" + strings.Repeat("x", maxDestructiveCommandBytes),
			},
		})
		if !got.HighConfidence || got.TargetSummary != "filesystem_delete:1-targets" {
			t.Fatalf("parser-defined statement boundaries must preserve the complete delete: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("complete nested script before truncated suffix", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName: "shell",
			Arguments: map[string]any{
				"command": "sh -c 'rm -rf /etc'; printf '" + strings.Repeat("x", maxDestructiveCommandBytes),
			},
		})
		if !got.HighConfidence || got.TargetSummary != "filesystem_delete:1-targets" {
			t.Fatalf("complete nested statement must survive the incomplete suffix: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("incomplete nested statement is never inferred", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName: "shell",
			Arguments: map[string]any{
				"command": "printf '%s' \"$(rm -rf /etc); printf '" + strings.Repeat("x", maxDestructiveCommandBytes),
			},
		})
		if got.HighConfidence || got.SuggestedAction != DecisionAudit {
			t.Fatalf("incomplete nested statement must not become a confirmed command: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("oversized command after sensitive target", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "shell",
			Arguments: map[string]any{"command": "rm -rf /etc #" + strings.Repeat("x", maxDestructiveCommandBytes)},
		})
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
			t.Fatalf("confirmed sensitive target must survive input budget rejection: %+v", got)
		}
		if got.TargetSummary != "filesystem_delete:1-targets" || got.DiscardablePathMatched {
			t.Fatalf("confirmed target summary must stay bounded without downgrade: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("syntax node overflow after sensitive target", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "shell",
			Arguments: map[string]any{"command": "rm -rf /etc;" + strings.Repeat("echo x;", maxDestructiveSyntaxNodes)},
		})
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
			t.Fatalf("confirmed sensitive target must survive syntax node rejection: %+v", got)
		}
		if got.TargetSummary != "filesystem_delete:1-targets" || got.DiscardablePathMatched {
			t.Fatalf("syntax node rejection must retain bounded target without downgrade: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("structured target overflow", func(t *testing.T) {
		targets := make([]string, maxDestructiveTargets+1)
		for index := range targets {
			targets[index] = "/etc/target-" + strconv.Itoa(index)
		}
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName: "resource_manager",
			Arguments: map[string]any{
				"action":  "delete",
				"path":    "/etc/passwd",
				"targets": targets,
			},
		})
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
			t.Fatalf("confirmed structured target must survive target budget rejection: %+v", got)
		}
		if got.TargetSummary != "filesystem_delete:256-targets" || got.DiscardablePathMatched {
			t.Fatalf("structured overflow summary must remain bounded without downgrade: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("brace target overflow", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "shell",
			Arguments: map[string]any{"command": "rm -rf /tmp/" + strings.Repeat("{a,b}", 9)},
		})
		if !got.HighConfidence || got.TargetSummary != "filesystem_delete:256-targets" {
			t.Fatalf("confirmed brace targets must survive expansion budget rejection: %+v", got)
		}
		assertParseRejected(t, got)
	})
}

func TestAnalyzeDestructiveOperationBudgetRejectsWithoutFinding(t *testing.T) {
	got := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName:  "shell",
		Arguments: map[string]any{"command": "echo ok #" + strings.Repeat("x", maxDestructiveCommandBytes)},
	})
	if got.HighConfidence || got.SuggestedAction != DecisionAudit {
		t.Fatalf("budget rejection without finding must remain non-gating analysis: %+v", got)
	}
	assertParseRejected(t, got)
}

func TestAnalyzeDestructiveOperationDynamicRedirectRejectsDowngrade(t *testing.T) {
	got := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName:         "shell",
		WorkingDirectory: "/repo/app",
		RepositoryRoot:   "/repo",
		Arguments: map[string]any{
			"command": `rm -rf /repo/app/dist > "$TARGET"`,
		},
	})
	if !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
		t.Fatalf("confirmed delete must survive an unresolved redirect: %+v", got)
	}
	if got.DiscardablePathMatched {
		t.Fatalf("unresolved redirect must block composite discardable downgrade: %+v", got)
	}
	assertParseRejected(t, got)
}

func TestAnalyzeDestructiveOperationUnifiedDialectBudgets(t *testing.T) {
	commands := []DestructiveInput{
		{ToolName: "powershell", Arguments: map[string]any{"command": `Remove-Item C:\Windows\System32; Write-Output ` + strings.Repeat("x", maxDestructiveCommandBytes)}},
		{ToolName: "cmd", Arguments: map[string]any{"command": `del C:\Windows\System32 & echo ` + strings.Repeat("x", maxDestructiveCommandBytes)}},
		{ToolName: "powershell", Arguments: map[string]any{"command": `Remove-Item C:\Windows\System32; Write-Output ` + strings.Repeat("x ", maxDestructiveSyntaxNodes+1)}},
		{ToolName: "cmd", Arguments: map[string]any{"command": `del C:\Windows\System32 & echo ` + strings.Repeat("x ", maxDestructiveSyntaxNodes+1)}},
	}
	for index, input := range commands {
		got := AnalyzeDestructiveOperation(input)
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
			t.Fatalf("dialect budget case %d must preserve confirmed finding: %+v", index, got)
		}
		if got.DiscardablePathMatched || got.TargetSummary != "filesystem_delete:1-targets" {
			t.Fatalf("dialect budget case %d must keep bounded sensitive summary: %+v", index, got)
		}
		assertParseRejected(t, got)
		for _, evidence := range got.Evidence {
			if evidence.Length > maxDestructiveCommandBytes {
				t.Fatalf("dialect budget case %d evidence exceeded byte budget: %+v", index, evidence)
			}
		}
	}

	withoutFinding := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName:  "powershell",
		Arguments: map[string]any{"command": "Write-Output " + strings.Repeat("x", maxDestructiveCommandBytes)},
	})
	if withoutFinding.HighConfidence || withoutFinding.SuggestedAction != DecisionAudit {
		t.Fatalf("legacy budget without finding must remain non-gating: %+v", withoutFinding)
	}
	assertParseRejected(t, withoutFinding)

	posixArgv := []any{"bash", "-c", "rm -rf /etc #" + strings.Repeat("x", maxDestructiveCommandBytes)}
	posix := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName:  "exec",
		Arguments: map[string]any{"argv": posixArgv},
	})
	if !posix.HighConfidence || posix.TargetSummary != "filesystem_delete:1-targets" {
		t.Fatalf("POSIX argv byte budget must preserve confirmed nested finding: %+v", posix)
	}
	assertParseRejected(t, posix)

	powershellArgv := make([]any, 0, maxDestructiveSyntaxNodes+3)
	powershellArgv = append(powershellArgv, "Remove-Item", `C:\Windows\System32`)
	for index := 0; index <= maxDestructiveSyntaxNodes; index++ {
		powershellArgv = append(powershellArgv, "-Verbose")
	}
	powershell := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName:  "powershell",
		Arguments: map[string]any{"argv": powershellArgv},
	})
	if !powershell.HighConfidence || powershell.TargetSummary != "filesystem_delete:1-targets" {
		t.Fatalf("PowerShell argv token budget must preserve confirmed finding: %+v", powershell)
	}
	assertParseRejected(t, powershell)
}

func TestAnalyzeDestructiveOperationSQLBudgets(t *testing.T) {
	t.Run("oversized comment preserves confirmed drop", func(t *testing.T) {
		query := "DROP TABLE customers; /*" + strings.Repeat("x", maxDestructiveCommandBytes)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": query},
		})
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm || got.TargetSummary != "database_destroy:1-targets" {
			t.Fatalf("confirmed DROP must survive SQL input rejection: %+v", got)
		}
		assertParseRejected(t, got)
		assertBoundedDestructiveEvidence(t, got, query, maxDestructiveCommandBytes)
	})

	t.Run("unknown oversized query audits", func(t *testing.T) {
		query := "SELECT " + strings.Repeat("x", maxDestructiveCommandBytes)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": query},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("unknown oversized SQL must remain audit-only: %+v", got)
		}
		assertParseRejected(t, got)
		assertBoundedDestructiveEvidence(t, got, query, maxDestructiveCommandBytes)
	})

	t.Run("oversized quoted drop stays data", func(t *testing.T) {
		query := "SELECT 'DROP TABLE hidden " + strings.Repeat("x", maxDestructiveCommandBytes)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": query},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("DROP inside a truncated quote must remain data: %+v", got)
		}
		assertParseRejected(t, got)
		assertBoundedDestructiveEvidence(t, got, query, maxDestructiveCommandBytes)
	})

	t.Run("oversized commented drop stays comment", func(t *testing.T) {
		query := "SELECT 1; -- DROP TABLE hidden " + strings.Repeat("x", maxDestructiveCommandBytes)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": query},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("DROP inside a truncated comment must remain non-executable: %+v", got)
		}
		assertParseRejected(t, got)
		assertBoundedDestructiveEvidence(t, got, query, maxDestructiveCommandBytes)
	})
	t.Run("token overflow preserves confirmed drop", func(t *testing.T) {
		query := "DROP TABLE customers;" + strings.Repeat("x ", maxDestructiveSyntaxNodes+1)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": query},
		})
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
			t.Fatalf("confirmed DROP must survive SQL token rejection: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("same statement token overflow preserves confirmed drop", func(t *testing.T) {
		query := "DROP TABLE customers " + strings.Repeat("x ", maxDestructiveSyntaxNodes)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": query},
		})
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm || got.TargetSummary != "database_destroy:1-targets" {
			t.Fatalf("bounded leading tokens must preserve the confirmed DROP: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("unknown token overflow audits", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": strings.Repeat("x ", maxDestructiveSyntaxNodes+1)},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("unknown SQL token overflow must remain audit-only: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("statement overflow audits", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": strings.Repeat("SELECT 1;", maxDestructiveTargets+1)},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("SQL statement overflow must remain audit-only: %+v", got)
		}
		assertParseRejected(t, got)
	})
}

func TestAnalyzeDestructiveOperationSQLNonMonotonicBudgets(t *testing.T) {
	budgetRejected := []struct {
		name  string
		query string
	}{
		{"delete where after token budget", "DELETE FROM sessions " + strings.Repeat("x ", maxDestructiveSyntaxNodes) + " WHERE id = 1"},
		{"delete where after byte budget", "DELETE FROM sessions " + strings.Repeat("x", maxDestructiveCommandBytes) + " WHERE id = 1"},
		{"update where after token budget", "UPDATE accounts SET active false " + strings.Repeat("x ", maxDestructiveSyntaxNodes) + " WHERE id = 1"},
		{"delete before statement overflow", "DELETE FROM sessions;" + strings.Repeat("SELECT 1;", maxDestructiveTargets)},
	}
	for _, tt := range budgetRejected {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:  "database.query",
				Arguments: map[string]any{"query": tt.query},
			})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("non-monotonic SQL finding must audit after budget rejection: %+v", got)
			}
			assertParseRejected(t, got)
		})
	}

	for _, query := range []string{
		"DELETE FROM sessions",
		"UPDATE accounts SET active = false",
	} {
		t.Run("complete no where/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:  "database.query",
				Arguments: map[string]any{"query": query},
			})
			if !got.HighConfidence || got.SuggestedAction != DecisionConfirm || got.ParseRejected {
				t.Fatalf("complete unscoped mutation must remain deterministic: %+v", got)
			}
		})
	}
}

func assertBoundedDestructiveEvidence(t *testing.T, got DestructiveAnalysis, raw string, limit int) {
	t.Helper()
	if len(got.Evidence) == 0 {
		t.Fatalf("budget rejection must retain bounded evidence: %+v", got)
	}
	if len(raw) > limit {
		raw = raw[:limit]
	}
	want := sanitizedEvidence("", "", "", raw)
	for _, evidence := range got.Evidence {
		if evidence.Length > limit {
			t.Fatalf("evidence length %d exceeded limit %d: %+v", evidence.Length, limit, evidence)
		}
		if evidence.Length != want.Length || evidence.MaskedPreview != want.MaskedPreview || evidence.Hash != want.Hash {
			t.Fatalf("evidence must derive only from the bounded SQL prefix: got %+v want %+v", evidence, want)
		}
	}
}

func TestAnalyzeDestructiveOperationCompositeCommandTargets(t *testing.T) {
	tests := []struct {
		name, command, wantSummary string
	}{
		{"mixed segments", "rm -rf /repo/app/dist && rm -rf /etc", "filesystem_delete:2-targets"},
		{"delete and redirect", "rm -rf /repo/app/dist > /etc/important.conf", "filesystem_delete:2-targets"},
		{"multiple redirects", "echo x > /repo/app/dist/output > /etc/important.conf", "filesystem_overwrite:2-targets"},
		{"two discardable directories", "rm -rf /repo/app/dist && rm -rf /repo/app/build", "filesystem_delete:2-targets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:         "shell",
				WorkingDirectory: "/repo/app", RepositoryRoot: "/repo",
				Arguments: map[string]any{"command": tt.command},
			})
			if !got.HighConfidence {
				t.Fatalf("composite destructive command must remain high confidence: %+v", got)
			}
			if got.DiscardablePathMatched {
				t.Fatalf("multi-target composite command must not be downgraded: %+v", got)
			}
			if got.TargetSummary != tt.wantSummary {
				t.Fatalf("summary=%q want %q: %+v", got.TargetSummary, tt.wantSummary, got)
			}
		})

	}
}
func TestAnalyzeDestructiveOperationSimulationFlagsBindToCommand(t *testing.T) {
	executing := []DestructiveInput{
		{ToolName: "shell", Arguments: map[string]any{"command": "rm -rf /srv/data; echo --dry-run"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "echo --dry-run; rm -rf /srv/data"}},
		{ToolName: "shell", Arguments: map[string]any{"action": "list", "command": "rm -rf /srv/data"}},
		{ToolName: "shell", Arguments: map[string]any{"simulate": true, "command": "rm -rf /srv/data"}},
	}
	for index, input := range executing {
		got := AnalyzeDestructiveOperation(input)
		if !got.HighConfidence {
			t.Fatalf("conflicting or unrelated simulation case %d must preserve destructive command: %+v", index, got)
		}
	}

	simulated := []DestructiveInput{
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-run=client"}},
		{ToolName: "powershell", Arguments: map[string]any{"command": "Remove-Item C:\\data\\old.txt -WhatIf"}},
	}
	for index, input := range simulated {
		got := AnalyzeDestructiveOperation(input)
		if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
			t.Fatalf("same-command simulation case %d must audit: %+v", index, got)
		}
	}
}

func TestAnalyzeDestructiveOperationCommandSimulationFlags(t *testing.T) {
	simulated := []DestructiveInput{
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-run=client"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-run"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-run server"}},
		{ToolName: "powershell", Arguments: map[string]any{"command": "Remove-Item C:\\data\\old.txt -WhatIf"}},
		{ToolName: "powershell", Arguments: map[string]any{"command": "Format-Volume -DriveLetter D -wHaTiF"}},
		{ToolName: "exec", Arguments: map[string]any{"argv": []any{"kubectl", "delete", "pod", "api", "--dry-run=server"}}},
		{ToolName: "exec", Arguments: map[string]any{"argv": []any{"kubectl", "delete", "pod", "api", "--dry-run", "client"}}},
	}
	for index, input := range simulated {
		got := AnalyzeDestructiveOperation(input)
		if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
			t.Fatalf("simulation case %d must not gate: %+v", index, got)
		}
	}

	executing := []DestructiveInput{
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api"}},
		{ToolName: "powershell", Arguments: map[string]any{"command": "Remove-Item C:\\data\\old.txt"}},
		{ToolName: "powershell", Arguments: map[string]any{"command": "Format-Volume -DriveLetter D"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-runner"}},
		{ToolName: "powershell", Arguments: map[string]any{"command": "Remove-Item C:\\data\\old.txt -WhatIfElse"}},
	}
	for index, input := range executing {
		got := AnalyzeDestructiveOperation(input)
		if !got.HighConfidence {
			t.Fatalf("executing case %d must remain high confidence: %+v", index, got)
		}
	}
}

func TestAnalyzeDestructiveOperationPowerShellWhatIfBoolean(t *testing.T) {
	simulated := []string{
		`Remove-Item C:\data\old.txt -WhatIf:$true`,
		`Clear-Content C:\data\old.txt -wHaTiF:$TrUe`,
	}
	for _, command := range simulated {
		t.Run("simulated/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "powershell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("WhatIf true must audit as simulated execution: %+v", got)
			}
		})
	}

	executing := []string{
		`Remove-Item C:\data\old.txt -WhatIf:$false`,
		`Clear-Content C:\data\old.txt -wHaTiF:$FaLsE`,
	}
	for _, command := range executing {
		t.Run("executing/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "powershell", Arguments: map[string]any{"command": command}})
			if !got.HighConfidence {
				t.Fatalf("WhatIf false must preserve destructive execution: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationSimulationFlagContext(t *testing.T) {
	simulated := []string{
		"kubectl delete pod api --dry-run=client",
		"kubectl delete pod api --dry-run=server",
		"kubectl delete pod api --dry-run=true",
		"kubectl delete pod api --dry-run",
		"kubectl delete pod api --dry-run client",
	}
	for _, command := range simulated {
		t.Run("simulation/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
				t.Fatalf("explicit simulation must audit: %+v", got)
			}
		})
	}

	executing := []DestructiveInput{
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-run=none"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-run=false"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-run=0"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "kubectl delete pod api --dry-run none"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "rm -rf -- /srv/data --dry-run"}},
		{ToolName: "exec", Arguments: map[string]any{"argv": []any{"rm", "-rf", "--", "/srv/data", "--dry-run"}}},
		{ToolName: "powershell", Arguments: map[string]any{"command": "Remove-Item C:\\data\\old.txt -- -WhatIf"}},
	}
	for index, input := range executing {
		got := AnalyzeDestructiveOperation(input)
		if !got.HighConfidence {
			t.Fatalf("execution case %d must remain high confidence: %+v", index, got)
		}
		if index == 4 || index == 5 {
			if got.TargetSummary != "filesystem_delete:1-targets" {
				t.Fatalf("rm terminator case must retain exactly the real path target: %+v", got)
			}
		}
	}
}

func TestAnalyzeDestructiveOperationKubectlDeleteTargets(t *testing.T) {
	explicit := []string{
		"kubectl delete deployment api",
		"kubectl delete pods --all -n production",
		"kubectl delete -f k8s/prod.yaml",
		"kubectl delete --filename=k8s/prod.yaml",
	}
	for _, command := range explicit {
		t.Run("explicit/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			assertDestructive(t, got, "cluster_destroy")
		})
	}

	incomplete := []string{
		"kubectl delete namespace",
		"kubectl delete pods -n production",
		"kubectl delete --all -n production",
		"kubectl delete -f",
	}
	for _, command := range incomplete {
		t.Run("incomplete/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("kubectl delete without a concrete target must audit: %+v", got)
			}
		})
	}

	resource := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName: "shell", WorkingDirectory: "/repo", RepositoryRoot: "/repo",
		Arguments: map[string]any{"command": "kubectl delete deployment dist"},
	})
	assertDestructive(t, resource, "cluster_destroy")
	if resource.DiscardablePathMatched {
		t.Fatalf("cluster resources must never receive path noise reduction: %+v", resource)
	}
}

func TestAnalyzeDestructiveOperationCommandTargetCompleteness(t *testing.T) {
	incomplete := []string{
		"truncate -s 0",
		"Format-Volume -DriveLetter",
		"kubectl delete namespace",
	}
	for _, command := range incomplete {
		t.Run("incomplete/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("option or resource type is not a complete target: %+v", got)
			}
		})
	}

	explicit := []struct {
		command, subcategory string
	}{
		{"TRUNCATE -S 0 /var/log/app.log", "filesystem_overwrite"},
		{"FORMAT-VOLUME -DriveLetter D", "storage_destroy"},
		{"KUBECTL DELETE namespace production", "cluster_destroy"},
	}
	for _, tt := range explicit {
		t.Run("explicit/"+tt.command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "PowerShell", Arguments: map[string]any{"command": tt.command}})
			assertDestructive(t, got, tt.subcategory)
		})
	}
}

func TestAnalyzeDestructiveOperationSQLQuotedIdentifiers(t *testing.T) {
	for _, query := range []string{
		`DROP TABLE "users"`,
		`DELETE FROM "sessions"`,
	} {
		t.Run("identifier/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "database.query", Arguments: map[string]any{"query": query}})
			if !got.HighConfidence {
				t.Fatalf("quoted identifier is a real SQL target: %+v", got)
			}
		})
	}

	for _, query := range []string{
		`SELECT 'DROP TABLE users'`,
		`SELECT 'DELETE FROM sessions'`,
		"-- DROP TABLE users\nSELECT 1",
		`DELETE FROM logs WHERE note = 'DROP TABLE users'`,
	} {
		t.Run("non-code/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "database.query", Arguments: map[string]any{"query": query}})
			if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
				t.Fatalf("SQL strings/comments must not create destructive intent: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationSQLQuoteClosure(t *testing.T) {
	incomplete := []string{
		`DROP TABLE "customers`,
		`DROP TABLE 'customers`,
		`DROP TABLE $body$customers`,
		"DROP TABLE `customers",
		`DROP TABLE customers '`,
		`SELECT 'DROP TABLE hidden`,
		`SELECT $body$DROP TABLE hidden`,
	}
	for _, query := range incomplete {
		t.Run("incomplete/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:  "database.query",
				Arguments: map[string]any{"query": query},
			})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("unclosed SQL quote must remain audit-only: %+v", got)
			}
			assertParseRejected(t, got)
		})
	}

	t.Run("truncated double quoted identifier", func(t *testing.T) {
		query := `DROP TABLE "customers` + strings.Repeat("x", maxDestructiveCommandBytes)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:  "database.query",
			Arguments: map[string]any{"query": query},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("truncated quoted identifier must not become a complete target: %+v", got)
		}
		assertParseRejected(t, got)
	})

	closedIdentifiers := []string{
		`DROP TABLE "customers"`,
		"DROP TABLE `customers`",
	}
	for _, query := range closedIdentifiers {
		t.Run("closed identifier/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:  "database.query",
				Arguments: map[string]any{"query": query},
			})
			if !got.HighConfidence || got.SuggestedAction != DecisionConfirm || got.ParseRejected {
				t.Fatalf("closed quoted identifier must remain deterministic: %+v", got)
			}
		})
	}

	closedLiterals := []string{
		`SELECT 'DROP TABLE hidden'`,
		`SELECT $body$DROP TABLE hidden$body$`,
	}
	for _, query := range closedLiterals {
		t.Run("closed literal/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: "postgres",
				Arguments:  map[string]any{"query": query},
			})
			if got.HighConfidence || got.ParseRejected {
				t.Fatalf("closed SQL literal must remain benign and complete: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationSQLBracketIdentifiers(t *testing.T) {
	benign := []string{
		`SELECT [x; DROP TABLE users]`,
		`SELECT [x]]; DROP TABLE hidden]`,
	}
	for _, query := range benign {
		t.Run("benign/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: "sqlserver",
				Arguments:  map[string]any{"query": query},
			})
			if got.HighConfidence || got.ParseRejected {
				t.Fatalf("bracket identifier contents must not become SQL code: %+v", got)
			}
		})
	}

	destructive := []struct {
		query       string
		subcategory string
	}{
		{`DELETE FROM [sessions WHERE id=1]`, "database_unscoped_mutation"},
		{`DROP TABLE [customers]`, "database_destroy"},
		{`DROP TABLE [customer]]archive]`, "database_destroy"},
	}
	for _, tt := range destructive {
		t.Run("closed/"+tt.query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: "sqlserver",
				Arguments:  map[string]any{"query": tt.query},
			})
			if !got.HighConfidence || got.Subcategory != tt.subcategory || got.ParseRejected {
				t.Fatalf("closed bracket identifier must be one deterministic target: %+v", got)
			}
		})
	}

	for _, query := range []string{
		`DROP TABLE [customers`,
		`SELECT [x; DROP TABLE users`,
	} {
		t.Run("incomplete/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: "sqlserver",
				Arguments:  map[string]any{"query": query},
			})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("unclosed bracket identifier must remain audit-only: %+v", got)
			}
			assertParseRejected(t, got)
		})
	}
}

func TestAnalyzeDestructiveOperationMySQLExecutableComments(t *testing.T) {
	for _, query := range []string{
		`/*! DROP TABLE users */`,
		`/*!50000 DROP TABLE users */`,
	} {
		t.Run("executes/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: "mysql",
				Arguments:  map[string]any{"query": query},
			})
			if !got.HighConfidence || got.Subcategory != "database_destroy" || got.ParseRejected {
				t.Fatalf("executable comment SQL must be analyzed: %+v", got)
			}
		})
	}

	t.Run("ordinary block comment remains ignored", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "mysql",
			Arguments:  map[string]any{"query": `/* DROP TABLE hidden */ SELECT 1`},
		})
		if got.HighConfidence || got.ParseRejected {
			t.Fatalf("ordinary block comment must remain non-executable: %+v", got)
		}
	})

	t.Run("unclosed executable comment rejects", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "mysql",
			Arguments:  map[string]any{"query": `/*! DROP TABLE users`},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("unclosed executable comment must remain audit-only: %+v", got)
		}
		assertParseRejected(t, got)
	})
	t.Run("unclosed executable comment does not close at semicolon", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "mysql",
			Arguments:  map[string]any{"query": `/*! DROP TABLE users; SELECT 1`},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("semicolon cannot close an executable comment wrapper: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("quoted SQL inside executable comment remains data", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "mysql",
			Arguments:  map[string]any{"query": `/*! SELECT 'DROP TABLE hidden' */`},
		})
		if got.HighConfidence || got.ParseRejected {
			t.Fatalf("executable comment contents must still honor SQL quoting: %+v", got)
		}
	})

	budgeted := []struct {
		name  string
		query string
	}{
		{"token budget", "/*! DROP TABLE users " + strings.Repeat("x ", maxDestructiveSyntaxNodes) + " */"},
		{"statement budget", "/*! DROP TABLE users;" + strings.Repeat("SELECT 1;", maxDestructiveTargets) + "*/"},
		{"byte budget", "/*! DROP TABLE users */ " + strings.Repeat("x", maxDestructiveCommandBytes)},
	}
	for _, tt := range budgeted {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: "mysql",
				Arguments:  map[string]any{"query": tt.query},
			})
			if !got.HighConfidence || got.Subcategory != "database_destroy" || got.SuggestedAction != DecisionConfirm {
				t.Fatalf("bounded executable comment finding must be preserved: %+v", got)
			}
			assertParseRejected(t, got)
			assertBoundedDestructiveEvidence(t, got, tt.query, maxDestructiveCommandBytes)
		})
	}
	t.Run("executable nesting limit rejects", func(t *testing.T) {
		query := strings.Repeat("/*!", maxDestructiveShellDepth+1) +
			" DROP TABLE hidden " + strings.Repeat("*/", maxDestructiveShellDepth+1)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "mysql",
			Arguments:  map[string]any{"query": query},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("executable comment nesting overflow must remain audit-only: %+v", got)
		}
		assertParseRejected(t, got)
	})
}

func TestAnalyzeDestructiveOperationPostgresNestedBlockComments(t *testing.T) {
	t.Run("closed nested comment remains ignored", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "postgres",
			Arguments: map[string]any{
				"query": `SELECT 1 /* outer /* inner */ ; DROP TABLE hidden */`,
			},
		})
		if got.HighConfidence || got.ParseRejected {
			t.Fatalf("nested ordinary block comment must remain non-executable: %+v", got)
		}
	})
	t.Run("executable marker nested in ordinary comment stays ignored", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "postgres",
			Arguments: map[string]any{
				"query": `SELECT 1 /* outer /*! DROP TABLE hidden */ still outer */`,
			},
		})
		if got.HighConfidence || got.ParseRejected {
			t.Fatalf("ordinary comment context must suppress nested executable markers: %+v", got)
		}
	})

	t.Run("real statement after nested comment executes", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "postgres",
			Arguments: map[string]any{
				"query": `SELECT 1 /* outer /* inner */ hidden */; DROP TABLE visible`,
			},
		})
		if !got.HighConfidence || got.Subcategory != "database_destroy" || got.ParseRejected {
			t.Fatalf("SQL after the outer closing delimiter must remain executable: %+v", got)
		}
	})

	t.Run("unclosed outer comment rejects without exposing drop", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "postgres",
			Arguments: map[string]any{
				"query": `SELECT 1 /* outer /* inner */ ; DROP TABLE hidden`,
			},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("unclosed outer block comment must remain audit-only: %+v", got)
		}
		assertParseRejected(t, got)
	})

	t.Run("ordinary nesting limit rejects", func(t *testing.T) {
		query := strings.Repeat("/*", maxDestructiveShellDepth+1) +
			" DROP TABLE hidden " + strings.Repeat("*/", maxDestructiveShellDepth+1)
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "postgres",
			Arguments:  map[string]any{"query": query},
		})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("ordinary comment nesting overflow must remain audit-only: %+v", got)
		}
		assertParseRejected(t, got)
	})
}

func TestAnalyzeDestructiveOperationSQLBackslashEscapes(t *testing.T) {
	benign := []struct {
		query   string
		dialect string
	}{
		{`SELECT E'it\'s; DROP TABLE hidden'`, "postgres"},
		{`SELECT 'it\'s; DROP TABLE hidden'`, "mysql"},
		{`SELECT E'path\\server; DROP TABLE hidden'`, "postgres"},
		{`SELECT 'it''s; DROP TABLE hidden'`, "postgres"},
	}
	for _, tt := range benign {
		t.Run("closed/"+tt.query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: tt.dialect,
				Arguments:  map[string]any{"query": tt.query},
			})
			if got.HighConfidence || got.ParseRejected {
				t.Fatalf("escaped SQL string contents must remain non-executable: %+v", got)
			}
		})
	}

	for _, tt := range []struct {
		query   string
		dialect string
	}{
		{`SELECT E'it\'s; DROP TABLE hidden`, "postgres"},
		{`SELECT 'it\'s; DROP TABLE hidden`, "mysql"},
	} {
		t.Run("unclosed/"+tt.query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: tt.dialect,
				Arguments:  map[string]any{"query": tt.query},
			})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("unclosed escaped SQL string must remain audit-only: %+v", got)
			}
			assertParseRejected(t, got)
		})
	}

	t.Run("real drop after closed escaped string", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "postgres",
			Arguments:  map[string]any{"query": `SELECT E'it\'s'; DROP TABLE visible`},
		})
		if !got.HighConfidence || got.Subcategory != "database_destroy" || got.ParseRejected {
			t.Fatalf("SQL after a closed escaped string must remain executable: %+v", got)
		}
	})
}

func TestAnalyzeDestructiveOperationSQLDialectAmbiguity(t *testing.T) {
	nestedComment := `SELECT 1 /* outer /* inner */ ; DROP TABLE visible */`
	nestedCases := []struct {
		name     string
		dialect  string
		high     bool
		rejected bool
	}{
		{"postgres", "postgres", false, false},
		{"mysql", "mysql", true, false},
		{"sqlserver", "sqlserver", false, false},
		{"sqlite", "sqlite", true, false},
		{"generic", "generic", false, true},
		{"empty", "", false, true},
		{"invalid", "oracle", false, true},
	}
	for _, tt := range nestedCases {
		t.Run("nested/"+tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: tt.dialect,
				Arguments:  map[string]any{"query": nestedComment},
			})
			if got.HighConfidence != tt.high || got.ParseRejected != tt.rejected {
				t.Fatalf("nested comment dialect result mismatch: %+v", got)
			}
			if tt.rejected && (got.Confidence != "medium" || got.SuggestedAction != DecisionAudit) {
				t.Fatalf("ambiguous nested comment must remain audit-only: %+v", got)
			}
			for _, evidence := range got.Evidence {
				if evidence.SourceField != "query" || evidence.Length != len(nestedComment) {
					t.Fatalf("dialect metadata must not enter SQL evidence: %+v", evidence)
				}
			}
		})
	}

	backslashQuote := `SELECT 'x\'; DROP TABLE users`
	backslashCases := []struct {
		name     string
		dialect  string
		high     bool
		rejected bool
	}{
		{"postgres", "postgres", true, false},
		{"mysql", "mysql", false, true},
		{"sqlserver", "sqlserver", true, false},
		{"sqlite", "sqlite", true, false},
		{"generic", "generic", false, true},
		{"empty", "", false, true},
		{"invalid", "not-a-dialect", false, true},
	}
	for _, tt := range backslashCases {
		t.Run("backslash/"+tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: tt.dialect,
				Arguments:  map[string]any{"query": backslashQuote},
			})
			if got.HighConfidence != tt.high || got.ParseRejected != tt.rejected {
				t.Fatalf("backslash quote dialect result mismatch: %+v", got)
			}
			if tt.rejected && (got.Confidence != "medium" || got.SuggestedAction != DecisionAudit) {
				t.Fatalf("ambiguous or incomplete backslash quote must audit: %+v", got)
			}
		})
	}

	t.Run("postgres E string escapes", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "postgres",
			Arguments:  map[string]any{"query": `SELECT E'it\'s; DROP TABLE hidden'`},
		})
		if got.HighConfidence || got.ParseRejected {
			t.Fatalf("Postgres E string must honor backslash escapes: %+v", got)
		}
	})

	t.Run("mysql ordinary string escapes", func(t *testing.T) {
		got := AnalyzeDestructiveOperation(DestructiveInput{
			ToolName:   "database.query",
			SQLDialect: "mysql",
			Arguments:  map[string]any{"query": `SELECT 'it\'s; DROP TABLE hidden'`},
		})
		if got.HighConfidence || got.ParseRejected {
			t.Fatalf("MySQL ordinary string must honor backslash escapes: %+v", got)
		}
	})

	for _, query := range []string{
		"DROP TABLE users",
		"TRUNCATE TABLE logs",
		"DELETE FROM sessions",
	} {
		t.Run("generic unambiguous/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:  "database.query",
				Arguments: map[string]any{"query": query},
			})
			if !got.HighConfidence || got.SuggestedAction != DecisionConfirm || got.ParseRejected {
				t.Fatalf("unambiguous generic SQL must remain deterministic: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationMySQLExecutableCommentDialectAmbiguity(t *testing.T) {
	dialects := []struct {
		name       string
		dialect    string
		high       bool
		rejected   bool
		confidence string
	}{
		{"mysql", "mysql", true, false, "high"},
		{"postgres", "postgres", false, false, "low"},
		{"sqlserver", "sqlserver", false, false, "low"},
		{"sqlite", "sqlite", false, false, "low"},
		{"generic", "generic", false, true, "medium"},
		{"empty", "", false, true, "medium"},
		{"unknown", "oracle", false, true, "medium"},
	}
	for _, query := range []string{
		`/*! DROP TABLE users */`,
		`/*!50000 DROP TABLE users */`,
	} {
		for _, tt := range dialects {
			t.Run(tt.name+"/"+query, func(t *testing.T) {
				got := AnalyzeDestructiveOperation(DestructiveInput{
					ToolName:   "database.query",
					SQLDialect: tt.dialect,
					Arguments:  map[string]any{"query": query},
				})
				if got.HighConfidence != tt.high ||
					got.ParseRejected != tt.rejected ||
					got.Confidence != tt.confidence {
					t.Fatalf("executable comment dialect result mismatch: %+v", got)
				}
				if tt.high && got.SuggestedAction != DecisionConfirm {
					t.Fatalf("MySQL executable comment must remain confirmable: %+v", got)
				}
				if tt.rejected && got.SuggestedAction != DecisionAudit {
					t.Fatalf("ambiguous executable comment must remain audit-only: %+v", got)
				}
				if !tt.high && !tt.rejected &&
					(got.SuggestedAction != DecisionAudit || got.Category != "") {
					t.Fatalf("non-MySQL dialect must treat executable marker as an ordinary comment: %+v", got)
				}
			})
		}
	}
}

func TestAnalyzeDestructiveOperationDollarQuoteDialectAmbiguity(t *testing.T) {
	query := `SELECT 1 AS $x$; DROP TABLE users; SELECT 1 AS $x$`
	cases := []struct {
		name       string
		dialect    string
		high       bool
		rejected   bool
		confidence string
	}{
		{"postgres", "postgres", false, false, "low"},
		{"mysql", "mysql", true, false, "high"},
		{"sqlserver", "sqlserver", true, false, "high"},
		{"sqlite", "sqlite", true, false, "high"},
		{"generic", "generic", false, true, "medium"},
		{"empty", "", false, true, "medium"},
		{"unknown", "oracle", false, true, "medium"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: tt.dialect,
				Arguments:  map[string]any{"query": query},
			})
			if got.HighConfidence != tt.high ||
				got.ParseRejected != tt.rejected ||
				got.Confidence != tt.confidence {
				t.Fatalf("dollar quote dialect result mismatch: %+v", got)
			}
			if tt.high && got.SuggestedAction != DecisionConfirm {
				t.Fatalf("non-Postgres dialect must preserve the executable DROP: %+v", got)
			}
			if !tt.high && got.SuggestedAction != DecisionAudit {
				t.Fatalf("Postgres or ambiguous dollar quote must remain audit-only: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationSQLCodeContext(t *testing.T) {
	benign := []string{
		`SELECT '; DROP TABLE users'`,
		`SELECT "name; DROP TABLE users"`,
		`SELECT $$; DROP TABLE users$$`,
		`SELECT $body$; DROP TABLE users$body$`,
		"SELECT 1 # ; DROP TABLE users\n",
		`SELECT 1 /* ; DROP TABLE users */`,
	}
	for _, query := range benign {
		t.Run("benign/"+query, func(t *testing.T) {
			dialect := ""
			if strings.Contains(query, "$") {
				dialect = "postgres"
			}
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: dialect,
				Arguments:  map[string]any{"query": query},
			})
			if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
				t.Fatalf("non-code SQL must not create destructive intent: %+v", got)
			}
		})
	}

	destructive := []string{
		`SELECT $$; DROP TABLE users$$; DROP TABLE audit_log`,
		`SELECT $body$; DROP TABLE users$body$; DROP TABLE audit_log`,
		"SELECT 1 # ; DROP TABLE users\n; DROP TABLE audit_log",
		`SELECT '; DROP TABLE users'; DROP TABLE audit_log`,
	}
	for _, query := range destructive {
		t.Run("destructive/"+query, func(t *testing.T) {
			dialect := ""
			if strings.Contains(query, "$") {
				dialect = "postgres"
			}
			got := AnalyzeDestructiveOperation(DestructiveInput{
				ToolName:   "database.query",
				SQLDialect: dialect,
				Arguments:  map[string]any{"query": query},
			})
			if !got.HighConfidence || got.Subcategory != "database_destroy" {
				t.Fatalf("real code-context DROP must remain destructive: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationSQLStatementTargets(t *testing.T) {
	highConfidence := []string{
		"DROP TABLE IF EXISTS app.users",
		"TRUNCATE TABLE ONLY app.events",
		"DELETE FROM app.sessions; SELECT 1 WHERE 1=1",
		"SELECT 1; DELETE FROM audit.events",
		"UPDATE ONLY app.accounts SET active=false",
	}
	for _, query := range highConfidence {
		t.Run("high/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "database.query", Arguments: map[string]any{"query": query}})
			if !got.HighConfidence {
				t.Fatalf("expected statement-scoped high confidence, got %+v", got)
			}
		})
	}

	incomplete := []string{
		"DROP TABLE",
		"DROP TABLE IF EXISTS",
		"TRUNCATE TABLE ONLY",
		"DELETE FROM",
	}
	for _, query := range incomplete {
		t.Run("incomplete/"+query, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "database.query", Arguments: map[string]any{"query": query}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("missing SQL object must audit at medium confidence: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationFindDelete(t *testing.T) {
	root := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", WorkingDirectory: "/repo", RepositoryRoot: "/repo", Arguments: map[string]any{"command": "find / -delete"}})
	assertDestructive(t, root, "filesystem_delete")
	if root.DiscardablePathMatched {
		t.Fatalf("root target must never receive discardable-path noise reduction: %+v", root)
	}

	explicit := []string{
		"find /repo/tmp -type f -delete",
		"FIND /repo/build /repo/dist -delete",
	}
	for _, command := range explicit {
		t.Run("explicit/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			assertDestructive(t, got, "filesystem_delete")
		})
	}

	incomplete := []string{
		"find -delete",
		"find -type f -delete",
		"find . -delete",
	}
	for _, command := range incomplete {
		t.Run("incomplete/"+command, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("find expression without explicit start path must audit: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationStructuredActions(t *testing.T) {
	tests := []struct {
		name, want string
		input      DestructiveInput
	}{
		{"remove file", "filesystem_delete", DestructiveInput{ToolName: "file_manager", ToolType: "file", Arguments: map[string]any{"action": "remove", "path": "/repo/old.txt"}}},
		{"truncate file", "filesystem_overwrite", DestructiveInput{ToolName: "file_manager", ToolType: "file", Arguments: map[string]any{"operation": "truncate", "path": "/repo/cache.bin"}}},
		{"format storage", "storage_destroy", DestructiveInput{ToolName: "volume_manager", ToolType: "storage", Arguments: map[string]any{"action": "format", "volume_id": "vol-123"}}},
		{"purge resource", "resource_destroy", DestructiveInput{ToolName: "resource_manager", Arguments: map[string]any{"operation": "purge", "resource_id": "resource-123"}}},
		{"destroy infrastructure target", "infrastructure_destroy", DestructiveInput{ToolName: "terraform.workspace", ToolType: "infrastructure", Arguments: map[string]any{"action": "destroy", "target": "production"}}},
		{"reset source", "vcs_destroy", DestructiveInput{ToolName: "source_control", ToolType: "source", Arguments: map[string]any{"action": "reset", "repository_id": "repo-123"}}},
		{"tool name purge volume", "storage_destroy", DestructiveInput{ToolName: "storage.volume.purge", ToolType: "storage", Arguments: map[string]any{"volume_id": "vol-456"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertDestructive(t, AnalyzeDestructiveOperation(tt.input), tt.want)
		})
	}

	for _, action := range []string{"delete", "destroy", "remove", "purge", "truncate", "format", "reset"} {
		t.Run("missing target/"+action, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "resource_manager", Arguments: map[string]any{"action": action}})
			if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
				t.Fatalf("structured action without target must audit at medium confidence: %+v", got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationStructuredCloudDelete(t *testing.T) {
	got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "aws.ec2", ToolType: "cloud", Arguments: map[string]any{"action": "delete", "resource_type": "snapshot", "resource_id": "snap-123"}})
	assertDestructive(t, got, "cloud_resource_destroy")
}

func TestAnalyzeDestructiveOperationArgv(t *testing.T) {
	got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "exec", WorkingDirectory: "/repo/app", RepositoryRoot: "/repo", Arguments: map[string]any{"argv": []any{"git", "clean", "-fdx"}}})
	assertDestructive(t, got, "vcs_destroy")
}

func TestAnalyzeDestructiveOperationDatabaseToolModality(t *testing.T) {
	destructive := []DestructiveInput{
		{ToolName: "run", ToolType: "database", Arguments: map[string]any{"query": "DROP TABLE users"}},
		{ToolName: "database.query", Arguments: map[string]any{"query": "DROP TABLE users"}},
		{ToolName: "sql.execute", Arguments: map[string]any{"query": "DROP TABLE users"}},
	}
	for index, input := range destructive {
		got := AnalyzeDestructiveOperation(input)
		if !got.HighConfidence || got.Subcategory != "database_destroy" {
			t.Fatalf("database capability case %d must be analyzed as SQL: %+v", index, got)
		}
	}

	benign := []DestructiveInput{
		{ToolName: "search_query", ToolType: "search", Arguments: map[string]any{"query": "DROP TABLE users"}},
		{ToolName: "query_status", Arguments: map[string]any{"query": "DROP TABLE users"}},
		{ToolName: "request.query", ToolType: "http", Arguments: map[string]any{"query": "DROP TABLE users"}},
	}
	for index, input := range benign {
		got := AnalyzeDestructiveOperation(input)
		if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
			t.Fatalf("non-database query tool case %d must not be parsed as SQL: %+v", index, got)
		}
	}
}

func TestAnalyzeDestructiveOperationAvoidsFalsePositives(t *testing.T) {
	tests := []DestructiveInput{
		{ToolName: "delete_files", Arguments: map[string]any{"operation": "dry-run", "path": "/srv/data"}},
		{ToolName: "delete_status", Arguments: map[string]any{"action": "list", "path": "/srv/data"}},
		{ToolName: "delete_files", Arguments: map[string]any{"action": "delete", "dry_run": true, "path": "/srv/data"}},
		{ToolName: "resources.delete.query", Arguments: map[string]any{"action": "query", "path": "/srv/data"}},
		{ToolName: "database.query", Arguments: map[string]any{"query": "DELETE FROM sessions WHERE id=7"}},
		{ToolName: "database.query", Arguments: map[string]any{"query": "UPDATE accounts SET active=false WHERE id=7"}},
		{ToolName: "write_file", Arguments: map[string]any{"path": "/repo/README.md", "content": "Run rm -rf / only in a disposable VM"}},
		{ToolName: "write_file", Arguments: map[string]any{"path": "/repo/example.md", "content": "code: docker system prune -af"}},
		{ToolName: "edit_file", Arguments: map[string]any{"path": "/repo/main.go", "replacement": "// terraform destroy is forbidden"}},
		{ToolName: "shell", Arguments: map[string]any{"command": "go test ./internal/agentguard"}},
		{ToolName: "resource_manager", Arguments: map[string]any{"action": "delete"}},
		{ToolName: "write_file", Arguments: map[string]any{"args": []any{"rm", "-rf", "/srv/data"}}},
		{ToolName: "write_file", Arguments: map[string]any{"command": "rm -rf /srv/data", "path": "/repo/doc.md"}},
		{ToolName: "collection.update", Arguments: map[string]any{"action": "detach", "target": "deprecated-label"}},
	}
	for i, input := range tests {
		got := AnalyzeDestructiveOperation(input)
		if got.HighConfidence || got.SuggestedAction == DecisionConfirm || got.SuggestedAction == DecisionBlock {
			t.Fatalf("case %d unexpectedly gated: %+v", i, got)
		}
	}
}

func TestAnalyzeDestructiveOperationStructuredPluralTargets(t *testing.T) {
	valid := []struct {
		name      string
		toolType  string
		arguments map[string]any
		want      string
	}{
		{"paths", "file", map[string]any{"action": "delete", "paths": []string{"/repo/a", "/repo/b"}}, "filesystem_delete:2-targets"},
		{"file paths", "file", map[string]any{"action": "delete", "file_paths": []any{"/repo/a", "/repo/b"}}, "filesystem_delete:2-targets"},
		{"targets", "resource", map[string]any{"action": "delete", "targets": []string{"one", "two"}}, "resource_destroy:2-targets"},
		{"ids", "resource", map[string]any{"action": "delete", "ids": []any{"one", "two"}}, "resource_destroy:2-targets"},
		{"resource ids", "resource", map[string]any{"action": "delete", "resource_ids": []string{"one", "two"}}, "resource_destroy:2-targets"},
	}
	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "resource_manager", ToolType: tt.toolType, Arguments: tt.arguments})
			if !got.HighConfidence || got.TargetSummary != tt.want {
				t.Fatalf("plural targets must all be retained: %+v", got)
			}
		})
	}

	onlyMalformed := []map[string]any{
		{"action": "delete", "paths": []string{}},
		{"action": "delete", "targets": []any{2}},
		{"action": "delete", "ids": []any{""}},
	}
	for index, arguments := range onlyMalformed {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "resource_manager", Arguments: arguments})
		if got.HighConfidence || got.Confidence != "medium" || got.SuggestedAction != DecisionAudit {
			t.Fatalf("only-malformed plural targets case %d must audit: %+v", index, got)
		}
	}

	conflicts := []struct {
		arguments map[string]any
		want      string
	}{
		{map[string]any{"action": "delete", "path": "/repo/keep", "targets": []any{1}}, "filesystem_delete:1-targets"},
		{map[string]any{"action": "delete", "path": "/repo/keep", "targets": []any{}}, "filesystem_delete:1-targets"},
		{map[string]any{"action": "delete", "path": "/repo/keep", "targets": []any{"", "two"}}, "filesystem_delete:2-targets"},
	}
	for index, tt := range conflicts {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "resource_manager", Arguments: tt.arguments})
		if !got.HighConfidence || got.TargetSummary != tt.want {
			t.Fatalf("valid targets must survive malformed plural case %d: %+v", index, got)
		}
		conflictEvidence := false
		for _, evidence := range got.Evidence {
			if evidence.RuleID == "agent_destructive_target_conflict" && evidence.MaskedPreview == "" && evidence.Hash == "" {
				conflictEvidence = true
			}
		}
		if !conflictEvidence {
			t.Fatalf("malformed plural case %d needs safe conflict evidence: %+v", index, got)
		}
	}

	tooMany := make([]string, maxDestructiveTargets+1)
	for index := range tooMany {
		tooMany[index] = "id-" + strings.Repeat("x", index+1)
	}
	overLimit := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "resource_manager", Arguments: map[string]any{"action": "delete", "targets": tooMany}})
	if !overLimit.HighConfidence || overLimit.TargetSummary != "resource_destroy:256-targets" || !overLimit.ParseRejected {
		t.Fatalf("structured target limit must preserve bounded confirmed finding: %+v", overLimit)
	}

	mixed := AnalyzeDestructiveOperation(DestructiveInput{
		ToolName: "file_manager", ToolType: "file",
		WorkingDirectory: "/repo/app", RepositoryRoot: "/repo", DiscardablePaths: []string{"dist"},
		Arguments: map[string]any{"action": "delete", "paths": []string{"/repo/app/dist", "/etc/passwd"}},
	})
	if !mixed.HighConfidence || mixed.DiscardablePathMatched || mixed.TargetSummary != "filesystem_delete:2-targets" {
		t.Fatalf("mixed discardable and sensitive targets must never downgrade: %+v", mixed)
	}
}

func TestStructuredTargetsPluralTraversalIsBounded(t *testing.T) {
	stringValues := make([]string, 10_000)
	anyValues := make([]any, 10_000)
	for index := range stringValues {
		value := "id-" + strconv.Itoa(index)
		stringValues[index] = value
		anyValues[index] = value
	}
	anyValues[maxDestructiveTargets] = 42

	tests := []struct {
		name         string
		arguments    map[string]any
		wantConflict bool
	}{
		{"string slice", map[string]any{"targets": stringValues}, false},
		{"any slice preserves conflict", map[string]any{"targets": anyValues}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspected := 0
			got := structuredTargetsWithObserver(tt.arguments, func(any) {
				inspected++
			})
			if inspected != maxDestructiveTargets+1 {
				t.Fatalf("inspected %d plural values, want %d", inspected, maxDestructiveTargets+1)
			}
			if !got.Exceeded || len(got.Targets) != maxDestructiveTargets {
				t.Fatalf("bounded traversal must retain 256 targets and reject overflow: %+v", got)
			}
			if got.Conflict != tt.wantConflict {
				t.Fatalf("conflict=%v want %v: %+v", got.Conflict, tt.wantConflict, got)
			}
		})
	}
}

func TestAnalyzeDestructiveOperationDiscardablePaths(t *testing.T) {
	tests := []struct {
		name, tool, cwd, root, command string
		discardable                    []string
		want                           bool
	}{
		{"linux dist", "shell", "/repo/app", "/repo", "rm -rf /repo/app/dist/assets", nil, true},
		{"windows node modules", "powershell", "C:\\repo\\app", "C:\\repo", "Remove-Item -Recurse C:\\repo\\app\\node_modules\\pkg", nil, true},
		{"configured generated", "shell", "/repo", "/repo", "rm -rf /repo/generated", []string{"generated"}, true},
		{"repo root", "shell", "/repo", "/repo", "rm -rf /repo", nil, false},
		{"git", "shell", "/repo", "/repo", "rm -rf /repo/.git", nil, false},
		{"home", "shell", "/home/alice/repo", "/home/alice/repo", "rm -rf /home/alice", nil, false},
		{"windows home", "powershell", "C:\\Users\\Alice\\project", "C:\\Users", "Remove-Item -Recurse C:\\USERS\\Alice", []string{"Alice"}, false},
		{"linux root", "shell", "/repo", "/repo", "rm -rf /", nil, false},
		{"drive root", "powershell", "C:\\repo", "C:\\repo", "Remove-Item -Recurse C:\\", nil, false},
		{"root repository", "shell", "/", "/", "rm -rf /tmp/test-output", nil, false},
		{"drive root repository", "powershell", "C:\\", "C:\\", "Remove-Item -Recurse C:\\tmp\\test-output", nil, false},
		{"escape", "shell", "/repo", "/repo", "rm -rf /repo/dist/../../etc", nil, false},
		{"wildcard", "shell", "/repo", "/repo", "rm -rf /repo/dist/*", nil, false},
		{"mixed", "shell", "/repo", "/repo", "rm -rf /repo/dist /repo/src", nil, false},
		{"relative cwd", "shell", "./repo", "/repo", "rm -rf /repo/dist", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: tt.tool, WorkingDirectory: tt.cwd, RepositoryRoot: tt.root, DiscardablePaths: tt.discardable, Arguments: map[string]any{"command": tt.command}})
			if got.DiscardablePathMatched != tt.want {
				t.Fatalf("match=%v want %v: %+v", got.DiscardablePathMatched, tt.want, got)
			}
			if tt.want && (got.HighConfidence || got.SuggestedAction != DecisionAudit || got.DiscardablePathReason == "") {
				t.Fatalf("discardable target was not audit-only: %+v", got)
			}
		})
	}
}

func assertParseRejected(t *testing.T, got DestructiveAnalysis) {
	t.Helper()
	field := reflect.ValueOf(got).FieldByName("ParseRejected")
	if !field.IsValid() || field.Kind() != reflect.Bool || !field.Bool() {
		t.Fatalf("analysis must expose an explicit parse rejection state: %+v", got)
	}
}

func assertDestructive(t *testing.T, got DestructiveAnalysis, want string) {
	t.Helper()
	if !got.HighConfidence || got.Category != "destructive_operation" || got.Subcategory != want {
		t.Fatalf("unexpected analysis: %+v", got)
	}
	if got.SuggestedAction != DecisionConfirm && got.SuggestedAction != DecisionBlock {
		t.Fatalf("high confidence operation must gate: %+v", got)
	}
	if got.TargetSummary == "" || len(got.Evidence) == 0 {
		t.Fatalf("safe summary/evidence missing: %+v", got)
	}
	for _, evidence := range got.Evidence {
		if evidence.Hash == "" || !strings.HasPrefix(evidence.MaskedPreview, "<redacted:") {
			t.Fatalf("raw evidence leaked: %+v", evidence)
		}
	}
}
