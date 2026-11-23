package backfill

import (
	"os"
	"strings"
	"testing"
)

func TestDetectAgentUAIdentity(t *testing.T) {
	cases := []struct {
		name string
		row  agentUAIdentityRow
		want string
	}{
		{"workbuddy main over codex", agentUAIdentityRow{UserAgent: wbUA, DeclaredType: "main", AgentType: "openai-codex", Source: "message_protocol"}, "workbuddy"},
		{"workbuddy auxiliary client_header", agentUAIdentityRow{UserAgent: wbUA, DeclaredType: "auxiliary", AgentType: "auxiliary", Source: "client_header"}, "workbuddy"},
		{"workbuddy compaction client_header", agentUAIdentityRow{UserAgent: wbUA, DeclaredType: "compaction", AgentType: "compaction", Source: "client_header"}, "workbuddy"},
		{"deepseek content", agentUAIdentityRow{UserAgent: ds1UA, AgentType: "dify-coze", Source: "content"}, "deepseek-harness"},
		{"deepseek message_protocol", agentUAIdentityRow{UserAgent: ds2UA, AgentType: "cursor", Source: "message_protocol"}, "deepseek-harness"},
		{"already same product", agentUAIdentityRow{UserAgent: wbUA, AgentType: "workbuddy", Source: "message_protocol"}, ""},
		{"openai python unknown", agentUAIdentityRow{UserAgent: "OpenAI/Python 2.24.0", AgentType: "openai-codex", Source: "content"}, ""},
		{"go http client unknown", agentUAIdentityRow{UserAgent: "Go-http-client/1.1", AgentType: "claude-code", Source: "message_protocol"}, ""},
		{"client_header concrete declared", agentUAIdentityRow{UserAgent: wbUA, DeclaredType: "cursor", AgentType: "cursor", Source: "client_header"}, ""},
		{"client_header generic declared but concrete stored", agentUAIdentityRow{UserAgent: wbUA, DeclaredType: "main", AgentType: "cursor", Source: "client_header"}, ""},
		{"vscode runtime is not a product", agentUAIdentityRow{UserAgent: "Mozilla/5.0 Code/1.99 Electron/30", AgentType: "openai-codex", Source: "content"}, ""},
	}
	for _, tc := range cases {
		v1, _ := agentUAIdentitySpecFor(AgentUAIdentityTask)
		detection, ok := detectAgentUAIdentity(tc.row, v1)
		got := ""
		if ok {
			got = detection.Product
			if detection.Source != "user_agent" || detection.Confidence != 0.85 {
				t.Fatalf("%s: source=%q confidence=%v", tc.name, detection.Source, detection.Confidence)
			}
		}
		if got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// 任务写入的迁移号必须与注册该任务的迁移文件编号一致。
func TestAgentUAIdentityMigrationNumberMatchesRegistration(t *testing.T) {
	entries, err := os.ReadDir("../../../../deploy/migrations")
	if err != nil {
		t.Fatal(err)
	}
	found := ""
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), agentUAIdentityMigration+"_") {
			continue
		}
		body, readErr := os.ReadFile("../../../../deploy/migrations/" + entry.Name())
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(body), "'"+AgentUAIdentityTask+"'") {
			found = entry.Name()
		}
	}
	if found == "" {
		t.Fatalf("no migration %s_* registers task %s", agentUAIdentityMigration, AgentUAIdentityTask)
	}
}
