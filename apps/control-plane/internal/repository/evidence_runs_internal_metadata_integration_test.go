package repository

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestListEvidenceRunsExcludesHistoricalInternalMetadataCalls(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_internal_metadata_%d", suffix)
	t.Cleanup(func() {
		for _, query := range []string{
			"DELETE FROM access_content_logs WHERE tenant_id = $1",
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			if _, err := db.Exec(ctx, query, tenantID); err != nil {
				t.Logf("cleanup %q: %v", query, err)
			}
		}
		db.Close()
	})

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	type fixture struct {
		id, agentType, host, path, requestText, responseText string
		model                                                string
		requestBytes                                         int
		fileMetadata                                         string
		visible                                              bool
	}
	const codexTitlePrompt = `You are a helpful assistant. You will be presented with a user prompt, and your job is to provide a short title for a task that will be created from that prompt.
The tasks typically have to do with coding-related tasks, for example requests for bug fixes or questions about a codebase. The title you generate will be shown in the UI to represent the prompt.
Generate a concise UI title (up to 36 characters) for this task.
Generate a clear, informative task title based solely on the prompt provided. Follow the rules.`
	fixtures := []fixture{
		{id: "codex-title", agentType: "openai-codex", host: "api.example.test", path: "/v1/responses?source=title", model: "gpt-5.6-luna", requestText: codexTitlePrompt, responseText: `{"description":"fix retention","title":"Fix retention"}`},
		{id: "codebuddy-title", agentType: "codebuddy", host: "copilot.tencent.com", path: "/v2/chat/completions?source=title", model: "deepseek-v4-pro", requestBytes: 1086, requestText: "Q: come on\nA: the workspace is empty", responseText: "Start in an empty workspace"},
		{id: "workbuddy-title", agentType: "workbuddy", host: "copilot.tencent.com", path: "/v2/chat/completions?source=title", model: "deepseek-v4-flash", requestBytes: 1309, requestText: "<session>start</session>", responseText: `{"isNewTopic": true, "title": "Start work"}`},
		{id: "workbuddy-title-reordered", agentType: "workbuddy", host: "copilot.tencent.com", path: "/v2/chat/completions", model: "deepseek-v4-flash", requestBytes: 1309, requestText: "<session>continue</session>", responseText: `{"title": "Continue work", "isNewTopic": true}`},
		{id: "ordinary-summary", agentType: "openai-codex", host: "api.example.test", path: "/v1/responses", requestText: "Please summarize the title-generation design for the customer.", responseText: "Customer-facing summary", visible: true},
		{id: "partial-title-quote", agentType: "openai-codex", host: "api.example.test", path: "/v1/responses", requestText: "You are a helpful assistant. You will be presented with a user prompt, and your job is to provide a short title for a task that will be created from that prompt. What does this sentence mean?", responseText: "It asks a model to title a task.", visible: true},
		{id: "title-wrong-endpoint", agentType: "openai-codex", host: "api.example.test", path: "/v1/chat/completions", model: "gpt-5.6-luna", requestText: codexTitlePrompt, responseText: `{"description":"user result","title":"User result"}`, visible: true},
		{id: "title-wrong-agent", agentType: "cline", host: "api.example.test", path: "/v1/responses", model: "gpt-5.6-luna", requestText: codexTitlePrompt, responseText: `{"description":"user result","title":"User result"}`, visible: true},
		{id: "codebuddy-user-chat", agentType: "codebuddy", host: "copilot.tencent.com", path: "/v2/chat/completions", model: "auto", requestBytes: 29759, requestText: "Q: What is this API?\nA: It is the old answer.", responseText: "A business API", visible: true},
		{id: "codebuddy-large-deepseek", agentType: "codebuddy", host: "copilot.tencent.com", path: "/v2/chat/completions", model: "deepseek-v4-pro", requestBytes: 29424, requestText: "Q: What is this API?\nA: It is the old answer.", responseText: "A business API", visible: true},
		{id: "codebuddy-image-chat", agentType: "codebuddy", host: "copilot.tencent.com", path: "/v2/chat/completions", model: "deepseek-v4-pro", requestBytes: 1086, requestText: "Q: What is in this image?\nA: Prior context", responseText: "A red diagram", fileMetadata: `[{"name":"shot.png"}]`, visible: true},
		{id: "workbuddy-json", agentType: "workbuddy", host: "copilot.tencent.com", path: "/v2/chat/completions", model: "deepseek-v4-flash", requestBytes: 1309, requestText: "Return JSON", responseText: `{"isNewTopic": true, "title": "User requested output"}`, visible: true},
	}

	base := time.Date(2026, 9, 3, 6, 0, 0, 0, time.UTC)
	for index, item := range fixtures {
		requestID := fmt.Sprintf("%s-%d", item.id, suffix)
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
				proxy_access_type, proxy_access_type_resolved, proxy_provider, proxy_product,
				proxy_tls_inspected, proxy_content_retained, proxy_retention_level,
				proxy_endpoint_kind, agent_type, proxy_request_bytes, risk_state, has_retained_content,
				environment_scope, created_at
			) VALUES (
				$1, $1, $2, 'proxy', 'success', 'forward', $3, $4, 'POST',
				'ai_ide', 'ai_ide', 'test', 'test', TRUE, TRUE, 'content', 'chat',
				$5, $6, 'normal', TRUE, 'customer', $7
			)
		`, requestID, tenantID, item.host, item.path, item.agentType, item.requestBytes, base.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatalf("insert request %s: %v", item.id, err)
		}
		metadata := item.fileMetadata
		if metadata == "" {
			metadata = "[]"
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO access_content_logs (
				id, request_id, tenant_id, request_content_redacted,
				response_content_redacted, file_metadata_json, provider, model,
				environment_scope, created_at
			) VALUES ($1, $1, $2, $3, $4, $5::jsonb, 'test', NULLIF($6, ''), 'customer', $7)
		`, requestID, tenantID, item.requestText, item.responseText, metadata, item.model, base.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatalf("insert content %s: %v", item.id, err)
		}
	}

	repo := NewRequestLogRepository(db)
	records, total, err := repo.ListEvidenceRuns(ctx, tenantID, "agent_tasks", ForwardProxyAccessFilter{
		EnvironmentScope: "customer",
		ContentOnly:      true,
		Limit:            100,
	})
	if err != nil {
		t.Fatalf("list evidence runs: %v", err)
	}
	wantVisible := make([]string, 0, len(fixtures))
	for _, item := range fixtures {
		if item.visible {
			wantVisible = append(wantVisible, item.id)
		}
	}
	gotVisible := make([]string, 0, len(records))
	for _, record := range records {
		for _, item := range fixtures {
			if record.RepresentativeRequestID == fmt.Sprintf("%s-%d", item.id, suffix) {
				gotVisible = append(gotVisible, item.id)
				break
			}
		}
	}
	sort.Strings(gotVisible)
	sort.Strings(wantVisible)
	if fmt.Sprint(gotVisible) != fmt.Sprint(wantVisible) || total != len(wantVisible) {
		t.Fatalf("visible runs=%v total=%d, want %v total=%d", gotVisible, total, wantVisible, len(wantVisible))
	}

	keywordRecords, keywordTotal, err := repo.ListEvidenceRuns(ctx, tenantID, "agent_tasks", ForwardProxyAccessFilter{
		EnvironmentScope: "customer",
		ContentOnly:      true,
		Keyword:          "helpful assistant",
		Limit:            100,
	})
	if err != nil {
		t.Fatalf("keyword list evidence runs: %v", err)
	}
	if keywordTotal != 3 || len(keywordRecords) != 3 {
		t.Fatalf("keyword results leaked exact Codex title metadata: total=%d records=%+v", keywordTotal, keywordRecords)
	}

	var retainedRows int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM access_content_logs WHERE tenant_id = $1`, tenantID).Scan(&retainedRows); err != nil {
		t.Fatalf("count retained audit rows: %v", err)
	}
	if retainedRows != len(fixtures) {
		t.Fatalf("read-side projection must not delete audit evidence: rows=%d want=%d", retainedRows, len(fixtures))
	}
}
