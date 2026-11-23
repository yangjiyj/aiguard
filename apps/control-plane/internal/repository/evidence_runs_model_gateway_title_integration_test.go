package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestListEvidenceRunsExcludesWorkBuddyModelGatewayTitleCalls(t *testing.T) {
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
	tenantID := fmt.Sprintf("tenant_model_title_%d", suffix)
	t.Cleanup(func() {
		for _, query := range []string{
			"DELETE FROM content_logs WHERE tenant_id = $1",
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			if _, err := db.Exec(ctx, query, tenantID); err != nil {
				t.Logf("cleanup %q: %v", query, err)
			}
		}
		db.Close()
	})
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	type fixture struct {
		name, agentType, proxyMode, endpointType, user, assistant string
		hidden                                                    bool
	}
	fixtures := []fixture{
		{
			name: "internal", agentType: "workbuddy", proxyMode: "chat_completion", endpointType: "chat",
			user: "<session>\nInspect the retained gateway task", assistant: `{"isNewTopic":true,"title":"Inspect retained gateway"}`,
			hidden: true,
		},
		{
			name: "main-task", agentType: "workbuddy", proxyMode: "chat_completion", endpointType: "chat",
			user: "<session>\nInspect the retained gateway task\n</session>", assistant: "I inspected the gateway and found two issues.",
		},
		{
			name: "extra-json-key", agentType: "workbuddy", proxyMode: "chat_completion", endpointType: "chat",
			user: "<session>\nReturn the full JSON object\n</session>", assistant: `{"isNewTopic":true,"title":"Requested JSON","details":"customer requested"}`,
		},
		{
			name: "ordinary-json", agentType: "workbuddy", proxyMode: "chat_completion", endpointType: "chat",
			user: "Return the title JSON exactly", assistant: `{"isNewTopic":true,"title":"Requested JSON"}`,
		},
		{
			name: "other-agent", agentType: "openai-codex", proxyMode: "chat_completion", endpointType: "chat",
			user: "<session>\nDiscuss XML wrappers\n</session>", assistant: `{"isNewTopic":true,"title":"Discuss XML wrappers"}`,
		},
	}

	requestIDs := make(map[string]string, len(fixtures))
	for index, item := range fixtures {
		requestLogID := fmt.Sprintf("log_%s_%d", item.name, suffix)
		requestID := fmt.Sprintf("req_%s_%d", item.name, suffix)
		requestIDs[item.name] = requestID
		createdAt := base.Add(time.Duration(index) * time.Second)
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, endpoint_type, request_status,
				proxy_mode, proxy_access_type_resolved, agent_type, risk_state,
				has_retained_content, environment_scope, created_at
			) VALUES ($1, $2, $3, $4, 'success', $5, 'llm', $6, 'normal', TRUE, 'customer', $7)
		`, requestLogID, requestID, tenantID, item.endpointType, item.proxyMode, item.agentType, createdAt); err != nil {
			t.Fatalf("insert request %s: %v", item.name, err)
		}
		for messageIndex, message := range []struct{ role, content string }{
			{role: "user", content: item.user},
			{role: "assistant", content: item.assistant},
		} {
			if _, err := db.Exec(ctx, `
				INSERT INTO content_logs (
					id, request_id, tenant_id, role, content, tokens,
					environment_scope, message_index, created_at
				) VALUES ($1, $2, $3, $4, $5, 0, 'customer', $6, $7)
			`, fmt.Sprintf("cl_%s_%d_%d", item.name, suffix, messageIndex), requestLogID, tenantID,
				message.role, message.content, messageIndex, createdAt.Add(time.Duration(messageIndex)*time.Millisecond)); err != nil {
				t.Fatalf("insert content %s/%s: %v", item.name, message.role, err)
			}
		}
	}

	repo := NewRequestLogRepository(db)
	records, total, err := repo.ListEvidenceRuns(ctx, tenantID, "agent_tasks", ForwardProxyAccessFilter{
		EnvironmentScope: "customer", ContentOnly: true,
		StartTime: base.Add(-time.Minute), EndTime: base.Add(time.Minute), Limit: 100,
	})
	if err != nil {
		t.Fatalf("list evidence runs: %v", err)
	}
	if total != len(fixtures)-1 || len(records) != len(fixtures)-1 {
		t.Fatalf("visible runs total=%d records=%d, want %d: %+v", total, len(records), len(fixtures)-1, records)
	}
	for _, record := range records {
		for _, member := range record.MemberRequestIDs {
			if member == requestIDs["internal"] {
				t.Fatalf("internal WorkBuddy title call leaked into task list: %+v", record)
			}
		}
	}
	var retained int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM request_logs WHERE tenant_id = $1`, tenantID).Scan(&retained); err != nil {
		t.Fatalf("count retained request logs: %v", err)
	}
	if retained != len(fixtures) {
		t.Fatalf("read-side filter changed audit ledger: retained=%d want=%d", retained, len(fixtures))
	}
}
