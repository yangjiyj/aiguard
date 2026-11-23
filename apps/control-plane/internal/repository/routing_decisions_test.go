package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupRoutingDecisionsTestDB opens a test database connection and seeds a tenant.
func setupRoutingDecisionsTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tenantID := fmt.Sprintf("tenant_rd_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

func TestListRoutingDecisions(t *testing.T) {
	pool, tenantID := setupRoutingDecisionsTestDB(t)
	repo := NewRequestLogRepository(pool)
	ctx := context.Background()

	// Insert a request_log with routing_decision_json (model_id NULL to avoid FK)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	requestID := "req_" + sfx

	routingDecision := map[string]any{
		"policy_id":   "policy_123",
		"policy_name": "Test Policy",
		"action":      "route_to_provider",
		"target":      "provider_abc",
		"reason":      "matched rule X",
	}
	routingJSON, _ := json.Marshal(routingDecision)

	_, err := pool.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, request_status, latency_ms, created_at, routing_decision_json)
		VALUES ($1, $2, $3, $4, 137, $5, $6)
	`, "rl_"+sfx, requestID, tenantID, "completed", time.Now(), routingJSON)
	if err != nil {
		t.Fatalf("insert request_log: %v", err)
	}

	// Also insert a request_log WITHOUT routing_decision_json (should be excluded)
	_, err = pool.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, request_status, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, "rl_no_rd_"+sfx, "req_no_rd_"+sfx, tenantID, "completed", time.Now())
	if err != nil {
		t.Fatalf("insert request_log without routing decision: %v", err)
	}

	// List routing decisions
	logs, total, err := repo.ListRoutingDecisions(ctx, tenantID, 10, 0)
	if err != nil {
		t.Fatalf("ListRoutingDecisions: %v", err)
	}

	// Should return 1 (only the one with routing_decision_json)
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	// Verify the routing decision data
	if logs[0].RequestID != requestID {
		t.Errorf("expected request_id %s, got %s", requestID, logs[0].RequestID)
	}
	if logs[0].RoutingDecisionJSON == nil {
		t.Fatalf("RoutingDecisionJSON should not be nil")
	}
	if logs[0].RoutingDecisionJSON["policy_id"] != "policy_123" {
		t.Errorf("expected policy_id policy_123, got %v", logs[0].RoutingDecisionJSON["policy_id"])
	}
	if logs[0].RoutingDecisionJSON["action"] != "route_to_provider" {
		t.Errorf("expected action route_to_provider, got %v", logs[0].RoutingDecisionJSON["action"])
	}
	if logs[0].LatencyMS == nil || *logs[0].LatencyMS != 137 {
		t.Fatalf("expected customer latency_ms=137, got %#v", logs[0].LatencyMS)
	}
}

func TestListRoutingDecisionsPagination(t *testing.T) {
	pool, tenantID := setupRoutingDecisionsTestDB(t)
	repo := NewRequestLogRepository(pool)
	ctx := context.Background()

	// Insert 3 request_logs with routing_decision_json (model_id NULL)
	for i := 0; i < 3; i++ {
		sfx := fmt.Sprintf("%d_%d", time.Now().UnixNano(), i)
		routingDecision := map[string]any{
			"policy_id": fmt.Sprintf("policy_%d", i),
			"action":    "test_action",
		}
		routingJSON, _ := json.Marshal(routingDecision)

		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (id, request_id, tenant_id, request_status, created_at, routing_decision_json)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, "rl_pag_"+sfx, "req_pag_"+sfx, tenantID, "completed", time.Now(), routingJSON)
		if err != nil {
			t.Fatalf("insert request_log %d: %v", i, err)
		}
		time.Sleep(1 * time.Millisecond) // Ensure different created_at
	}

	// Test limit
	logs, total, err := repo.ListRoutingDecisions(ctx, tenantID, 2, 0)
	if err != nil {
		t.Fatalf("ListRoutingDecisions: %v", err)
	}
	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 logs with limit=2, got %d", len(logs))
	}

	// Test offset
	logs2, _, err := repo.ListRoutingDecisions(ctx, tenantID, 2, 2)
	if err != nil {
		t.Fatalf("ListRoutingDecisions offset: %v", err)
	}
	if len(logs2) != 1 {
		t.Errorf("expected 1 log with offset=2, got %d", len(logs2))
	}
}

func TestListRoutingDecisionsEmpty(t *testing.T) {
	pool, tenantID := setupRoutingDecisionsTestDB(t)
	repo := NewRequestLogRepository(pool)
	ctx := context.Background()

	// No data inserted
	logs, total, err := repo.ListRoutingDecisions(ctx, tenantID, 10, 0)
	if err != nil {
		t.Fatalf("ListRoutingDecisions: %v", err)
	}

	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}

func TestListRoutingDecisionsPreservesUnknownLatencyAsNull(t *testing.T) {
	pool, tenantID := setupRoutingDecisionsTestDB(t)
	repo := NewRequestLogRepository(pool)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `INSERT INTO request_logs (id,request_id,tenant_id,request_status,latency_ms,created_at,routing_decision_json) VALUES ('rd_null_latency','req_null_latency',$1,'completed',NULL,NOW(),'{}'::jsonb)`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	items, total, err := repo.ListRoutingDecisions(ctx, tenantID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].LatencyMS != nil {
		t.Fatalf("unknown latency must stay null, total=%d items=%#v", total, items)
	}
}

func TestRoutingDecisionAPIFiltersModelProviderResultAndFallback(t *testing.T) {
	pool, tenantID := setupRoutingDecisionsTestDB(t)
	repo := NewRequestLogRepository(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	v2 := `{"model_route_v2":{"schema_version":2,"requested_model":"logical/model","planned_route":{"provider_name":"供应商甲","route_ref":"线路 A"},"actual_route":{"provider_name":"供应商乙","route_ref":"线路 B"},"fallback_used":true,"fallback_reason":"primary_failed"}}`
	_, err := pool.Exec(ctx, `INSERT INTO request_logs (id,request_id,tenant_id,request_status,created_at,routing_decision_json) VALUES ('rd_filter','req_filter',$1,'completed',$2,$3::jsonb)`, tenantID, now, v2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO request_logs (id,request_id,tenant_id,request_status,created_at,routing_decision_json) VALUES ('rd_other','req_other',$1,'failed',$2,'{"model_route_v2":{"schema_version":2,"requested_model":"other","fallback_used":false}}'::jsonb)`, tenantID, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	items, total, err := repo.ListRoutingDecisionsFiltered(ctx, tenantID, RoutingDecisionFilter{From: now.Add(-time.Minute), To: now.Add(time.Minute), Model: "logical/model", Provider: "供应商乙", Result: "completed", Fallback: boolPtr(true)}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].RequestID != "req_filter" {
		t.Fatalf("filters not applied: total=%d items=%#v", total, items)
	}
}

func boolPtr(v bool) *bool { return &v }

func TestRoutingDecisionPaginationStableForEqualTimestampsAndMarksInvalidJSONShape(t *testing.T) {
	pool, tenantID := setupRoutingDecisionsTestDB(t)
	repo := NewRequestLogRepository(pool)
	ctx := context.Background()
	stamp := time.Now().UTC()
	for _, id := range []string{"a", "b", "c"} {
		payload := `{"model_route_v2":{"schema_version":2,"requested_model":"m"}}`
		if id == "b" {
			payload = `"not-an-object"`
		}
		_, err := pool.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,request_status,created_at,routing_decision_json) VALUES($1,$2,$3,'completed',$4,$5::jsonb)`, "stable_"+id, "req_"+id, tenantID, stamp, payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	first, _, err := repo.ListRoutingDecisions(ctx, tenantID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := repo.ListRoutingDecisions(ctx, tenantID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	third, _, err := repo.ListRoutingDecisions(ctx, tenantID, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].RequestID != "req_c" || second[0].RequestID != "req_b" || third[0].RequestID != "req_a" {
		t.Fatalf("unstable order: %s %s %s", first[0].RequestID, second[0].RequestID, third[0].RequestID)
	}
	if second[0].DecisionParseStatus != "unparseable" || second[0].RoutingDecisionJSON != nil {
		t.Fatalf("invalid JSON shape silently accepted: %#v", second[0])
	}
}
