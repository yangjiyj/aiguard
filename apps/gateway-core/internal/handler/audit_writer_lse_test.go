package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestRealAuditWriterEnsureRequestLogPersistsLSECorrelation(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}

	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req-lse",
		TenantID:     "tenant-lse",
		ProjectID:    "project-lse",
		UserID:       "user-lse",
		ClientID:     "key-lse",
		TraceID:      "trace-1",
		LSEEvalRunID: "eval-1",
		LSETaskID:    "task-1",
		LSESampleID:  "sample-1",
		LSETargetID:  "target-1",
	}

	writer.EnsureRequestLog(context.Background(), envelope)

	if mockDB.execCalls != 1 {
		t.Fatalf("expected 1 DB Exec call, got %d", mockDB.execCalls)
	}
	query := mockDB.queries[0]
	for _, column := range []string{"trace_id", "lse_eval_run_id", "lse_task_id", "lse_sample_id", "lse_target_id"} {
		if !strings.Contains(query, column) {
			t.Fatalf("EnsureRequestLog query should include %s, query was: %s", column, query)
		}
	}
	for _, want := range []string{"trace-1", "eval-1", "task-1", "sample-1", "target-1"} {
		if !argsContainString(mockDB.args[0], want) {
			t.Fatalf("EnsureRequestLog args should contain %q, args were %#v", want, mockDB.args[0])
		}
	}
}

func TestRealAuditWriterFinalizeRequestLogPersistsLSECorrelation(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}

	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req-lse-final",
		TenantID:     "tenant-lse",
		ProjectID:    "project-lse",
		UserID:       "user-lse",
		ProviderID:   "provider-lse",
		ModelID:      "model-lse",
		TraceID:      "trace-final",
		LSEEvalRunID: "eval-final",
		LSETaskID:    "task-final",
		LSESampleID:  "sample-final",
		LSETargetID:  "target-final",
	}

	writer.FinalizeRequestLog(context.Background(), envelope, nil, "completed", 200, 15, nil)

	if mockDB.execCalls != 1 {
		t.Fatalf("expected 1 DB Exec call, got %d", mockDB.execCalls)
	}
	query := mockDB.queries[0]
	for _, column := range []string{"trace_id", "lse_eval_run_id", "lse_task_id", "lse_sample_id", "lse_target_id"} {
		if !strings.Contains(query, column) {
			t.Fatalf("FinalizeRequestLog query should include %s, query was: %s", column, query)
		}
	}
	for _, want := range []string{"trace-final", "eval-final", "task-final", "sample-final", "target-final"} {
		if !argsContainString(mockDB.args[0], want) {
			t.Fatalf("FinalizeRequestLog args should contain %q, args were %#v", want, mockDB.args[0])
		}
	}
}

func argsContainString(args []interface{}, want string) bool {
	for _, arg := range args {
		if got, ok := arg.(string); ok && got == want {
			return true
		}
	}
	return false
}
