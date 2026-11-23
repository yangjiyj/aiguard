package handler

// MCP 审计补 LSE 关联四元组落库回归：newMCPAuditRecord 从 AuthInfo 取 lse_*，
// mcpAccessUpsertArgs 把它们放在 $21-$24（末尾），使按 eval_run/task/sample/target
// 维度归并 MCP request_logs 成为可能（此前 MCP 只落 trace_id、与反代/正向链路不一致）。

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

func TestNewMCPAuditRecordCarriesLSECorrelation(t *testing.T) {
	h := &MCPProxyHandler{}
	info := &auth.AuthInfo{
		RequestID:        "req_abc",
		TenantID:         "tenant-1",
		ProjectID:        "proj-1",
		TraceID:          "task:q1",
		LSEEvalRunID:     "run-1",
		LSETaskID:        "task-1",
		LSESampleID:      "sample-1",
		LSETargetID:      "target-1",
		EnvironmentScope: "customer",
	}
	server := &mcpServerRoute{ID: "srv-1", TenantID: "tenant-1", Name: "svc", ServerURL: "https://up.example/mcp"}
	r := httptest.NewRequest("POST", "/mcp/srv-1", nil)

	record := h.newMCPAuditRecord(info, server, r, 10, 20, "success", 200, 0)
	if record.LSEEvalRunID != "run-1" || record.LSETaskID != "task-1" ||
		record.LSESampleID != "sample-1" || record.LSETargetID != "target-1" {
		t.Fatalf("LSE four-tuple not copied from AuthInfo: %+v", record)
	}

	args := mcpAccessUpsertArgs(record)
	if len(args) != 25 {
		t.Fatalf("expected 25 upsert args ($1-$25), got %d", len(args))
	}
	// $21-$24（0-indexed 20-23）= LSE 四元组，与 mcpAccessUpsertSQL 里 trace_id 之后
	// 列位置引用的占位符对齐。
	if args[20] != "run-1" || args[21] != "task-1" || args[22] != "sample-1" || args[23] != "target-1" {
		t.Fatalf("LSE args not at positions $21-$24: %v", args[20:24])
	}
	if args[24] != "customer" {
		t.Fatalf("environment scope not carried at $25: %v", args[24])
	}
	if !strings.Contains(mcpAccessUpsertSQL, "environment_scope") {
		t.Fatal("MCP request upsert must persist environment_scope")
	}
}

func TestNewMCPAuditRecordEmptyLSEStaysEmpty(t *testing.T) {
	h := &MCPProxyHandler{}
	info := &auth.AuthInfo{RequestID: "req_x", TenantID: "tenant-1"}
	server := &mcpServerRoute{ID: "srv-1", Name: "svc", ServerURL: "https://up.example"}
	r := httptest.NewRequest("POST", "/mcp/srv-1", nil)

	args := mcpAccessUpsertArgs(h.newMCPAuditRecord(info, server, r, 0, 0, "success", 200, 0))
	// NULLIF($21,'') 保证空关联落 NULL；这里只断言参数为空串，交给 SQL NULLIF 处理。
	if args[20] != "" || args[21] != "" || args[22] != "" || args[23] != "" {
		t.Fatalf("expected empty LSE args, got %v", args[20:24])
	}
	if args[24] != "legacy-unclassified" {
		t.Fatalf("blank MCP scope must remain explicitly legacy, got %v", args[24])
	}
}
