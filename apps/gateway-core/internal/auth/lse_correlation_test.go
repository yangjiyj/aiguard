package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestExtractLSECorrelationHeaders(t *testing.T) {
	header := http.Header{}
	header.Set("X-LSE-Eval-Run-Id", "eval_run_123")
	header.Set("X-LSE-Task-Id", "task-456")
	header.Set("X-LSE-Sample-Id", "sample_789")
	header.Set("X-LSE-Target-Id", "target-A")
	header.Set("X-LSE-Trace-Id", "trace_abc-123")

	corr := extractLSECorrelationHeaders(header)

	if corr.EvalRunID != "eval_run_123" {
		t.Fatalf("EvalRunID = %q", corr.EvalRunID)
	}
	if corr.TaskID != "task-456" {
		t.Fatalf("TaskID = %q", corr.TaskID)
	}
	if corr.SampleID != "sample_789" {
		t.Fatalf("SampleID = %q", corr.SampleID)
	}
	if corr.TargetID != "target-A" {
		t.Fatalf("TargetID = %q", corr.TargetID)
	}
	if corr.TraceID != "trace_abc-123" {
		t.Fatalf("TraceID = %q", corr.TraceID)
	}
}

func TestExtractLSECorrelationHeadersDropsInvalidValues(t *testing.T) {
	header := http.Header{}
	header.Set("X-LSE-Eval-Run-Id", "eval run with spaces")
	header.Set("X-LSE-Task-Id", "task_ok-123")
	header.Set("X-LSE-Trace-Id", strings.Repeat("a", 129))

	corr := extractLSECorrelationHeaders(header)

	if corr.EvalRunID != "" {
		t.Fatalf("invalid EvalRunID should be dropped, got %q", corr.EvalRunID)
	}
	if corr.TaskID != "task_ok-123" {
		t.Fatalf("valid TaskID should be preserved, got %q", corr.TaskID)
	}
	if corr.TraceID != "" {
		t.Fatalf("too-long TraceID should be dropped, got %q", corr.TraceID)
	}
}

func TestGetAuthInfoIncludesLSECorrelationContext(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, TraceIDKey, "trace-ctx")
	ctx = context.WithValue(ctx, LSEEvalRunIDKey, "eval-ctx")
	ctx = context.WithValue(ctx, LSETaskIDKey, "task-ctx")
	ctx = context.WithValue(ctx, LSESampleIDKey, "sample-ctx")
	ctx = context.WithValue(ctx, LSETargetIDKey, "target-ctx")
	req := (&http.Request{}).WithContext(ctx)

	info := GetAuthInfo(req)

	if info.TraceID != "trace-ctx" || info.LSEEvalRunID != "eval-ctx" || info.LSETaskID != "task-ctx" || info.LSESampleID != "sample-ctx" || info.LSETargetID != "target-ctx" {
		t.Fatalf("GetAuthInfo() did not preserve LSE correlation: %#v", info)
	}
}
