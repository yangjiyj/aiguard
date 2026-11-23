package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceHealthJudgeUsesCurrentAuthenticatedRuntime(t *testing.T) {
	for _, tc := range []struct {
		name         string
		enabled      bool
		missing      bool
		expired      bool
		pending      bool
		operational  bool
		windowFailed bool
		wantStatus   string
		wantReason   string
	}{
		{name: "current operational judge", enabled: true, operational: true, wantStatus: "healthy"},
		{name: "current disabled judge", enabled: false, wantStatus: "disabled", wantReason: "judge_not_required"},
		{name: "missing report", enabled: true, missing: true, wantStatus: "unknown", wantReason: "runtime_report_missing"},
		{name: "expired report", enabled: true, expired: true, operational: true, wantStatus: "unknown", wantReason: "runtime_report_missing"},
		{name: "configuration not applied", enabled: true, pending: true, operational: true, wantStatus: "processing", wantReason: "runtime_config_pending"},
		{name: "judge unavailable", enabled: true, wantStatus: "degraded", wantReason: "judge_unavailable"},
		{name: "real traffic overrides successful probe", enabled: true, operational: true, windowFailed: true, wantStatus: "degraded", wantReason: "judge_timeouts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSemanticRuntimeReportsForTest()
			t.Cleanup(resetSemanticRuntimeReportsForTest)
			settings := map[string]string{"semantic_enabled": "false", "judge_backend": "bundled"}
			if tc.enabled {
				settings["semantic_enabled"] = "true"
			}
			semanticDeps := semanticTestDeps(settings)
			configs, err := buildSemanticComponentConfigs(context.Background(), semanticDeps)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.missing {
				report := semanticRuntimeReport{Component: semanticEngineComponent, NodeID: "health-engine",
					AppliedRevision: configs.EngineRevision, ConfigLoaded: semanticBoolPtr(true),
					JudgeRequired: semanticBoolPtr(tc.enabled), JudgeOperational: semanticBoolPtr(tc.operational),
					ReportedAt: time.Now().UTC()}
				if tc.expired {
					report.ReportedAt = time.Now().UTC().Add(-semanticRuntimeReportTTL - time.Second)
				}
				if tc.pending {
					report.AppliedRevision = strings.Repeat("a", 32)
				}
				if tc.operational {
					report.JudgeLastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
				}
				if tc.windowFailed {
					report.JudgeWindowAttempts = 10
					report.JudgeWindowSuccesses = 1
					report.JudgeWindowTimeouts = 9
				}
				reportSemanticRuntime(report)
			}
			got := judgeComponent(context.Background(), ReadModelDeps{SemanticDeps: semanticDeps})
			if got["status"] != tc.wantStatus {
				t.Fatalf("status=%v want=%s component=%v", got["status"], tc.wantStatus, got)
			}
			if tc.wantReason != "" && got["reason_code"] != tc.wantReason {
				t.Fatalf("reason=%v want=%s", got["reason_code"], tc.wantReason)
			}
			if tc.windowFailed && got["judge_window_timeouts"] != 9 {
				t.Fatalf("lost real-traffic evidence: %v", got)
			}
		})
	}
}

func TestServiceHealthJudgeAnyFailedNodePreventsHealthy(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	deps := semanticTestDeps(map[string]string{"semantic_enabled": "true", "judge_backend": "bundled"})
	configs, err := buildSemanticComponentConfigs(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	for index, operational := range []bool{false, true} {
		reportSemanticRuntime(semanticRuntimeReport{Component: semanticEngineComponent,
			NodeID: []string{"engine-failed", "engine-healthy"}[index], AppliedRevision: configs.EngineRevision,
			ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(true), JudgeOperational: semanticBoolPtr(operational),
			ReportedAt: time.Now().UTC().Add(time.Duration(index-1) * time.Second)})
	}
	got := judgeComponent(context.Background(), ReadModelDeps{SemanticDeps: deps})
	if got["status"] != "degraded" || got["runtime_active_nodes"] != 2 {
		t.Fatalf("failed node hidden: %v", got)
	}
}

func TestServiceHealthJudgeDoesNotInvokeModelOrExposeConfiguration(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	deps := semanticTestDeps(map[string]string{"semantic_enabled": "true", "judge_backend": "custom",
		"judge_url": "https://judge.example/v1/chat/completions", "judge_model": "private-model", "judge_api_key": "private-secret"})
	configs, err := buildSemanticComponentConfigs(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	reportSemanticRuntime(semanticRuntimeReport{Component: semanticEngineComponent, NodeID: "engine-private",
		AppliedRevision: configs.EngineRevision, ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(true),
		JudgeOperational: semanticBoolPtr(true), ReportedAt: time.Now().UTC()})
	got := judgeComponent(context.Background(), ReadModelDeps{SemanticDeps: deps, SecurityEngineURL: server.URL})
	if got["status"] != "healthy" {
		t.Fatalf("runtime evidence ignored: %v", got)
	}
	if calls.Load() != 0 {
		t.Fatalf("health invoked a remote service: %d", calls.Load())
	}
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"judge.example", "private-model", "private-secret", "engine-private", server.URL} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("health exposes private configuration: %q", secret)
		}
	}
}
