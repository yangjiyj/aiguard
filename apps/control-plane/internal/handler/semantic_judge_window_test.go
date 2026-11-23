package handler

import (
	"strings"
	"testing"
	"time"
)

// Task 5-E: the judge's health must be judged by real traffic, not only by the
// one-shot probe. A probe that answers a greeting proves the endpoint is
// reachable; it proves nothing about long requests on a CPU-bound judge.

func TestSemanticJudgeWindowVerdictIgnoresThinSamples(t *testing.T) {
	cases := []struct {
		name                          string
		attempts, successes, timeouts int
		wantReason                    string
	}{
		{"no traffic leaves the probe in charge", 0, 0, 0, ""},
		{"one failure is not a rate", 1, 0, 1, ""},
		{"four failures are not a rate", 4, 0, 4, ""},
		{"healthy window", 20, 19, 0, ""},
		{"exactly at the floor is healthy", 20, 19, 1, ""},
		{"legacy 20 percent is degraded", 10, 2, 8, "judge_timeouts"},
		{"94 percent is degraded", 100, 94, 6, "judge_timeouts"},
		{"below the floor, timeouts dominate", 10, 1, 8, "judge_timeouts"},
		{"below the floor, other failures dominate", 10, 1, 1, "judge_failures"},
		{"total failure is attributed to timeouts", 5, 0, 5, "judge_timeouts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ratio, reason := semanticJudgeWindowVerdict(tc.attempts, tc.successes, tc.timeouts)
			if reason != tc.wantReason {
				t.Fatalf("reason=%q want %q", reason, tc.wantReason)
			}
			if tc.attempts == 0 {
				if ratio != 0 {
					t.Fatalf("ratio should be unset with no traffic, got %v", ratio)
				}
				return
			}
			if want := float64(tc.successes) / float64(tc.attempts); ratio != want {
				t.Fatalf("ratio=%v want %v", ratio, want)
			}
		})
	}
}

func TestSemanticJudgeWindowOverridesAHealthyProbe(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	now := time.Now().UTC()
	desired := semanticDesiredRevisions{
		Engine:              strings.Repeat("a", semanticRevisionHexLength),
		Gateway:             strings.Repeat("b", semanticRevisionHexLength),
		EngineJudgeRequired: true,
	}
	for _, report := range []semanticRuntimeReport{
		{
			Component: semanticEngineComponent, NodeID: "engine-1",
			AppliedRevision: desired.Engine, HeldRevision: desired.Engine,
			ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(true),
			// The probe succeeded: the judge answered a short greeting in time.
			JudgeOperational: semanticBoolPtr(true),
			// Real traffic did not: 10 attempts, 1 success, 8 timeouts.
			JudgeWindowAttempts: 10, JudgeWindowSuccesses: 1, JudgeWindowTimeouts: 8,
			JudgeP50LatencyMS: 8000, ReportedAt: now,
		},
		{
			Component: semanticGatewayComponent, NodeID: "gateway-1",
			AppliedRevision: desired.Gateway, HeldRevision: desired.Gateway,
			ConfigLoaded: semanticBoolPtr(true), ReportedAt: now,
		},
	} {
		if err := recordSemanticRuntime(report, now); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	status := buildSemanticRuntimeStatus(desired, now)

	if status.RuntimeVerified || status.Status != semanticRuntimeStatusDegraded {
		t.Fatalf("a passing probe with failing real traffic must not verify: %+v", status)
	}
	engine := semanticComponentStatusByName(t, status, semanticEngineComponent)
	if engine.LastError != "judge_timeouts" {
		t.Fatalf("the degraded reason must name the window failure, got %q", engine.LastError)
	}
	if engine.JudgeSuccessRatio != 0.1 {
		t.Fatalf("the windowed success ratio must be exposed, got %v", engine.JudgeSuccessRatio)
	}
	if len(engine.Nodes) != 1 {
		t.Fatalf("expected one engine node, got %d", len(engine.Nodes))
	}
	node := engine.Nodes[0]
	if node.DegradedReason != "judge_timeouts" || node.JudgeSuccessRatio != 0.1 {
		t.Fatalf("the node must carry the ratio and its reason: %+v", node)
	}
	if node.JudgeWindowAttempts != 10 || node.JudgeWindowTimeouts != 8 {
		t.Fatalf("the raw window counts must survive so n is observable: %+v", node)
	}
}

func TestSemanticJudgeWindowWithThinSamplesDoesNotDegrade(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	now := time.Now().UTC()
	desired := semanticDesiredRevisions{
		Engine:              strings.Repeat("a", semanticRevisionHexLength),
		Gateway:             strings.Repeat("b", semanticRevisionHexLength),
		EngineJudgeRequired: true,
	}
	for _, report := range []semanticRuntimeReport{
		{
			Component: semanticEngineComponent, NodeID: "engine-1",
			AppliedRevision: desired.Engine, HeldRevision: desired.Engine,
			ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(true),
			JudgeOperational: semanticBoolPtr(true),
			// A single timeout is noise, not a rate: it must not cry wolf.
			JudgeWindowAttempts: 1, JudgeWindowSuccesses: 0, JudgeWindowTimeouts: 1,
			ReportedAt: now,
		},
		{
			Component: semanticGatewayComponent, NodeID: "gateway-1",
			AppliedRevision: desired.Gateway, HeldRevision: desired.Gateway,
			ConfigLoaded: semanticBoolPtr(true), ReportedAt: now,
		},
	} {
		if err := recordSemanticRuntime(report, now); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	status := buildSemanticRuntimeStatus(desired, now)

	if !status.RuntimeVerified || status.Status != semanticRuntimeStatusApplied {
		t.Fatalf("a single-sample window must not block verification: %+v", status)
	}
}

func TestSemanticJudgeWindowIgnoredWhenJudgeIsNotRequired(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	now := time.Now().UTC()
	desired := semanticDesiredRevisions{
		Engine:              strings.Repeat("a", semanticRevisionHexLength),
		Gateway:             strings.Repeat("b", semanticRevisionHexLength),
		EngineJudgeRequired: false,
	}
	for _, report := range []semanticRuntimeReport{
		{
			Component: semanticEngineComponent, NodeID: "engine-1",
			AppliedRevision: desired.Engine, HeldRevision: desired.Engine,
			ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(false),
			JudgeOperational: semanticBoolPtr(false),
			// Judge off: a bad window is not a degradation of anything.
			JudgeWindowAttempts: 10, JudgeWindowSuccesses: 0, JudgeWindowTimeouts: 10,
			ReportedAt: now,
		},
		{
			Component: semanticGatewayComponent, NodeID: "gateway-1",
			AppliedRevision: desired.Gateway, HeldRevision: desired.Gateway,
			ConfigLoaded: semanticBoolPtr(true), ReportedAt: now,
		},
	} {
		if err := recordSemanticRuntime(report, now); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	status := buildSemanticRuntimeStatus(desired, now)

	if !status.RuntimeVerified || status.Status != semanticRuntimeStatusApplied {
		t.Fatalf("with the judge disabled a bad window must not degrade: %+v", status)
	}
}
