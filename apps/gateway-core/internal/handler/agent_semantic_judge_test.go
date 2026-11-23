package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type fakeSemanticChecker struct {
	findings []SecurityFinding
	err      error
	gotRole  string
	gotStage string
}

func (f *fakeSemanticChecker) CheckInput(ctx context.Context, env *modelrouter.RequestEnvelope, content string, idx int, role string, contentSource string) (string, string, []SecurityFinding, error) {
	f.gotRole = role
	if f.err != nil {
		return "", "", nil, f.err
	}
	return "audit", content, f.findings, nil
}

func (f *fakeSemanticChecker) CheckOutput(ctx context.Context, env *modelrouter.RequestEnvelope, content string, idx int) (string, string, []SecurityFinding, error) {
	return "allow", content, nil, nil
}

func (f *fakeSemanticChecker) CheckSemanticOnly(ctx context.Context, env *modelrouter.RequestEnvelope, content string) ([]SecurityFinding, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.findings, nil
}

func (f *fakeSemanticChecker) CheckSemanticStage(ctx context.Context, env *modelrouter.RequestEnvelope, content string, stage string) ([]SecurityFinding, error) {
	f.gotStage = stage
	if f.err != nil {
		return nil, f.err
	}
	return f.findings, nil
}

func (f *fakeSemanticChecker) CheckTriage(ctx context.Context, env *modelrouter.RequestEnvelope, content string, findings []SecurityFinding) ([]SecurityFinding, error) {
	return findings, nil
}

func TestAgentSemanticJudgeMapsMaliciousToAudit(t *testing.T) {
	checker := &fakeSemanticChecker{findings: []SecurityFinding{
		{Type: "semantic_attack", Category: "semantic_jailbreak", Severity: "high", Confidence: 0.9, MatchedTextPreview: "semantic_jailbreak|input"},
	}}
	judge := agentSemanticJudge{checker: checker, envelope: &modelrouter.RequestEnvelope{RequestID: "r1"}}
	d, err := judge.Judge(context.Background(), "http_get", map[string]any{"url": "https://x/y"})
	if err != nil {
		t.Fatalf("judge should fail-open, got err %v", err)
	}
	if checker.gotStage != "agent" {
		t.Fatalf("Agent 工具调用必须显式走 semantic_stage=agent, got %q", checker.gotStage)
	}
	if d.RawDecision != agentguard.DecisionAudit {
		t.Fatalf("malicious semantic finding should map to audit, got %q", d.RawDecision)
	}
	if d.Reason != "semantic_jailbreak" {
		t.Fatalf("category should drive reason, got %q", d.Reason)
	}
}

func TestAgentSemanticJudgeIgnoresNonSemanticFindings(t *testing.T) {
	checker := &fakeSemanticChecker{findings: []SecurityFinding{
		{Type: "pii", Category: "id_card", Severity: "high", Confidence: 0.95},
	}}
	judge := agentSemanticJudge{checker: checker, envelope: &modelrouter.RequestEnvelope{}}
	d, _ := judge.Judge(context.Background(), "read_file", map[string]any{"path": "/x"})
	if d.RawDecision != agentguard.DecisionAllow {
		t.Fatalf("non-semantic findings must be ignored by the semantic judge, got %q", d.RawDecision)
	}
}

func TestAgentSemanticJudgeFailOpenOnError(t *testing.T) {
	checker := &fakeSemanticChecker{err: errors.New("engine down")}
	judge := agentSemanticJudge{checker: checker, envelope: &modelrouter.RequestEnvelope{}}
	d, err := judge.Judge(context.Background(), "http_get", map[string]any{"url": "https://x"})
	if err != nil {
		t.Fatalf("judge must swallow errors (fail-open), got %v", err)
	}
	if d.RawDecision != agentguard.DecisionAllow {
		t.Fatalf("errored judge should yield allow, got %q", d.RawDecision)
	}
}
