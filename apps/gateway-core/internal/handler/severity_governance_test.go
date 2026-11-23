package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"testing"
)

func TestStructuredGatePreservesSQLAndCommandImpact(t *testing.T) {
	for _, tc := range []struct{ typ, tool, field, value, risk string }{
		{"database", "execute_sql", "query", "ALTER TABLE demo ADD COLUMN note TEXT", "high"},
		{"database", "execute_sql", "query", "WITH x AS (DELETE FROM demo RETURNING *) SELECT * FROM x", "high"},
		{"database", "execute_sql", "query", "EXPLAIN ANALYZE DELETE FROM demo", "high"},
		{"database", "execute_sql", "query", "DROP DATABASE demo", "critical"},
		{"system", "run_shell", "command", "rm -rf /srv/build-cache", "high"},
		// 客户A 11-21：只删临时目录降为中危（处置仍按策略）。
		{"system", "run_shell", "command", "rm -rf /tmp/build-cache", "medium"},
		{"system", "run_shell", "command", "rm -rf /", "critical"},
	} {
		args := map[string]any{tc.field: tc.value, "dialect": "postgres"}
		base := agentguard.AnalyzeToolCall(context.Background(), agentguard.ToolCallAnalysisInput{ToolName: tc.tool, ToolType: tc.typ, Arguments: args, Mode: agentguard.ModeAudit})
		got := evaluateStructuredToolCall(structuredToolCallInput{ToolName: tc.tool, ToolType: tc.typ, Arguments: args, Mode: agentguard.ModeAudit, AgentType: "openai-codex", BaseDecision: base})
		if got.Decision.RiskLevel != tc.risk || got.Decision.EffectiveDecision != agentguard.DecisionAudit {
			t.Fatalf("%s: %+v", tc.value, got.Decision)
		}
	}
}
