package agentguard

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type toolCallFixture struct {
	Name             string             `json:"name"`
	ToolName         string             `json:"tool_name"`
	ToolType         string             `json:"tool_type"`
	Arguments        map[string]any     `json:"arguments"`
	Fragments        []ContextFragment  `json:"fragments"`
	Mode             Mode               `json:"mode"`
	AllowedDomains   []string           `json:"allowed_domains"`
	CommandAllowlist []CommandAllowRule `json:"command_allowlist"`
	WantRaw          DecisionAction     `json:"want_raw"`
	WantEffective    DecisionAction     `json:"want_effective"`
}

func TestRedteamToolCallFixtures(t *testing.T) {
	fixtures := loadToolCallFixtures(t, "redteam_tool_calls.json")
	if len(fixtures) < 5 {
		t.Fatalf("expected at least five redteam fixtures, got %d", len(fixtures))
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			input := ToolCallAnalysisInput{
				ToolName:         fixture.ToolName,
				ToolType:         fixture.ToolType,
				Arguments:        fixture.Arguments,
				ContextFragments: fixture.Fragments,
				Mode:             fixture.Mode,
				AllowedDomains:   fixture.AllowedDomains,
				CommandAllowlist: fixture.CommandAllowlist,
				// 2.9.22：fixture 的期望是“防护项与未配置规则的高风险调用配成阻断”时的结果。
				Policy: highRiskBlockingPolicy(),
			}
			decision := AnalyzeToolCall(context.Background(), input)
			if decision.RawDecision != fixture.WantRaw || decision.EffectiveDecision != fixture.WantEffective {
				t.Fatalf("decision = raw:%s effective:%s, want raw:%s effective:%s (%#v)", decision.RawDecision, decision.EffectiveDecision, fixture.WantRaw, fixture.WantEffective, decision)
			}
			// 默认配置（告警放行）下同一 fixture 只审计；配置后判阻断的（防护项或高风险兜底）默认要告警。
			input.Policy = nil
			if byDefault := AnalyzeToolCall(context.Background(), input); byDefault.EffectiveDecision != DecisionAudit ||
				byDefault.NotificationRequired != (fixture.WantRaw == DecisionBlock) {
				t.Fatalf("default settings must audit (and alert when configured to block): %#v", byDefault)
			}
		})
	}
}

func TestBenignToolCallFixturesDoNotBlock(t *testing.T) {
	fixtures := loadToolCallFixtures(t, "benign_tool_calls.json")
	if len(fixtures) < 5 {
		t.Fatalf("expected at least five benign fixtures, got %d", len(fixtures))
	}
	blocked := 0
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
				ToolName:         fixture.ToolName,
				ToolType:         fixture.ToolType,
				Arguments:        fixture.Arguments,
				ContextFragments: fixture.Fragments,
				Mode:             fixture.Mode,
				AllowedDomains:   fixture.AllowedDomains,
				CommandAllowlist: fixture.CommandAllowlist,
			})
			if decision.EffectiveDecision == DecisionBlock {
				blocked++
				t.Fatalf("benign fixture blocked: %#v", decision)
			}
			if fixture.WantRaw != "" && decision.RawDecision != fixture.WantRaw {
				t.Fatalf("raw decision = %s, want %s", decision.RawDecision, fixture.WantRaw)
			}
			if fixture.WantEffective != "" && decision.EffectiveDecision != fixture.WantEffective {
				t.Fatalf("effective decision = %s, want %s", decision.EffectiveDecision, fixture.WantEffective)
			}
		})
	}
	if blocked != 0 {
		t.Fatalf("benign blocked count = %d, want 0", blocked)
	}
}

func loadToolCallFixtures(t *testing.T, name string) []toolCallFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	body = bytes.ReplaceAll(body, []byte("${AWS_ACCESS_KEY_ID_EXAMPLE}"), []byte(testAWSAccessKeyID()))
	var fixtures []toolCallFixture
	if err := json.Unmarshal(body, &fixtures); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return fixtures
}
