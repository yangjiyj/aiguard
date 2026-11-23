package handler

import (
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 语义判官的类别（semantic_exfil_induce / semantic_instruction_override / semantic_roleplay）
// 必须投影成平台认可的风险因子；否则网关已检出（high），平台却因风险因子为空而不生成告警。
func TestConnectorRiskFactorsMapSemanticJudgeCategories(t *testing.T) {
	cases := map[string][]string{
		"semantic_exfil_induce":         {"data_exfiltration", "prompt_injection"},
		"semantic_instruction_override": {"prompt_injection"},
		"semantic_roleplay":             {"prompt_injection"},
	}
	for category, want := range cases {
		e := &repository.SecurityEvent{EventType: "security_check", MatchedSummary: map[string]any{"findings": []any{
			map[string]any{"type": "semantic_attack", "category": category, "counts_as_security_finding": true},
		}}}
		if got := connectorRiskFactors(e); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: factors=%v want %v", category, got, want)
		}
		if got := connectorRiskCategory(e); got == "" {
			t.Fatalf("%s: risk category must not be empty", category)
		}
	}
}

// 内容安全类语义类别（骚扰/威胁/仇恨）不属于智能体八类风险因子，保持不映射。
func TestConnectorRiskFactorsKeepContentSafetySemanticUnmapped(t *testing.T) {
	e := &repository.SecurityEvent{EventType: "security_check", MatchedSummary: map[string]any{"findings": []any{
		map[string]any{"type": "semantic_attack", "category": "semantic_harassment", "counts_as_security_finding": true},
	}}}
	if got := connectorRiskFactors(e); len(got) != 0 {
		t.Fatalf("content-safety semantic category must stay unmapped, got %v", got)
	}
}
