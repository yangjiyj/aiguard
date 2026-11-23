package handler

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 合流矩阵前置验证（2A + 2B）：2A 的病态清单里会走 ParseRejected 兜底的输入，在合流后的网关上按
// agent.parse_rejected 的配置处置（接线在 2B；2A 单独时这项不读配置）。record / alert_allow / block
// 三档结果互不相同，防护项字段（ProtectionItem、ProtectionAction）非空且与配置一致。
func TestParseRejectedFollowsProtectionItemOnPathologicalInputs2922(t *testing.T) {
	_, pathological := loadR2922ShellCases(t)
	inputs := map[string]string{
		"rm 加 12000 个花括号":   "rm -rf " + strings.Repeat("{a,b}", 12000),
		"64KB 之后的 rm -rf /": "echo " + strings.Repeat("a", 70<<10) + "; rm -rf /",
	}
	for _, p := range pathological {
		inputs[p[0]] = p[1]
	}
	policyWith := func(action protection.Action) *agentguard.EffectivePolicy {
		return &agentguard.EffectivePolicy{ID: "r2922-matrix", Mode: agentguard.ModeStrict, DefaultAction: agentguard.DecisionAllow,
			RuleMode: agentguard.ModeStrict, Protections: protection.Settings{protection.KeyParseRejected: {Action: action}}}
	}
	type outcome struct {
		decision    agentguard.DecisionAction
		notify      bool
		parseAction string
	}
	parseHit := func(d agentguard.Decision) (agentguard.ProtectionHit, bool) {
		for _, hit := range d.ProtectionHits {
			if hit.Reason == protection.ReasonParseRejected {
				return hit, true
			}
		}
		return agentguard.ProtectionHit{}, false
	}
	covered := 0
	for name, command := range inputs {
		c := r2922Bash("matrix", r2922M, command)
		probe, _ := r2922Evaluate(c, policyWith(protection.ActionBlock))
		if _, ok := parseHit(probe); !ok {
			continue // 这条病态输入没有破坏性信号，记为“解析不完整但没有信号”，不归 agent.parse_rejected
		}
		covered++
		only := len(probe.ProtectionHits) == 1
		got := map[protection.Action]outcome{}
		for _, action := range []protection.Action{protection.ActionRecord, protection.ActionAlertAllow, protection.ActionBlock} {
			d, _ := r2922Evaluate(c, policyWith(action))
			hit, ok := parseHit(d)
			if !ok || hit.Action != string(action) || d.ProtectionItem == "" || d.ProtectionAction == "" {
				t.Errorf("%s/%s: protection fields hit=%+v item=%q action=%q", name, action, hit, d.ProtectionItem, d.ProtectionAction)
			}
			// 只命中这一项时，决定处置的就是它；同时命中别的项（如 SSH 私钥）时由最严的一项决定。
			if only && (d.ProtectionItem != protection.KeyParseRejected || d.ProtectionAction != string(action)) {
				t.Errorf("%s/%s: deciding item=%q action=%q", name, action, d.ProtectionItem, d.ProtectionAction)
			}
			got[action] = outcome{d.EffectiveDecision, d.NotificationRequired, hit.Action}
		}
		if got[protection.ActionBlock].decision != agentguard.DecisionBlock {
			t.Errorf("%s: block must block, got %+v", name, got[protection.ActionBlock])
		}
		for _, action := range []protection.Action{protection.ActionRecord, protection.ActionAlertAllow} {
			if got[action].decision == agentguard.DecisionBlock || got[action].decision == agentguard.DecisionConfirm {
				t.Errorf("%s/%s must not block, got %+v", name, action, got[action])
			}
		}
		if got[protection.ActionRecord] == got[protection.ActionAlertAllow] || got[protection.ActionRecord] == got[protection.ActionBlock] || got[protection.ActionAlertAllow] == got[protection.ActionBlock] {
			t.Errorf("%s: record / alert_allow / block must differ: %+v", name, got)
		}
		if only && (!got[protection.ActionAlertAllow].notify || got[protection.ActionRecord].notify) {
			t.Errorf("%s: alert_allow alerts, record only records: %+v", name, got)
		}
	}
	if covered < 2 {
		t.Fatalf("only %d inputs reached agent.parse_rejected; the matrix needs the pathological list to exercise it", covered)
	}
	t.Logf("%d inputs reached agent.parse_rejected", covered)
}
