package handler

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/endpointpolicy"
)

// 复审次要项：只有注册表端侧组的防护项是端侧内置规则；策略包里规则 ID 碰巧等于别的防护项原因码
// （如 restricted_file_pattern）的规则仍是管理员配置的显式规则。
func TestEndpointBundleHits2922OnlyEndpointGroupIsBuiltin(t *testing.T) {
	d := agentguard.Decision{RawDecision: agentguard.DecisionAllow, RiskLevel: "low"}
	evaluation := endpointpolicy.Evaluation{
		Hits: []endpointpolicy.Hit{
			{RuleID: "builtin_env_files", Decision: "audit", Risk: "high"},
			{RuleID: "restricted_file_pattern", Decision: "block", Risk: "high"},
		},
		Hit: endpointpolicy.Hit{RuleID: "restricted_file_pattern", Decision: "block", Risk: "high"}, Matched: true,
	}
	explicit, reported := mergeEndpointBundleHits(&d, evaluation, "/repo/.env", agentguard.DecisionAllow)
	if len(d.ProtectionHits) != 1 || d.ProtectionHits[0].Reason != "builtin_env_files" {
		t.Fatalf("only endpoint-group items are builtin protection hits: %+v", d.ProtectionHits)
	}
	if explicit == nil || explicit.RuleID != "restricted_file_pattern" || reported != agentguard.DecisionBlock || d.MatchedRuleID != "restricted_file_pattern" {
		t.Fatalf("a bundle rule outside the endpoint group is an explicit rule: explicit=%+v reported=%s d=%+v", explicit, reported, d)
	}
}

// 复审次要项：T13 授权拒绝单独成函数，只看端点（授权）模式。
func TestEndpointT13Denial2922(t *testing.T) {
	for _, tc := range []struct {
		mode agentguard.Mode
		want agentguard.DecisionAction
	}{{agentguard.ModeStrict, agentguard.DecisionBlock}, {agentguard.ModeObserve, agentguard.DecisionAudit}} {
		d := agentguard.Decision{EffectiveDecision: agentguard.DecisionAllow, RiskLevel: "low"}
		reported := applyEndpointT13Denial(&d, agentguard.DecisionAllow, tc.mode)
		if reported != agentguard.DecisionBlock || d.EffectiveDecision != tc.want || d.Reason != "t13_authorization_denied" || d.RiskLevel != "high" {
			t.Fatalf("mode %s: reported=%s d=%+v", tc.mode, reported, d)
		}
	}
}

// 复审次要项：取不到租户策略的日志每个租户每分钟一条。
func TestEndpointTenantPolicy2922UnavailableLogIsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	now := time.Unix(1_700_000_000, 0)
	g := &AgentEndpointGateway{resolveNow: func() time.Time { return now }}
	err := errors.New("control plane down")
	g.logTenantPolicyUnavailable("t1", err)
	g.logTenantPolicyUnavailable("t1", err)
	g.logTenantPolicyUnavailable("t2", err)
	now = now.Add(30 * time.Second)
	g.logTenantPolicyUnavailable("t1", err)
	if got := strings.Count(buf.String(), "tenant AgentGuard policy unavailable"); got != 2 {
		t.Fatalf("one line per tenant per minute, got %d:\n%s", got, buf.String())
	}
	now = now.Add(31 * time.Second)
	g.logTenantPolicyUnavailable("t1", err)
	if got := strings.Count(buf.String(), "tenant AgentGuard policy unavailable"); got != 3 {
		t.Fatalf("a minute later the tenant logs again, got %d", got)
	}
}
