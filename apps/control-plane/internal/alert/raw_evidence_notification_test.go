package alert

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 用户 11-17 定：邮件、Webhook 外发的告警正文带命中原文。桥接把安全事件摘要（matched）和主命中
// （primary_finding）原样放进外发正文，原文入库后外发正文里就有原文；群机器人只取带中文标签的字段。
func TestSecEventNotificationBodyCarriesRawEvidence(t *testing.T) {
	raw := "AKIAIOSFODNN7EXAMPLE"
	ev := secEventWithFindings("raw-notify", "block", map[string]any{
		"type": "secret", "category": "cloud_credential", "severity": "critical", "confidence": 1.0,
		"rule_name": "云凭据", "raw_evidence": raw, "evidence_context": "export AWS_ACCESS_KEY_ID=" + raw + " # deploy",
		"raw_evidence_sha256": "ab", "redacted_evidence": "AK****LE",
	})
	notifier := &fakeNotifier{}
	if _, err := gateBridge(&fakeSecEventSource{events: []*repository.SecurityEvent{ev}}, &fakePusher{}, notifier, 0.5).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notifier.calls != 1 {
		t.Fatalf("应外发一次: %d", notifier.calls)
	}
	primary, _ := notifier.lastBody["primary_finding"].(map[string]any)
	matched, _ := notifier.lastBody["matched"].(map[string]any)
	findings, _ := matched["findings"].([]any)
	if primary["raw_evidence"] != raw || len(findings) != 1 || findings[0].(map[string]any)["evidence_context"] != "export AWS_ACCESS_KEY_ID="+raw+" # deploy" {
		t.Fatalf("外发正文应带命中原文和前后文: %#v", notifier.lastBody)
	}
}

type rawCapturingPusher struct{ bodies []map[string]any }

func (p *rawCapturingPusher) Push(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL string) error {
	p.bodies = append(p.bodies, body)
	return nil
}

func (p *rawCapturingPusher) UpsertByGroup(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, groupKey string) (bool, error) {
	p.bodies = append(p.bodies, body)
	return true, nil
}

// 告警组、收件箱库里的正文不再存原文（原文只在 security_events 存一份，收件箱看原文按权限从事件取）；
// 邮件、Webhook 外发正文仍带原文（用户已定），从事件摘要组装。
func TestAlertGroupAndInboxBodiesDropRawButNotificationKeepsIt(t *testing.T) {
	raw := "AKIAIOSFODNN7EXAMPLE"
	ev := secEventWithFindings("raw-store", "block", map[string]any{
		"type": "secret", "category": "cloud_credential", "severity": "critical", "confidence": 1.0,
		"rule_name": "云凭据", "raw_evidence": raw, "evidence_context": "export AWS_ACCESS_KEY_ID=" + raw + " # deploy",
		"raw_evidence_sha256": "ab", "redacted_evidence": "AK****LE",
	})
	for _, dedup := range []bool{true, false} {
		groups, inbox, notifier := &fakeAlertGrouper{}, &rawCapturingPusher{}, &fakeNotifier{}
		bridge := gateBridge(&fakeSecEventSource{events: []*repository.SecurityEvent{ev}}, inbox, notifier, 0.5).WithAlertGroups(groups)
		bridge.dedup = dedup
		if _, err := bridge.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(groups.inputs) != 1 || len(inbox.bodies) != 1 || notifier.calls != 1 {
			t.Fatalf("dedup=%v: 组 %d、收件箱 %d、外发 %d", dedup, len(groups.inputs), len(inbox.bodies), notifier.calls)
		}
		for name, body := range map[string]map[string]any{"告警组": groups.inputs[0].BodyJSON, "收件箱": inbox.bodies[0]} {
			encoded, _ := json.Marshal(body)
			if strings.Contains(string(encoded), raw) || strings.Contains(string(encoded), `"evidence_context"`) {
				t.Fatalf("dedup=%v %s正文不应存原文: %s", dedup, name, encoded)
			}
			if !strings.Contains(string(encoded), "AK****LE") || !strings.Contains(string(encoded), `"event_id":"raw-store"`) {
				t.Fatalf("dedup=%v %s正文其余字段照旧: %s", dedup, name, encoded)
			}
		}
		sent, _ := json.Marshal(notifier.lastBody)
		if !strings.Contains(string(sent), `"raw_evidence":"`+raw+`"`) || !strings.Contains(string(sent), "export AWS_ACCESS_KEY_ID="+raw) {
			t.Fatalf("dedup=%v 外发正文应带原文和前后文: %s", dedup, sent)
		}
	}
	if ev.MatchedSummary["findings"].([]any)[0].(map[string]any)["raw_evidence"] != raw {
		t.Fatal("剔除不改事件本身")
	}
}

// 事件带 primary_finding.findings_index 时，告警正文与外发的主命中直接按它取（与网关选出的主命中一致），
// 不再由控制面另按严重度重选；没有引用的旧事件照旧重选。
func TestAlertBodyPrimaryFindingFollowsFindingsIndex(t *testing.T) {
	low := map[string]any{"type": "pii", "category": "pii_phone", "severity": "low", "confidence": 1.0, "rule_id": "r_low", "raw_evidence": "13800000000"}
	critical := map[string]any{"type": "secret", "category": "openai_key", "severity": "critical", "confidence": 1.0, "rule_id": "r_critical"}
	ev := secEventWithFindings("indexed", "block", low, critical)
	ev.MatchedSummary["primary_finding"] = map[string]any{"type": "pii", "category": "pii_phone", "rule_id": "r_low", "findings_index": float64(0)}
	legacy := secEventWithFindings("legacy", "block", low, critical)
	for _, tc := range []struct {
		ev   *repository.SecurityEvent
		want string
	}{{ev, "r_low"}, {legacy, "r_critical"}} {
		notifier := &fakeNotifier{}
		if _, err := gateBridge(&fakeSecEventSource{events: []*repository.SecurityEvent{tc.ev}}, &fakePusher{}, notifier, 0.5).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		primary, _ := notifier.lastBody["primary_finding"].(map[string]any)
		if primary["rule_id"] != tc.want || notifier.lastBody["rule_id"] != tc.want {
			t.Fatalf("%s: 主命中应为 %s: %#v", tc.ev.ID, tc.want, notifier.lastBody)
		}
	}
	if dominantFinding(ev)["raw_evidence"] != "13800000000" {
		t.Fatal("按引用取到的是 findings 里的原条目（带原文），不是 primary_finding 的引用壳")
	}
}
