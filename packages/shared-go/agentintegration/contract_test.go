package agentintegration

import (
	"testing"
	"time"
)

func TestEnforcementStatusRequiresEveryRegisteredAndExpectedGateway(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	p := Policy{ID: "p1", AgentInstanceID: "agent1", Enabled: true, Mode: "protect", Version: "2"}
	nodes := []Instance{{InstanceID: "gw1", BootID: "boot1", Mode: "protect", LastSeenAt: now}}
	receipts := []Receipt{{InstanceID: "gw1", BootID: "boot1", LoadedVersion: "2", LoadedAt: &now, BlockedCount: 1}}
	cases := []struct {
		name     string
		nodes    []Instance
		receipts []Receipt
		roster   []string
		version  string
		hit      bool
		status   string
		verified bool
	}{
		{"success", nodes, receipts, nil, "2", true, "applied", true},
		{"zero_instances", nil, nil, nil, "2", false, "pending", false},
		{"missing_expected", nodes, receipts, []string{"gw1", "gw2"}, "2", false, "pending", false},
		{"registered_not_loaded", append(append([]Instance{}, nodes...), Instance{InstanceID: "gw2", BootID: "boot2", Mode: "protect", LastSeenAt: now}), receipts, nil, "2", false, "pending", false},
		{"version_mismatch", nodes, receipts, nil, "1", false, "version_mismatch", false},
		{"restart", []Instance{{InstanceID: "gw1", BootID: "boot-new", Mode: "protect", LastSeenAt: now}}, receipts, nil, "2", false, "pending", false},
		{"stale", []Instance{{InstanceID: "gw1", BootID: "boot1", Mode: "protect", LastSeenAt: now.Add(-Freshness - time.Second)}}, receipts, nil, "2", false, "stale", false},
		// 心跳降频到 HeartbeatInterval 后，刚好错过一次心跳（年龄 = 一个间隔）的网关仍必须判为在线。
		{"heartbeat_age_one_interval_still_fresh", []Instance{{InstanceID: "gw1", BootID: "boot1", Mode: "protect", LastSeenAt: now.Add(-HeartbeatInterval)}}, receipts, nil, "2", false, "applied", true},
		// 连续错过一次心跳（年龄 = 两个间隔，含写入抖动）仍在线。
		{"heartbeat_age_two_intervals_still_fresh", []Instance{{InstanceID: "gw1", BootID: "boot1", Mode: "protect", LastSeenAt: now.Add(-2 * HeartbeatInterval)}}, receipts, nil, "2", false, "applied", true},
		{"record_mode", []Instance{{InstanceID: "gw1", BootID: "boot1", Mode: "record", LastSeenAt: now}}, receipts, nil, "2", false, "record_only", false},
		{"hit_required", nodes, []Receipt{{InstanceID: "gw1", BootID: "boot1", LoadedVersion: "2", LoadedAt: &now}}, nil, "2", true, "waiting_for_hit", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateStatus(p, tc.nodes, tc.receipts, tc.roster, tc.version, tc.hit, now)
			if got.Status != tc.status || got.EnforcementVerified != tc.verified {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestIdentifierAndUpstreamProjectionExcludeUntrustedValues(t *testing.T) {
	for _, bad := range []string{"", " agent", "agent/foreign", "agent\nheader"} {
		if ValidID(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if got := SafeURL("https://username:password@example.test/v1?api_key=secret#token"); got != "https://example.test/v1" {
		t.Fatal(got)
	}
	if SafeURL("file:///tmp/example") != "" {
		t.Fatal("accepted file URL")
	}
}

func TestUpdatedPolicyCannotReuseEarlierVersionHits(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	p := Policy{ID: "policy1", AgentInstanceID: "agent1", Enabled: true, Mode: "protect", Version: "2"}
	nodes := []Instance{{InstanceID: "gateway1", BootID: "boot1", Mode: "protect", LastSeenAt: now}}
	old := Receipt{InstanceID: "gateway1", BootID: "boot1", LoadedVersion: "1", LoadedAt: &now, HitCount: 20, BlockedCount: 20}
	if got := EvaluateStatus(p, nodes, []Receipt{old}, nil, "2", true, now); got.EnforcementVerified || got.Status != "version_mismatch" {
		t.Fatalf("old hits reused: %+v", got)
	}
	current := old
	current.LoadedVersion = "2"
	current.HitCount, current.BlockedCount = 0, 0
	if got := EvaluateStatus(p, nodes, []Receipt{current}, nil, "2", true, now); got.EnforcementVerified || got.Status != "waiting_for_hit" {
		t.Fatalf("new version must await own hit: %+v", got)
	}
	current.HitCount, current.BlockedCount = 1, 1
	if got := EvaluateStatus(p, nodes, []Receipt{current}, nil, "2", true, now); !got.EnforcementVerified {
		t.Fatalf("new blocked evidence rejected: %+v", got)
	}
}

// 阈值约束：状态页的在线判定窗口必须大于心跳写入间隔的 2 倍以上，
// 否则一次心跳写入失败/延迟（现场磁盘偶发卡顿几十秒）就会把健康网关误判为 stale。
func TestFreshnessWindowIsAtLeastTwiceTheHeartbeatInterval(t *testing.T) {
	if Freshness < 2*HeartbeatInterval {
		t.Fatalf("Freshness=%s must be >= 2*HeartbeatInterval(%s)", Freshness, HeartbeatInterval)
	}
	if HeartbeatInterval < 10*time.Second {
		t.Fatalf("HeartbeatInterval=%s: 心跳写入不应比 10 秒更频繁（每台网关每天不应超过 8640 次写）", HeartbeatInterval)
	}
}
