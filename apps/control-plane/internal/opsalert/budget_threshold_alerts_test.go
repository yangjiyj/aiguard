package opsalert

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

type fakeClaims struct{ seen map[string]bool }

func (f *fakeClaims) claim(_ context.Context, c billing.BudgetThresholdCandidate, threshold int) (bool, error) {
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	k := c.TenantID + "|" + c.ScopeType + "|" + c.ScopeID + "|" + c.PeriodStart.Format(time.RFC3339) + "|" + fmt.Sprint(threshold)
	if f.seen[k] {
		return false, nil
	}
	f.seen[k] = true
	return true, nil
}

func ptr(v int64) *int64 { return &v }

func TestBudgetThresholdScannerNotifiesEachThresholdOncePerPeriod(t *testing.T) {
	groups, inbox, n := &fakeGroups{}, &fakeInbox{}, &fakeNotifier{}
	period := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	used := int64(800)
	load := func(_ context.Context, tenant string, _ time.Time) (billing.BudgetTreeInput, error) {
		return billing.BudgetTreeInput{TenantID: tenant, TenantName: "XX科技", Currency: "CNY", EmployeeMonthStart: period,
			Employees: []billing.BudgetTreeEmployee{{UserID: "u1", Username: "张三", EffectiveMicros: ptr(1_000_000_000), UsedMicros: used * 1_000_000}}}, nil
	}
	claims := &fakeClaims{}
	s := &BudgetThresholdScanner{emitter: NewEmitter(groups, inbox, n), tenants: func(context.Context) ([]string, error) { return []string{"t1"}, nil }, load: load, claim: claims.claim}
	now := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if _, err := s.RunOnce(context.Background(), now); err != nil {
			t.Fatal(err)
		}
	}
	if len(n.titles) != 1 || !strings.Contains(n.titles[0], "预算已用 80%") || !strings.Contains(n.titles[0], "员工 张三") || !strings.Contains(n.titles[0], "¥800.00 / ¥1,000.00") {
		t.Fatalf("80%% 只应外发一次: %v", n.titles)
	}
	used = 1000
	for i := 0; i < 2; i++ {
		if _, err := s.RunOnce(context.Background(), now); err != nil {
			t.Fatal(err)
		}
	}
	if len(n.titles) != 2 || !strings.Contains(n.titles[1], "预算已用尽 100%") {
		t.Fatalf("100%% 只应外发一次: %v", n.titles)
	}
	if inbox.types[0] != TypeBudgetThreshold80 || inbox.types[1] != TypeBudgetThreshold100 {
		t.Fatalf("inbox types = %v", inbox.types)
	}
	// 新周期重新计数
	period = period.AddDate(0, 1, 0)
	if _, err := s.RunOnce(context.Background(), now.AddDate(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	if len(n.titles) != 3 {
		t.Fatalf("新周期应再次通知: %v", n.titles)
	}
	if g := groups.inputs[0]; g.DispositionClass != "informational" || g.AlertType != TypeBudgetThreshold80 {
		t.Fatalf("80%% 预警是提示类，不进待处置: %#v", g)
	}
}

// 直接越过 100% 时只发 100%，同时把 80% 记为已发，避免回头补发 80%。
func TestBudgetThresholdScannerJumpTo100SkipsStale80(t *testing.T) {
	groups, n := &fakeGroups{}, &fakeNotifier{}
	claims := &fakeClaims{}
	used := int64(1200_000_000)
	s := &BudgetThresholdScanner{emitter: NewEmitter(groups, nil, n), tenants: func(context.Context) ([]string, error) { return []string{"t1"}, nil },
		load: func(_ context.Context, tenant string, _ time.Time) (billing.BudgetTreeInput, error) {
			return billing.BudgetTreeInput{TenantID: tenant, TenantName: "XX科技", OrganizationBudget: &billing.BudgetTreePolicy{MonthlyMicros: ptr(1000_000_000), Timezone: "Asia/Shanghai"}, OrganizationUsed: &used}, nil
		}, claim: claims.claim}
	now := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	if _, err := s.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	used = 900_000_000
	if _, err := s.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(n.titles) != 1 || !strings.Contains(n.titles[0], "组织 XX科技") || !strings.Contains(n.titles[0], "100%") {
		t.Fatalf("titles = %v", n.titles)
	}
}

func TestBudgetThresholdKindsHaveChineseLabels(t *testing.T) {
	for _, typ := range []string{TypeBudgetThreshold80, TypeBudgetThreshold100} {
		k, ok := KindOf(typ)
		if !ok || k.Label == "" || k.Suggestion == "" {
			t.Fatalf("%s kind = %#v", typ, k)
		}
	}
}
