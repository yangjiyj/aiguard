package opsalert

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeGroups struct {
	inputs []repository.AlertGroupUpsertInput
	open   map[string]bool
}

func (f *fakeGroups) UpsertOpen(_ context.Context, in repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error) {
	if f.open == nil {
		f.open = map[string]bool{}
	}
	f.inputs = append(f.inputs, in)
	created := !f.open[in.GroupKey]
	f.open[in.GroupKey] = true
	return &repository.AlertGroup{ID: "ag_" + in.GroupKey}, created, nil
}

type fakeInbox struct{ types, urls []string }

func (f *fakeInbox) UpsertByGroup(_ context.Context, _, _, typ, _ string, _ map[string]any, url, _ string) (bool, error) {
	f.types = append(f.types, typ)
	f.urls = append(f.urls, url)
	return true, nil
}

type fakeNotifier struct{ titles []string }

func (f *fakeNotifier) Dispatch(_ context.Context, _, _, title string, _ map[string]any) error {
	f.titles = append(f.titles, title)
	return nil
}

// 同类型同作用域聚合到一个告警组，只在首次外发；不同作用域分开。
func TestEmitGroupsByTypeAndScopeAndNotifiesOnce(t *testing.T) {
	groups, inbox, n := &fakeGroups{}, &fakeInbox{}, &fakeNotifier{}
	e := NewEmitter(groups, inbox, n)
	ctx := context.Background()
	ev := Event{TenantID: "t1", Type: TypeBudgetExhausted, ScopeKey: "team:rd", ScopeLabel: "部门 研发部", OccurredAt: time.Now()}
	if created, err := e.Emit(ctx, ev); err != nil || !created {
		t.Fatalf("first emit created=%v err=%v", created, err)
	}
	if created, err := e.Emit(ctx, ev); err != nil || created {
		t.Fatalf("repeat emit must fold: created=%v err=%v", created, err)
	}
	ev.ScopeKey, ev.ScopeLabel = "user:u2", "员工 李四"
	if created, _ := e.Emit(ctx, ev); !created {
		t.Fatal("different scope must open a new group")
	}
	if len(n.titles) != 2 || n.titles[0] != "预算用尽断流 · 部门 研发部" {
		t.Fatalf("notifications=%v", n.titles)
	}
	in := groups.inputs[0]
	if in.AlertType != TypeBudgetExhausted || in.Severity != "high" || in.Stage != "" || in.DispositionClass != "action_required" ||
		in.BodyJSON["suggestion"] == "" || in.BodyJSON["type_label"] != "预算用尽断流" {
		t.Fatalf("group input=%+v", in)
	}
	if inbox.urls[0] != "/cost/alerts" {
		t.Fatalf("inbox target=%v", inbox.urls)
	}
}

// 每种类型都要有中文名称和中文处置建议，不能露英文枚举。
func TestEveryKindHasChineseLabelAndSuggestion(t *testing.T) {
	han := regexp.MustCompile(`\p{Han}`)
	for _, typ := range Types() {
		k, _ := KindOf(typ)
		if !han.MatchString(k.Label) || !han.MatchString(k.Suggestion) || k.Severity == "" || k.Domain == "" {
			t.Fatalf("kind %s incomplete: %+v", typ, k)
		}
	}
	for _, typ := range []string{TypeBudgetExhausted, TypeUnpricedRejected, TypeWalletOverdraft, TypeFinalizeFailed, TypeReservationLeak, TypeProxyUsageUnknown, TypeAuditRecordDropped, TypeAuditVerifyFailed, TypeAuditHMACDefaultKey} {
		if _, ok := KindOf(typ); !ok {
			t.Fatalf("missing kind %s", typ)
		}
	}
}

func TestEmitRejectsUnknownTypeAndMissingTenant(t *testing.T) {
	e := NewEmitter(&fakeGroups{}, nil, nil)
	if _, err := e.Emit(context.Background(), Event{TenantID: "t", Type: "nope"}); err == nil {
		t.Fatal("unknown type must be rejected")
	}
	if _, err := e.Emit(context.Background(), Event{Type: TypeFinalizeFailed}); err == nil {
		t.Fatal("missing tenant must be rejected")
	}
}
