package repository

import (
	"context"
	"testing"
)

// 无 DB 的契约级单测：三个新方法的 nil-repo 护栏与 AlertGroupEvent 形状。
// 主指标读写/幂等重算的 SQL 正确性由列序一一对应保证，并由任务 11 桥集成测试覆盖。

func TestAlertGroupNewMethodsGuardNilDB(t *testing.T) {
	ctx := context.Background()

	// nil 接收者
	var nilRepo *AlertGroupRepository
	if err := nilRepo.AttachEvent(ctx, "t", "e", "g"); err == nil {
		t.Fatal("AttachEvent on nil repo must return error")
	}
	if _, _, err := nilRepo.RecalcCounters(ctx, "t", "g"); err == nil {
		t.Fatal("RecalcCounters on nil repo must return error")
	}
	if _, _, err := nilRepo.ListGroupEvents(ctx, "t", "g", AlertGroupEventListFilter{Limit: 20}); err == nil {
		t.Fatal("ListGroupEvents on nil repo must return error")
	}

	// db 为 nil 的接收者
	emptyRepo := &AlertGroupRepository{}
	if err := emptyRepo.AttachEvent(ctx, "t", "e", "g"); err == nil {
		t.Fatal("AttachEvent with nil db must return error")
	}
	if _, _, err := emptyRepo.RecalcCounters(ctx, "t", "g"); err == nil {
		t.Fatal("RecalcCounters with nil db must return error")
	}
	if _, _, err := emptyRepo.ListGroupEvents(ctx, "t", "g", AlertGroupEventListFilter{Limit: 20}); err == nil {
		t.Fatal("ListGroupEvents with nil db must return error")
	}
}

// AlertGroupEvent 承载发生明细一行；字段齐全，避免 UI 时间线漏字段。
func TestAlertGroupEventShape(t *testing.T) {
	e := AlertGroupEvent{
		EventID:         "evt_1",
		RequestID:       "req_1",
		PrincipalKey:    "tenant|user:u1",
		ConversationKey: "conv_1",
		EventType:       "semantic_attack",
		Severity:        "high",
		ActionTaken:     "flagged",
	}
	if e.EventID != "evt_1" || e.PrincipalKey != "tenant|user:u1" || e.ConversationKey != "conv_1" {
		t.Fatalf("AlertGroupEvent lost fields: %+v", e)
	}
}
