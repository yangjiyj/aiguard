package handler

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestCustomerVisibleCorrelationValueHidesInternalKeys(t *testing.T) {
	for _, value := range []string{
		"caller_6ca233ddc4c8",
		" key_b5b4caa8 ",
		"user_7813951c",
		"client_internal_1",
		"7813951c-67e4-41ec-b866-8a85f87cd1ec",
	} {
		if got := customerVisibleCorrelationValue(value); got != "" {
			t.Fatalf("customerVisibleCorrelationValue(%q) = %q, want empty", value, got)
		}
	}
	for _, value := range []string{"zhangsan", "研发助手"} {
		if got := customerVisibleCorrelationValue(value); got != value {
			t.Fatalf("customerVisibleCorrelationValue(%q) = %q", value, got)
		}
	}
}

func TestCustomerFacingAccessDTOHidesInternalClientID(t *testing.T) {
	dto := mapForwardProxyAccessToInfo(repository.ForwardProxyAccessRecord{
		ClientID:   "caller_6ca233ddc4c8",
		ClientName: "研发助手",
	})
	if dto.ClientID != "" {
		t.Fatalf("customer access DTO leaked client id %q", dto.ClientID)
	}
	if dto.ClientName != "研发助手" {
		t.Fatalf("customer access DTO lost client name %q", dto.ClientName)
	}
}

func TestCustomerVisibleSessionHidesInternalClientID(t *testing.T) {
	session := map[string]interface{}{
		"client_id":   "caller_6ca233ddc4c8",
		"client_name": "研发助手",
		"source_ip":   "100.67.114.59",
	}
	customerVisibleSession(session)
	if _, ok := session["client_id"]; ok {
		t.Fatalf("customer session leaked client_id: %#v", session)
	}
	if session["client_name"] != "研发助手" || session["source_ip"] != "100.67.114.59" {
		t.Fatalf("customer session lost visible identity: %#v", session)
	}
}

func TestAlertGroupDTOHidesInternalPrincipalKey(t *testing.T) {
	now := time.Date(2026, 7, 26, 8, 0, 0, 0, time.UTC)
	dto := toAlertGroupDTO(&repository.AlertGroup{
		ID:           "ag_1",
		PrincipalKey: "caller_6ca233ddc4c8",
		FirstSeenAt:  now,
		LastSeenAt:   now,
	})
	if dto.PrincipalKey != "" {
		t.Fatalf("alert group DTO leaked principal key %q", dto.PrincipalKey)
	}
}

func TestAlertGroupEventDTOHidesInternalPrincipalKey(t *testing.T) {
	dto := toAlertGroupEventDTO(&repository.AlertGroupEvent{
		EventID:      "evt_1",
		RequestID:    "req_1",
		PrincipalKey: "caller_6ca233ddc4c8",
		CreatedAt:    time.Date(2026, 7, 26, 8, 0, 0, 0, time.UTC),
	})
	if dto.PrincipalKey != "" {
		t.Fatalf("alert event DTO leaked principal key %q", dto.PrincipalKey)
	}
	if dto.RequestID != "req_1" {
		t.Fatalf("alert event DTO lost request id %q", dto.RequestID)
	}
}
