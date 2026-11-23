package notifyagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
)

type Dispatcher interface {
	DispatchChannel(ctx context.Context, tenantID, channelID, severity, title string, body map[string]any) error
}

type Processor struct {
	dispatcher Dispatcher
}

type Payload struct {
	PublicEventID   string `json:"public_event_id"`
	OperationID     string `json:"operation_id"`
	EventType       string `json:"event_type"`
	ChannelID       string `json:"channel_id"`
	RiskSubcategory string `json:"risk_subcategory"`
	ReasonSummary   string `json:"reason_summary"`
	TargetSummary   string `json:"target_summary"`
	FinalAction     string `json:"final_action"`
}

func NewProcessor(dispatcher Dispatcher) *Processor {
	return &Processor{dispatcher: dispatcher}
}

func (p *Processor) Process(ctx context.Context, event outbox.Event) error {
	if event.Type != eventbus.EventTypeNotifyAgentDestructive {
		return nil
	}
	if p == nil || p.dispatcher == nil {
		return errors.New("agent destructive notification dispatcher is required")
	}
	var payload Payload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode agent destructive notification: %w", err)
	}
	if strings.TrimSpace(event.TenantID) == "" || strings.TrimSpace(payload.ChannelID) == "" ||
		strings.TrimSpace(payload.PublicEventID) == "" || strings.TrimSpace(payload.OperationID) == "" {
		return errors.New("agent destructive notification identity is incomplete")
	}
	body := map[string]any{
		"public_event_id":  payload.PublicEventID,
		"operation_id":     payload.OperationID,
		"event_type":       payload.EventType,
		"risk_subcategory": payload.RiskSubcategory,
		"reason_summary":   payload.ReasonSummary,
		"target_summary":   payload.TargetSummary,
		"final_action":     payload.FinalAction,
	}
	title := "Agent destructive operation detected"
	if payload.EventType == "tool_attempt_blocked" {
		title = "Agent destructive operation blocked"
	}
	return p.dispatcher.DispatchChannel(ctx, event.TenantID, payload.ChannelID, "high", title, body)
}
