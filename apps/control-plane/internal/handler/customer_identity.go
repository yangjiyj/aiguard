package handler

import (
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/google/uuid"
)

// customerVisibleCorrelationValue keeps customer-defined names/usernames while
// hiding deterministic internal correlation keys from ordinary customer APIs.
func customerVisibleCorrelationValue(value string) string {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "caller_") ||
		strings.HasPrefix(lower, "key_") ||
		strings.HasPrefix(lower, "user_") ||
		strings.HasPrefix(lower, "client_") {
		return ""
	}
	if _, err := uuid.Parse(trimmed); err == nil {
		return ""
	}
	return trimmed
}

func customerVisibleSession(session map[string]interface{}) {
	if session == nil {
		return
	}
	clientID, _ := session["client_id"].(string)
	if customerVisibleCorrelationValue(clientID) == "" {
		delete(session, "client_id")
	}
	callerID, _ := session["caller_id"].(string)
	if customerVisibleCorrelationValue(callerID) == "" {
		delete(session, "caller_id")
	}
}

type alertGroupEventDTO struct {
	RowKey          string    `json:"row_key"`
	EventID         string    `json:"event_id"`
	RequestID       string    `json:"request_id"`
	PrincipalKey    string    `json:"principal_key,omitempty"`
	ConversationKey string    `json:"conversation_key"`
	EventType       string    `json:"event_type"`
	Severity        string    `json:"severity"`
	ActionTaken     string    `json:"action_taken"`
	CreatedAt       time.Time `json:"created_at"`
	EventCount      int       `json:"event_count"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}

func toAlertGroupEventDTO(event *repository.AlertGroupEvent) alertGroupEventDTO {
	if event == nil {
		return alertGroupEventDTO{}
	}
	return alertGroupEventDTO{
		RowKey:          event.RowKey,
		EventID:         event.EventID,
		RequestID:       event.RequestID,
		PrincipalKey:    customerVisibleCorrelationValue(event.PrincipalKey),
		ConversationKey: event.ConversationKey,
		EventType:       event.EventType,
		Severity:        event.Severity,
		ActionTaken:     event.ActionTaken,
		CreatedAt:       event.CreatedAt,
		EventCount:      event.EventCount,
		FirstSeenAt:     event.FirstSeenAt,
		LastSeenAt:      event.LastSeenAt,
	}
}
