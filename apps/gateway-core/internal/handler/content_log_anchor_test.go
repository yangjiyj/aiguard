package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestWriteRequestContentLogsUsesOriginalMessageIndexes(t *testing.T) {
	audit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: audit}
	messages := []Message{
		{Role: "system", Content: json.RawMessage(`"rules"`)},
		{Role: "user", Content: json.RawMessage(`""`)},
		{Role: "user", Content: json.RawMessage(`"anchored input"`)},
	}

	handler.writeRequestContentLogs(context.Background(), &modelrouter.RequestEnvelope{RequestID: "req-1"}, messages)

	if len(audit.ContentLogWrites) != 2 {
		t.Fatalf("content writes = %d, want 2", len(audit.ContentLogWrites))
	}
	if got := audit.ContentLogWrites[0].MessageIndex; got == nil || *got != 0 {
		t.Fatalf("first message index = %v, want 0", got)
	}
	if got := audit.ContentLogWrites[1].MessageIndex; got == nil || *got != 2 {
		t.Fatalf("third array message index = %v, want 2", got)
	}
}
