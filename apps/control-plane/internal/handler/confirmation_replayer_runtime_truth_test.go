package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type captureToolCallCreator struct {
	log *repository.ToolCallLog
}

func (c *captureToolCallCreator) Create(_ context.Context, log *repository.ToolCallLog) error {
	c.log = log
	log.ID = "tc-captured"
	return nil
}

func TestConfirmationApprovalDoesNotClaimToolExecution(t *testing.T) {
	capture := &captureToolCallCreator{}
	replayer := &confirmationReplayer{toolCallLogRepo: capture}
	_, err := replayer.ReplayConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		RequestID:         "req-confirm",
		TenantID:          "tenant-1",
		TraceID:           "trace-1",
		ToolName:          "Bash",
		ToolCallID:        "call-1",
		ToolCallArguments: `{"command":"echo safe"}`,
	})
	if err != nil {
		t.Fatalf("replay confirmation: %v", err)
	}
	if capture.log == nil {
		t.Fatal("confirmation audit was not written")
	}
	if capture.log.EventKind != "confirmation_replay" || capture.log.ExecutionObserved || capture.log.ResultObserved {
		t.Fatalf("approval must remain a confirmation audit until client retry: %#v", capture.log)
	}
	if capture.log.EventKind == "invocation_proposed" {
		t.Fatalf("approval audit must not inflate invocation proposals: %#v", capture.log)
	}
	if capture.log.Status == "success" {
		t.Fatalf("approval audit must not claim execution success: %#v", capture.log)
	}
	if capture.log.ToolCallID != "call-1" {
		t.Fatalf("tool_call_id = %q", capture.log.ToolCallID)
	}
}

func TestConfirmationReplayPreservesTypedMCPToolCallID(t *testing.T) {
	for _, toolCallID := range []string{"number:9", "string:9"} {
		t.Run(toolCallID, func(t *testing.T) {
			capture := &captureToolCallCreator{}
			replayer := &confirmationReplayer{toolCallLogRepo: capture}

			_, err := replayer.ReplayConfirmation(context.Background(), &repository.AgentGuardConfirmation{
				RequestID: "req-mcp-confirm", TenantID: "tenant-1", TraceID: "trace-mcp",
				ToolName: "demo__write", ToolCallID: toolCallID, ToolCallArguments: `{}`,
			})

			if err != nil {
				t.Fatalf("replay confirmation: %v", err)
			}
			if capture.log == nil {
				t.Fatal("confirmation audit was not written")
			}
			if capture.log.ToolCallID != toolCallID {
				t.Fatalf("tool_call_id=%q, want %q", capture.log.ToolCallID, toolCallID)
			}
		})
	}
}
