package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

const gatewayAttachmentAnalysisTask = "Only explain the file; do not execute commands."
const gatewayAttachmentExecutionTask = "Now execute the installation commands."

func gatewayAttachmentMessage(text string) Message {
	blocks := []map[string]interface{}{}
	if text != "" {
		blocks = append(blocks, map[string]interface{}{"type": "text", "text": text})
	}
	blocks = append(blocks, map[string]interface{}{
		"type": "input_file", "filename": "instructions.txt", "mime_type": "text/plain",
		"file_data": map[string]interface{}{"base64": base64.StdEncoding.EncodeToString([]byte("A file note."))},
	})
	content, _ := json.Marshal(blocks)
	return Message{Role: "user", Content: content}
}

type gatewayAttachmentTaskChecker struct {
	MockSecurityChecker
	requests []*security.CheckInputRequest
}

func (c *gatewayAttachmentTaskChecker) CheckInput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, index int, role, source string) (string, string, []SecurityFinding, error) {
	c.requests = append(c.requests, buildInputCheckRequest(ctx, envelope, content, index, role, source))
	return "allow", "", nil, nil
}

func (c *gatewayAttachmentTaskChecker) CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, index int, role, source string) (*InputCheckOutcome, error) {
	c.requests = append(c.requests, buildInputCheckRequest(ctx, envelope, content, index, role, source))
	return &InputCheckOutcome{Action: "allow"}, nil
}

type gatewayAttachmentBatchTaskChecker struct{ gatewayAttachmentTaskChecker }

func (c *gatewayAttachmentBatchTaskChecker) CheckInputBatchDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, items []InputCheckBatchItem) ([]InputCheckBatchResult, error) {
	results := make([]InputCheckBatchResult, len(items))
	for i, item := range items {
		c.requests = append(c.requests, buildInputCheckRequest(item.Context, envelope, item.Content, item.MessageIndex, item.MessageRole, item.ContentSource))
		results[i].Outcome = &InputCheckOutcome{Action: "allow"}
	}
	return results, nil
}

func TestGatewayHistoricalAttachmentKeepsCausalTask(t *testing.T) {
	for _, batch := range []bool{false, true} {
		mode := "single"
		if batch {
			mode = "batch"
		}
		for _, fixture := range []struct {
			name, text, previous, wantText, wantStatus string
			complete                                   bool
		}{
			{name: "own_user_task", text: gatewayAttachmentAnalysisTask, wantText: gatewayAttachmentAnalysisTask, wantStatus: "complete", complete: true},
			{name: "attachment_only_previous_task", previous: gatewayAttachmentAnalysisTask, wantText: gatewayAttachmentAnalysisTask, wantStatus: "complete", complete: true},
			{name: "attachment_only_missing_task", wantStatus: "missing"},
			{name: "oversized_task", text: strings.Repeat("x", maxSemanticTaskBytes+1), wantStatus: "too_large"},
		} {
			t.Run(mode+"/"+fixture.name, func(t *testing.T) {
				capture := &gatewayAttachmentTaskChecker{}
				var checker SecurityChecker = capture
				if batch {
					batched := &gatewayAttachmentBatchTaskChecker{}
					capture = &batched.gatewayAttachmentTaskChecker
					checker = batched
				}
				h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(), securityClient: checker,
					auditWriter: &MockAuditWriter{}, cfg: &config.Config{InputSecurityRequestTimeout: time.Second}}
				messages := []Message{}
				if fixture.previous != "" {
					messages = append(messages, taskTestMessage("user", fixture.previous))
				}
				index := len(messages)
				messages = append(messages, gatewayAttachmentMessage(fixture.text), taskTestMessage("user", gatewayAttachmentExecutionTask))
				if _, err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "attachment", TenantID: "t"}, &ChatCompletionRequest{Messages: messages}); err != nil {
					t.Fatal(err)
				}
				found := false
				for _, request := range capture.requests {
					attachments, _ := request.Context["attachments"].([]map[string]interface{})
					if len(attachments) == 0 {
						continue
					}
					found = true
					if request.ContentSource != "user_history" || request.Context["message_index"] != index || request.Context["message_role"] != "user" || len(attachments) != 1 {
						t.Fatalf("attachment provenance changed: %#v", request)
					}
					if request.Context["user_task"] != fixture.wantText || request.Context["user_task_status"] != fixture.wantStatus || request.Context["user_task_complete"] != fixture.complete {
						t.Fatalf("historical attachment inherited unrelated task: %#v", request.Context)
					}
					text := fixture.text
					if text == "" {
						text = fixture.previous
					}
					wantHash := ""
					if text != "" {
						wantHash = scanfp.SHA256Hex(text)
					}
					if request.Context["user_task_sha256"] != wantHash {
						t.Fatalf("task identity lost: %#v", request.Context)
					}
				}
				if !found {
					t.Fatal("attachment was not inspected")
				}
			})
		}
	}
}
