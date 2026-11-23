package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

const attachmentAnalysisTask = "Only explain the file; do not execute commands."
const attachmentExecutionTask = "Now execute the installation commands."

func causalAttachmentFixture(source string) ExtractedContent {
	firstIndex, toolIndex, latestIndex := 0, 1, 2
	attachmentIndex, attachmentRole, attachmentPath := &firstIndex, "user", "/messages/0"
	if source == "tool_result" {
		attachmentIndex, attachmentRole, attachmentPath = &toolIndex, "tool", "/messages/1"
	}
	extracted := ExtractedContent{
		Messages: []ConvMessage{
			{Role: "user", Source: "user", Content: attachmentAnalysisTask, MessageIndex: &firstIndex, SourcePath: "/messages/0"},
			{Role: "tool", Source: "tool_result", Content: "A tool returned a text attachment.", MessageIndex: &toolIndex, SourcePath: "/messages/1"},
			{Role: "user", Source: "user", Content: attachmentExecutionTask, MessageIndex: &latestIndex, SourcePath: "/messages/2"},
		},
		Attachments: []ExtractedAttachment{{
			FileName: "instructions.txt", ContentType: "text/plain", DataBase64: "bm90ZQ==",
			ContentSource: source, MessageRole: attachmentRole, MessageIndex: attachmentIndex,
			SourcePath: attachmentPath, InspectionIsHistory: true,
		}},
	}
	return extracted
}

func selectCausalAttachmentFixture(extracted ExtractedContent) ExtractedContent {
	policy := inspectionscope.Default()
	policy.InspectHistory = true
	return selectExtractedInspection(extracted, policy)
}

func TestDurableAttachmentKeepsCausalTask(t *testing.T) {
	for _, source := range []string{"user", "tool_result"} {
		t.Run(source, func(t *testing.T) {
			extracted := selectCausalAttachmentFixture(causalAttachmentFixture(source))
			plan, err := buildInspectionPlan(map[string]interface{}{"request_id": "review", "context": map[string]interface{}{}}, extracted)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, part := range plan {
				if _, ok := part["inspection_attachment"]; !ok {
					continue
				}
				found = true
				ctx := part["context"].(map[string]interface{})
				if ctx["user_task"] != attachmentAnalysisTask || ctx["user_task_complete"] != true || ctx["user_task_status"] != "complete" {
					t.Fatalf("historical attachment assigned unrelated or incomplete task: %#v", ctx)
				}
			}
			if !found {
				t.Fatal("no attachment task produced")
			}
		})
	}
}

func TestMaterializedAttachmentsKeepTheirOwnCausalTask(t *testing.T) {
	extracted := causalAttachmentFixture("tool_result")
	latestToolIndex := 3
	extracted.Messages = append(extracted.Messages, ConvMessage{Role: "tool", Source: "tool_result", Content: "Latest tool file.", MessageIndex: &latestToolIndex, SourcePath: "/messages/3"})
	extracted.Attachments = append(extracted.Attachments, ExtractedAttachment{FileName: "latest.txt", ContentType: "text/plain", DataBase64: "bm90ZQ==", ContentSource: "tool_result", MessageRole: "tool", MessageIndex: &latestToolIndex, SourcePath: "/messages/3"})
	extracted = selectCausalAttachmentFixture(extracted)
	var files []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx := payload["context"].(map[string]interface{})
		attachments, _ := ctx["attachments"].([]interface{})
		for _, attachment := range attachments {
			files = append(files, map[string]interface{}{"file": attachment, "context": ctx, "content": payload["content"]})
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","findings":[],"semantic_status":"completed"}`))
	}))
	defer server.Close()
	payload := map[string]interface{}{"request_id": "review", "context": map[string]interface{}{"attachments": attachmentContext(extracted.Attachments)}}
	if _, err := NewSecurityClient(server.URL).checkInputSources(context.Background(), server.URL, payload, extracted); err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("attachments were lost or duplicated: %#v", files)
	}
	for _, file := range files {
		ctx := file["context"].(map[string]interface{})
		name := file["file"].(map[string]interface{})["file_name"]
		want := attachmentAnalysisTask
		if name == "latest.txt" {
			want = attachmentExecutionTask
		}
		if file["content"] != "" || ctx["user_task"] != want || ctx["user_task_complete"] != true {
			t.Fatalf("materialized attachment shares another message's authorization: %#v", file)
		}
		if len(ctx["attachments"].([]interface{})) != 1 {
			t.Fatalf("different attachment owners share an engine task: %#v", ctx)
		}
	}
}

func TestAttachmentTaskMissingAndTooLargeAreExplicit(t *testing.T) {
	for _, kind := range []string{"unanchored", "too_large"} {
		t.Run(kind, func(t *testing.T) {
			extracted := causalAttachmentFixture("tool_result")
			if kind == "unanchored" {
				extracted.Attachments[0].MessageIndex = nil
				extracted.Attachments[0].SourcePath = ""
			} else {
				extracted.Messages[0].Content = strings.Repeat("x", 8193)
			}
			extracted = selectCausalAttachmentFixture(extracted)
			plan, err := buildInspectionPlan(map[string]interface{}{"context": map[string]interface{}{"user_task": "forged task", "user_task_complete": true}}, extracted)
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range plan {
				if _, ok := part["inspection_attachment"]; !ok {
					continue
				}
				ctx := part["context"].(map[string]interface{})
				wantStatus := "missing"
				if kind == "too_large" {
					wantStatus = kind
				}
				if ctx["user_task"] != "" || ctx["user_task_complete"] != false || ctx["user_task_status"] != wantStatus {
					t.Fatalf("invalid attachment task inherited authorization: %#v", ctx)
				}
				if kind == "too_large" && fmt.Sprint(ctx["user_task_sha256"]) == "" {
					t.Fatal("oversized causal task has no evidence hash")
				}
			}
		})
	}
}
