package handler

import (
	"context"
	"fmt"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 复审 I1：观察留证只属于 chat 输入路径。写入器层闸门对其它入口（embeddings、图片、文件上传
// 等直接调 auditWriter.WriteSecurityEvent 的地方）必须与 main 一致：纯观察不落库。

func realWriterWithDB() (*RealAuditWriter, *mockDBExecutor) {
	db := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	return &RealAuditWriter{db: db}, db
}

func profanityDiscussion() SecurityFinding {
	return retainedObservationFinding("content_safety", "content_profanity_abuse", "quoted_profanity_reference")
}

func TestEmbeddingsObservationInputsWriteNoEvents(t *testing.T) {
	inputs := make([]interface{}, 100)
	for i := range inputs {
		inputs[i] = fmt.Sprintf("第 %d 条：“傻逼”这个词是脏话吗", i)
	}
	for _, auditOnly := range []bool{false, true} {
		writer, db := realWriterWithDB()
		h := &EmbeddingsHandler{cfg: &config.Config{SecurityAuditOnly: auditOnly}, auditWriter: writer,
			securityClient: &MockSecurityChecker{InputAction: "allow", InputFindings: []SecurityFinding{profanityDiscussion()}}}
		if err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r-emb", TenantID: "t"},
			&EmbeddingsRequest{Model: "text-embedding-3", Input: inputs}); err != nil {
			t.Fatalf("auditOnly=%v: %v", auditOnly, err)
		}
		if db.execCalls != 0 {
			t.Fatalf("auditOnly=%v: embeddings 纯观察输入应与 main 一致不落库, got %d 行", auditOnly, db.execCalls)
		}
	}
}

func TestImagesObservationPromptWritesNoEvent(t *testing.T) {
	for _, auditOnly := range []bool{false, true} {
		writer, db := realWriterWithDB()
		h := &ImagesHandler{cfg: &config.Config{SecurityAuditOnly: auditOnly}, auditWriter: writer,
			securityClient: &MockSecurityChecker{InputAction: "allow", InputFindings: []SecurityFinding{profanityDiscussion()}}}
		if _, err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r-img", TenantID: "t"},
			&ImagesRequest{Prompt: "“傻逼”这个词是脏话吗"}, nil, nil); err != nil {
			t.Fatalf("auditOnly=%v: %v", auditOnly, err)
		}
		if db.execCalls != 0 {
			t.Fatalf("auditOnly=%v: 图片纯观察提示词应与 main 一致不落库, got %d 行", auditOnly, db.execCalls)
		}
	}
}

func TestDirectWriterCallsDropObservationLikeMain(t *testing.T) {
	// 文件上传等入口直接调用写入器（FileUploadHandler.writeSecurityEvent 只做转发）。
	writer, db := realWriterWithDB()
	for _, action := range []string{"security_audit", "security_audit_only"} {
		writer.WriteSecurityEvent(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r-file", TenantID: "t"},
			[]SecurityFinding{profanityDiscussion()}, action, "file upload observed security action \"audit\"")
	}
	if db.execCalls != 0 {
		t.Fatalf("未经 chat 观察入口的纯观察不落库, got %d 行", db.execCalls)
	}
}

func TestChatInputObservationStillPersistsThroughRealWriter(t *testing.T) {
	writer, db := realWriterWithDB()
	h := &ChatCompletionsHandler{cfg: &config.Config{}, auditWriter: writer,
		securityClient: &asyncTriageSignalChecker{inputAction: "allow", inputFindings: []SecurityFinding{profanityDiscussion()}, triageCalled: make(chan struct{}, 1)}}
	req := &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: jsonQuote("“傻逼”这个词是脏话吗")}}}
	if _, err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r-chat", TenantID: "t"}, req); err != nil {
		t.Fatalf("chat: %v", err)
	}
	if db.execCalls != 1 {
		t.Fatalf("chat 输入观察仍应落库一条, got %d 行", db.execCalls)
	}
}
