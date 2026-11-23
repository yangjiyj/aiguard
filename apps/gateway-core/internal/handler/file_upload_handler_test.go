package handler

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	securityclient "github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
)

type fileUploadRouteResolverStub struct {
	*MockModelResolver
	route *modelrouter.ModelRecord
	err   error
}

func (s *fileUploadRouteResolverStub) ResolveFileUploadRoute(context.Context, string) (*modelrouter.ModelRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.route, nil
}

type fileUploadSecurityStub struct {
	action      string
	findings    []SecurityFinding
	err         error
	attachments []map[string]interface{}
}

type fileUploadBindingSecurityStub struct {
	fileUploadSecurityStub
	tokens []securityclient.FileBindingToken
	bound  []struct {
		Token  securityclient.FileBindingToken
		FileID string
	}
}

func (s *fileUploadBindingSecurityStub) CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (*InputCheckOutcome, error) {
	action, masked, findings, err := s.CheckInput(ctx, envelope, content, messageIndex, messageRole, contentSource)
	if err != nil {
		return nil, err
	}
	return &InputCheckOutcome{Action: action, MaskedContent: masked, Findings: findings, FileBindings: s.tokens}, nil
}

func (s *fileUploadBindingSecurityStub) BindScannedFile(_ context.Context, _ *modelrouter.RequestEnvelope, token securityclient.FileBindingToken, fileID string) error {
	s.bound = append(s.bound, struct {
		Token  securityclient.FileBindingToken
		FileID string
	}{token, fileID})
	return nil
}

func (s *fileUploadSecurityStub) CheckInput(ctx context.Context, _ *modelrouter.RequestEnvelope, _ string, _ int, _ string, _ string) (string, string, []SecurityFinding, error) {
	s.attachments = attachmentsFromContext(ctx)
	if s.err != nil {
		return "", "", nil, s.err
	}
	return s.action, "", s.findings, nil
}

func (s *fileUploadSecurityStub) CheckOutput(context.Context, *modelrouter.RequestEnvelope, string, int) (string, string, []SecurityFinding, error) {
	return "allow", "", nil, nil
}

func (s *fileUploadSecurityStub) CheckSemanticOnly(context.Context, *modelrouter.RequestEnvelope, string) ([]SecurityFinding, error) {
	return nil, nil
}

func (s *fileUploadSecurityStub) CheckTriage(context.Context, *modelrouter.RequestEnvelope, string, []SecurityFinding) ([]SecurityFinding, error) {
	return nil, nil
}

type fileUploadCallerStub struct {
	calls int
	got   provider.FileUploadRequest
	body  []byte
	err   error
}

func (s *fileUploadCallerStub) TransformRequest(_ *modelrouter.RequestEnvelope, body []byte) ([]byte, error) {
	return body, nil
}

func (s *fileUploadCallerStub) Call(context.Context, *modelrouter.RequestEnvelope, []byte) ([]byte, error) {
	return nil, errors.New("unexpected generic provider call")
}

func (s *fileUploadCallerStub) CallStreaming(context.Context, *modelrouter.RequestEnvelope, []byte) ([]byte, error) {
	return nil, errors.New("unexpected streaming provider call")
}

func (s *fileUploadCallerStub) TransformResponse(body []byte) ([]byte, error) {
	return body, nil
}

func (s *fileUploadCallerStub) UploadFile(_ context.Context, upload provider.FileUploadRequest) ([]byte, error) {
	s.calls++
	s.got = upload
	return s.body, s.err
}

type fileUploadFactoryStub struct {
	caller ProviderCaller
}

func (s *fileUploadFactoryStub) CreateAdapter(*modelrouter.ModelRecord, string) ProviderCaller {
	return s.caller
}

func newFileUploadRequest(t *testing.T, content []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("purpose", "assistants"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("file", "customer-report.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req.WithContext(setAuthInfo(req.Context(), "tenant-file", "project-file", "user-file", "key-file", ""))
}

func newFileUploadHandlerForTest(cfg *config.Config, security SecurityChecker, caller *fileUploadCallerStub) *FileUploadHandler {
	resolver := &fileUploadRouteResolverStub{
		MockModelResolver: &MockModelResolver{ProviderAPIKey: "provider-secret"},
		route: &modelrouter.ModelRecord{
			ID: "model-file", ProviderID: "provider-file", ProviderType: "openai", ProviderBaseURL: "https://provider.example/v1",
			ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Files: true},
		},
	}
	return NewFileUploadHandler(cfg, resolver, security, &MockAuditWriter{}, &fileUploadFactoryStub{caller: caller}, nil)
}

func TestFileUploadHandlerStrictBlockStopsUpstream(t *testing.T) {
	security := &fileUploadSecurityStub{
		action:   "block",
		findings: []SecurityFinding{{Category: "file_policy_blocked_type", Action: "block"}},
	}
	caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
	h := newFileUploadHandlerForTest(&config.Config{}, security, caller)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newFileUploadRequest(t, []byte("%PDF-safe-sample")))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	if caller.calls != 0 {
		t.Fatalf("blocked upload reached upstream %d times", caller.calls)
	}
	if len(security.attachments) != 1 {
		t.Fatalf("security attachments = %#v", security.attachments)
	}
	if got, _ := security.attachments[0]["file_name"].(string); got != "customer-report.pdf" {
		t.Fatalf("file name = %q", got)
	}
}

// 审计模式最高优先级：文件类型"阻断"也只记录并继续上传。
func TestFileUploadHandlerAuditOnlyRecordsExplicitFileTypePolicy(t *testing.T) {
	security := &fileUploadBindingSecurityStub{
		fileUploadSecurityStub: fileUploadSecurityStub{
			action:   "block",
			findings: []SecurityFinding{{Category: "file_policy_blocked_type", Action: "block"}},
		},
		tokens: []securityclient.FileBindingToken{{Token: "audit-binding", SHA256: "sha1"}},
	}
	caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
	h := newFileUploadHandlerForTest(&config.Config{SecurityAuditOnly: true}, security, caller)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newFileUploadRequest(t, []byte("%PDF-safe-sample")))

	if response.Code == http.StatusForbidden {
		t.Fatalf("audit mode must not block an explicit file type, status = %d, body=%s", response.Code, response.Body.String())
	}
	if caller.calls != 1 {
		t.Fatalf("audit mode upload must reach upstream once, got %d", caller.calls)
	}
}

func TestFileUploadHandlerRejectsMissingUniqueRoute(t *testing.T) {
	security := &fileUploadSecurityStub{action: "allow"}
	caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
	h := newFileUploadHandlerForTest(&config.Config{}, security, caller)
	resolver := h.modelResolver.(*fileUploadRouteResolverStub)
	resolver.err = modelrouter.ErrAmbiguousFileUploadRoute

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newFileUploadRequest(t, []byte("%PDF-safe-sample")))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	if caller.calls != 0 {
		t.Fatalf("ambiguous upload reached upstream %d times", caller.calls)
	}
}

func TestFileUploadHandlerBindsOnlyVerifiedUpstreamFileObject(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		wantBinds  int
		wantFileID string
	}{
		{name: "verified_file", body: []byte(`{"id":"file_upstream","object":"file"}`), wantBinds: 1, wantFileID: "file_upstream"},
		{name: "wrong_object", body: []byte(`{"id":"file_upstream","object":"chat.completion"}`), wantBinds: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			security := &fileUploadBindingSecurityStub{
				fileUploadSecurityStub: fileUploadSecurityStub{action: "allow"},
				tokens:                 []securityclient.FileBindingToken{{Token: "one-time", SHA256: "sha1"}},
			}
			caller := &fileUploadCallerStub{body: tc.body}
			h := newFileUploadHandlerForTest(&config.Config{}, security, caller)
			response := httptest.NewRecorder()
			h.Handler().ServeHTTP(response, newFileUploadRequest(t, []byte("safe-bytes")))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
			}
			if len(security.bound) != tc.wantBinds {
				t.Fatalf("binding calls = %d, want %d", len(security.bound), tc.wantBinds)
			}
			if tc.wantFileID != "" && security.bound[0].FileID != tc.wantFileID {
				t.Fatalf("bound file_id = %q, want %q", security.bound[0].FileID, tc.wantFileID)
			}
		})
	}
}
