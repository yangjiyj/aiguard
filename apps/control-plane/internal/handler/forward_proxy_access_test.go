package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/go-chi/chi/v5"
)

type fakeForwardProxyAccessRepo struct {
	tenantID   string
	riskState  string
	accessType string
	limit      int
	offset     int

	capturedFilter repository.ForwardProxyAccessFilter
	summary        *repository.ForwardProxyAccessSummary
	records        []repository.ForwardProxyAccessRecord
	listCalled     bool
	summaryCalled  bool
	countsCalled   bool
	summaryErr     error
	listErr        error
}

func (f *fakeForwardProxyAccessRepo) ListForwardProxyAccess(ctx context.Context, tenantID string, filter repository.ForwardProxyAccessFilter) ([]repository.ForwardProxyAccessRecord, int, error) {
	f.listCalled = true
	f.tenantID = tenantID
	f.riskState = filter.RiskState
	f.accessType = filter.AccessType
	f.limit = filter.Limit
	f.offset = filter.Offset
	f.capturedFilter = filter
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	if f.records != nil {
		return f.records, len(f.records), nil
	}
	return []repository.ForwardProxyAccessRecord{
		{
			RequestID:          "req_forward_001",
			TenantID:           tenantID,
			CreatedAt:          time.Date(2026, 6, 6, 9, 30, 0, 0, time.UTC),
			SourceIP:           "10.10.10.8",
			TargetHost:         "api.deepseek.com",
			TargetPath:         "/v1/chat/completions",
			Method:             "POST",
			Provider:           "deepseek",
			ProviderCN:         "DeepSeek",
			Product:            "DeepSeek API",
			ProductCN:          "DeepSeek API",
			AccessType:         "llm",
			EndpointKind:       "chat",
			PathTemplate:       "/v1/chat/completions",
			Status:             "success",
			StatusCode:         200,
			ResponseBytes:      4096,
			RequestBytes:       2048,
			TunnelDurationMS:   1500,
			TLSInspected:       true,
			RetentionLevel:     "content",
			ContentRetained:    true,
			RiskState:          "risk",
			RiskReasons:        []string{"bank_card_cn", "secret"},
			ActionTaken:        "audit",
			SecurityEventCount: 1,
			DispositionStatus:  "open",
			AgentType:          "workbuddy",
			ClientName:         "yanfa.demo@jjdguard.invalid",
		},
	}, 1, nil
}

func (f *fakeForwardProxyAccessRepo) GetForwardProxyAccessSummary(ctx context.Context, tenantID string, filter repository.ForwardProxyAccessFilter) (repository.ForwardProxyAccessSummary, error) {
	f.summaryCalled = true
	if f.summaryErr != nil {
		return repository.ForwardProxyAccessSummary{}, f.summaryErr
	}
	if f.summary != nil {
		return *f.summary, nil
	}
	return repository.ForwardProxyAccessSummary{
		Total:                1,
		NormalCount:          0,
		RiskCount:            1,
		BlockedCount:         0,
		LLMCount:             1,
		NormalPublicCount:    0,
		RetainedContentCount: 1,
		AgentRequestCount:    1,
		IdentifiedAgentCount: 1,
		TopAgents: []repository.ForwardProxyAccessDimension{
			{Name: "workbuddy", Count: 1, RiskCount: 1},
		},
		TopProviders: []repository.ForwardProxyAccessDimension{
			{Name: "deepseek", Count: 1, RiskCount: 1},
		},
		TopTargets: []repository.ForwardProxyAccessDimension{
			{Name: "api.deepseek.com", Count: 1, RiskCount: 1},
		},
	}, nil
}

func (f *fakeForwardProxyAccessRepo) GetForwardProxyAccessCounts(ctx context.Context, tenantID string, filter repository.ForwardProxyAccessFilter) (repository.ForwardProxyAccessSummary, error) {
	f.countsCalled = true
	f.tenantID = tenantID
	f.capturedFilter = filter
	if f.summaryErr != nil {
		return repository.ForwardProxyAccessSummary{}, f.summaryErr
	}
	if f.summary != nil {
		return *f.summary, nil
	}
	return repository.ForwardProxyAccessSummary{Total: 42, LLMCount: 7, AIIdeCount: 3, NormalPublicCount: 32}, nil
}

type fakeAccessRollupSummaryRepo struct {
	called bool
	filter repository.ForwardProxyAccessFilter
	out    repository.ForwardProxyAccessSummary
	err    error
}

func (f *fakeAccessRollupSummaryRepo) GetAccessSummaryFiltered(ctx context.Context, tenantID string, filter repository.ForwardProxyAccessFilter) (repository.ForwardProxyAccessSummary, error) {
	f.called = true
	f.filter = filter
	return f.out, f.err
}

type fakeAccessContentRepo struct {
	tenantID   string
	requestID  string
	requestIDs []string

	// 可选：覆盖 GetAccessContentLog 返回的文件元数据（用于覆盖按 reference_id 解引用合并的路径）。
	fileMetadataJSON []byte

	// 解引用桩：reference_id -> 字节，并记录被调用时的租户与入参，用于断言租户收口。
	resolved          map[string]repository.ResolvedUploadedFile
	resolveTenantID   string
	resolveReferences []string
}

func (f *fakeAccessContentRepo) GetAccessContentLog(ctx context.Context, tenantID string, requestID string) (*repository.AccessContentLog, error) {
	f.tenantID = tenantID
	f.requestID = requestID
	retentionUntil := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	fileMetadata := f.fileMetadataJSON
	if fileMetadata == nil {
		fileMetadata = []byte(`[{"file_name":"report.pdf","sha256":"abc123","text_preview":"影像报告摘要"}]`)
	}
	return &repository.AccessContentLog{
		RequestID:        requestID,
		RequestContent:   "请分析患者报告，密钥已脱敏 [REDACTED]",
		ResponseContent:  "报告摘要正常",
		FileMetadataJSON: fileMetadata,
		RetentionUntil:   &retentionUntil,
	}, nil
}

func (f *fakeAccessContentRepo) GetAccessContentLogs(ctx context.Context, tenantID string, requestIDs []string) ([]repository.AccessContentLog, error) {
	f.requestIDs = append([]string(nil), requestIDs...)
	out := make([]repository.AccessContentLog, 0, len(requestIDs))
	for _, id := range requestIDs {
		log, err := f.GetAccessContentLog(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		if log != nil {
			out = append(out, *log)
		}
	}
	return out, nil
}

func (f *fakeAccessContentRepo) ResolveUploadedFileBytes(ctx context.Context, tenantID string, referenceIDs []string) (map[string]repository.ResolvedUploadedFile, error) {
	f.resolveTenantID = tenantID
	f.resolveReferences = referenceIDs
	out := map[string]repository.ResolvedUploadedFile{}
	for _, ref := range referenceIDs {
		if file, ok := f.resolved[ref]; ok {
			out[ref] = file
		}
	}
	return out, nil
}

func TestListForwardProxyAccessUsesTenantScopeAndReturnsSummary(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?access_type=llm&risk_state=risk&content_only=true&limit=20&offset=5", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.tenantID != "tenant_default" || repo.riskState != "risk" || repo.accessType != "llm" || repo.limit != 20 || repo.offset != 5 {
		t.Fatalf("unexpected repo filter: tenant=%s risk=%s access=%s limit=%d offset=%d", repo.tenantID, repo.riskState, repo.accessType, repo.limit, repo.offset)
	}
	if !repo.capturedFilter.ContentOnly {
		t.Fatal("expected content_only filter to be passed to repository")
	}

	var resp struct {
		Data []struct {
			RequestID         string   `json:"request_id"`
			TargetHost        string   `json:"target_host"`
			Provider          string   `json:"provider"`
			ProviderCN        string   `json:"provider_cn"`
			Product           string   `json:"product"`
			AccessType        string   `json:"access_type"`
			RetentionLevel    string   `json:"retention_level"`
			ContentRetained   bool     `json:"content_retained"`
			RiskState         string   `json:"risk_state"`
			RiskReasons       []string `json:"risk_reasons"`
			ActionTaken       string   `json:"action_taken"`
			DispositionStatus string   `json:"disposition_status"`
			AgentType         string   `json:"agent_type"`
			AgentLabel        string   `json:"agent_label"`
			ClientName        string   `json:"client_name"`
			RequestBytes      int64    `json:"request_bytes"`
			ResponseBytes     int64    `json:"response_bytes"`
			TunnelDurationMS  int64    `json:"tunnel_duration_ms"`
		} `json:"data"`
		Total   int `json:"total"`
		Summary struct {
			Total        int `json:"total"`
			RiskCount    int `json:"risk_count"`
			BlockedCount int `json:"blocked_count"`
			TopProviders []struct {
				Name      string `json:"name"`
				Count     int    `json:"count"`
				RiskCount int    `json:"risk_count"`
			} `json:"top_providers"`
			LLMCount               int `json:"llm_count"`
			AIIdeCount             int `json:"ai_ide_count"`
			NormalPublicCount      int `json:"normal_public_count"`
			RetainedContentCount   int `json:"retained_content_count"`
			AgentRequestCount      int `json:"agent_request_count"`
			IdentifiedAgentCount   int `json:"identified_agent_count"`
			UnidentifiedAgentCount int `json:"unidentified_agent_count"`
			TopAgents              []struct {
				Name  string `json:"name"`
				Label string `json:"label"`
				Count int    `json:"count"`
			} `json:"top_agents"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Data) != 1 {
		t.Fatalf("unexpected list response: %+v", resp)
	}
	if resp.Data[0].TargetHost != "api.deepseek.com" || resp.Data[0].Provider != "deepseek" || resp.Data[0].ProviderCN != "DeepSeek" || resp.Data[0].Product != "DeepSeek API" || resp.Data[0].AccessType != "llm" || resp.Data[0].RetentionLevel != "content" || !resp.Data[0].ContentRetained || resp.Data[0].RiskState != "risk" {
		t.Fatalf("unexpected record: %+v", resp.Data[0])
	}
	if resp.Data[0].RequestBytes != 2048 || resp.Data[0].ResponseBytes != 4096 || resp.Data[0].TunnelDurationMS != 1500 {
		t.Fatalf("expected upload/download bytes and tunnel duration, got %+v", resp.Data[0])
	}
	if strings.Join(resp.Data[0].RiskReasons, ",") != "bank_card_cn,secret" {
		t.Fatalf("expected concrete risk reasons, got %#v", resp.Data[0].RiskReasons)
	}
	// 正向代理抓到的智能体（如 WorkBuddy/VS Code）必须在访问留存里带上面向人的展示名，
	// 而不是露出原始 agent_type；这是用户要求「关于智能体的访问留存也要统计到」的落点。
	if resp.Data[0].AgentType != "workbuddy" || resp.Data[0].AgentLabel != "WorkBuddy" {
		t.Fatalf("expected agent_type=workbuddy/agent_label=WorkBuddy, got type=%q label=%q", resp.Data[0].AgentType, resp.Data[0].AgentLabel)
	}
	if resp.Data[0].ClientName != "yanfa.demo@jjdguard.invalid" {
		t.Fatalf("expected customer-readable Chat account, got %q", resp.Data[0].ClientName)
	}
	if resp.Summary.Total != 1 || resp.Summary.RiskCount != 1 || resp.Summary.TopProviders[0].Name != "deepseek" {
		t.Fatalf("unexpected summary: %+v", resp.Summary)
	}
	if resp.Summary.LLMCount != 1 || resp.Summary.NormalPublicCount != 0 || resp.Summary.RetainedContentCount != 1 {
		t.Fatalf("unexpected retention summary: %+v", resp.Summary)
	}
	if resp.Summary.AgentRequestCount != 1 || resp.Summary.IdentifiedAgentCount != 1 || len(resp.Summary.TopAgents) != 1 || resp.Summary.TopAgents[0].Label != "WorkBuddy" {
		t.Fatalf("unexpected agent summary: %+v", resp.Summary)
	}
}

func TestListForwardProxyAccessPassesBoundedKeywordAndSkipsHeavyAggregates(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?content_only=true&keyword=%E7%99%BB%E5%BD%95%E5%A4%B1%E8%B4%A5&from=2026-08-01T00%3A00%3A00Z&to=2026-08-16T00%3A00%3A00Z", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant_default"}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.capturedFilter.Keyword != "登录失败" || !repo.capturedFilter.SkipTotal {
		t.Fatalf("keyword filter=%+v", repo.capturedFilter)
	}
	if repo.summaryCalled {
		t.Fatal("keyword search must skip summary aggregation")
	}
}

func TestListForwardProxyAccessKeywordPaginationAndIdentityFilters(t *testing.T) {
	records := make([]repository.ForwardProxyAccessRecord, 21)
	for i := range records {
		records[i] = repository.ForwardProxyAccessRecord{
			RequestID: fmt.Sprintf("req_%03d", i),
			CreatedAt: time.Date(2026, 8, 15, 0, i, 0, 0, time.UTC),
		}
	}
	repo := &fakeForwardProxyAccessRepo{records: records}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?keyword=metadata&user_id=user_42&disposition=resolved&limit=20&offset=100&from=2026-08-01T00%3A00%3A00Z&to=2026-08-16T00%3A00%3A00Z", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant_default"}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.capturedFilter.UserID != "user_42" || repo.capturedFilter.Disposition != "resolved" || !repo.capturedFilter.ProbeHasMore {
		t.Fatalf("captured filter=%+v", repo.capturedFilter)
	}
	var resp types.ForwardProxyAccessListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 20 || !resp.HasMore || resp.TotalKnown || resp.Total != 121 {
		t.Fatalf("unexpected page response: data=%d has_more=%v total_known=%v total=%d", len(resp.Data), resp.HasMore, resp.TotalKnown, resp.Total)
	}
}

func TestListForwardProxyAccessExposesKeyOwnershipIdentityWithoutClaimingEmployee(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{records: []repository.ForwardProxyAccessRecord{{
		RequestID: "req_owner", CreatedAt: time.Now(), UserID: "user_42", Username: "张三",
		ClientID: "key_42", ClientName: "研发 Key", IdentityKind: "key_owner", KeyOwner: "张三",
	}}}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?limit=20", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant_default"}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(&Dependencies{ForwardProxyAccessRepo: repo}).ServeHTTP(w, req)

	var resp types.ForwardProxyAccessListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].IdentityKind != "key_owner" || resp.Data[0].KeyOwner != "张三" {
		t.Fatalf("unexpected identity response: %+v", resp.Data)
	}
}

func TestListForwardProxyAccessRejectsUnsafeKeywordBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{name: "too short", url: "/admin/v1/audit/access-retention?keyword=a"},
		{name: "over 180 days", url: "/admin/v1/audit/access-retention?keyword=metadata&from=2026-01-01T00%3A00%3A00Z&to=2026-08-01T00%3A00%3A00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeForwardProxyAccessRepo{}
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant_default"}))
			w := httptest.NewRecorder()

			ListForwardProxyAccess(&Dependencies{ForwardProxyAccessRepo: repo}).ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if repo.listCalled {
				t.Fatal("unsafe keyword search must not reach repository")
			}
		})
	}
}

func TestListForwardProxyAccessKeepsListWhenSummaryFails(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{summaryErr: errors.New("summary unavailable")}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected list to remain usable, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data         []types.ForwardProxyAccessInfo `json:"data"`
		SummaryError string                         `json:"summary_error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 1 || resp.SummaryError != "summary_unavailable" {
		t.Fatalf("unexpected degraded response: %+v", resp)
	}
}

func TestListForwardProxyAccessPassesDirectionAndReturnsCounts(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{
		summary: &repository.ForwardProxyAccessSummary{
			Total:        5,
			ForwardCount: 3,
			ReverseCount: 2,
			DeviceCount:  0,
		},
	}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?direction=reverse", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.capturedFilter.Direction != "reverse" {
		t.Fatalf("expected direction filter 'reverse', got %q", repo.capturedFilter.Direction)
	}

	var resp struct {
		Summary struct {
			Total        int `json:"total"`
			ForwardCount int `json:"forward_count"`
			ReverseCount int `json:"reverse_count"`
			DeviceCount  int `json:"device_count"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Summary.ForwardCount != 3 || resp.Summary.ReverseCount != 2 || resp.Summary.DeviceCount != 0 {
		t.Fatalf("unexpected direction counts: %+v", resp.Summary)
	}
}

func TestGetAccessRetentionContentUsesTenantScope(t *testing.T) {
	repo := &fakeAccessContentRepo{}
	deps := &Dependencies{AccessContentRepo: repo}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content", GetAccessRetentionContent(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_forward_001/content", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.tenantID != "tenant_default" || repo.requestID != "req_forward_001" {
		t.Fatalf("unexpected repo scope: tenant=%s request=%s", repo.tenantID, repo.requestID)
	}

	payload := w.Body.Bytes()
	assertCustomerRetentionResponseHasNoLegacyFields(t, payload)
	var resp struct {
		RequestID      string `json:"request_id"`
		UserInput      string `json:"user_input"`
		ModelOutput    string `json:"model_output"`
		RetentionUntil string `json:"retention_until"`
		Artifacts      []struct {
			DisplayName string `json:"display_name"`
			Status      string `json:"retention_status"`
		} `json:"artifacts"`
		EvidenceStatus string `json:"evidence_status"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.RequestID != "req_forward_001" || resp.UserInput == "" || resp.ModelOutput != "报告摘要正常" {
		t.Fatalf("unexpected content response: %+v", resp)
	}
	if resp.RetentionUntil != "2026-09-01T00:00:00Z" {
		t.Fatalf("retention_until = %q, want 2026-09-01T00:00:00Z", resp.RetentionUntil)
	}
	if len(resp.Artifacts) != 1 || resp.Artifacts[0].DisplayName != "report.pdf" || resp.Artifacts[0].Status != "reference_only" || resp.EvidenceStatus != "evidence_gap" {
		t.Fatalf("legacy metadata must be a safe evidence gap: %+v", resp)
	}
}

// TestGetAccessRetentionContentMergesReferencedUploadBytes 覆盖网页版三段式上传的展示路径：
// 对话行只携带 source=json_file_reference 的引用(无字节)，详情接口必须按 reference_id
// 在请求所属租户内解引用，把真实图片/文件字节合并回该条目，并改写成可预览/下载的真实文件。
func TestGetAccessRetentionContentMergesReferencedUploadBytes(t *testing.T) {
	repo := &fakeAccessContentRepo{
		fileMetadataJSON: []byte(`[{"source":"json_file_reference","stage":"request","reference_id":"file-abc","has_bytes":false}]`),
		resolved: map[string]repository.ResolvedUploadedFile{
			"file-abc": {
				ReferenceID: "file-abc",
				FileName:    "chest_ct.png",
				ContentType: "image/png",
				SHA256:      "deadbeef",
				DataBase64:  "QV9JTUFHRV9CWVRFUw==",
				Size:        18,
			},
		},
	}
	deps := &Dependencies{AccessContentRepo: repo}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content", GetAccessRetentionContent(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_forward_chat_001/content", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.resolveTenantID != "" || len(repo.resolveReferences) != 0 {
		t.Fatalf("typed detail must not resolve legacy reference bytes: tenant=%q refs=%#v", repo.resolveTenantID, repo.resolveReferences)
	}
	if strings.Contains(w.Body.String(), "file-abc") || strings.Contains(w.Body.String(), "QV9JTUFHRV9CWVRFUw==") {
		t.Fatalf("typed detail leaked legacy reference or bytes: %s", w.Body.String())
	}
}

func TestGetAccessRetentionImageProxyFetchesOnlyRetainedImageURL(t *testing.T) {
	imageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/qwen.png" {
			t.Fatalf("unexpected image path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("PNG_BYTES"))
	}))
	defer imageServer.Close()
	oldAllow := accessRetentionImageURLAllowed
	accessRetentionImageURLAllowed = func(ctx context.Context, u *url.URL) bool { return true }
	defer func() { accessRetentionImageURLAllowed = oldAllow }()
	oldClient := accessRetentionImageHTTPClient
	accessRetentionImageHTTPClient = &http.Client{Timeout: 2 * time.Second, Transport: http.DefaultTransport}
	defer func() { accessRetentionImageHTTPClient = oldClient }()

	imageURL := imageServer.URL + "/qwen.png?x-expires=1783834240"
	repo := &fakeAccessContentRepo{
		fileMetadataJSON: []byte(`[{"source":"response_url","stage":"response","download_url":"` + imageURL + `","content_type":"image/png"}]`),
	}
	deps := &Dependencies{AccessContentRepo: repo}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/image-proxy", GetAccessRetentionImageProxy(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_qwen_image/image-proxy?url="+url.QueryEscape(imageURL), nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.tenantID != "tenant_default" || repo.requestID != "req_qwen_image" {
		t.Fatalf("unexpected repo scope: tenant=%s request=%s", repo.tenantID, repo.requestID)
	}
	if got := w.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("content-type = %q, want image/png", got)
	}
	if w.Body.String() != "PNG_BYTES" {
		t.Fatalf("unexpected image body: %q", w.Body.String())
	}
}

func TestGetAccessRetentionImageProxyRejectsURLNotInRetainedContent(t *testing.T) {
	repo := &fakeAccessContentRepo{
		fileMetadataJSON: []byte(`[{"source":"response_url","stage":"response","download_url":"https://img.example.com/kept.png","content_type":"image/png"}]`),
	}
	deps := &Dependencies{AccessContentRepo: repo}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/image-proxy", GetAccessRetentionImageProxy(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_qwen_image/image-proxy?url="+url.QueryEscape("https://img.example.com/other.png"), nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unretained URL, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetAccessRetentionImageProxyRejectsRedirectToPrivateAddress(t *testing.T) {
	privateServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("PRIVATE_IMAGE"))
	}))
	defer privateServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, privateServer.URL+"/secret.png", http.StatusFound)
	}))
	defer redirectServer.Close()

	oldAllow := accessRetentionImageURLAllowed
	accessRetentionImageURLAllowed = func(ctx context.Context, u *url.URL) bool {
		return u.Host == strings.TrimPrefix(redirectServer.URL, "http://")
	}
	defer func() { accessRetentionImageURLAllowed = oldAllow }()

	oldClient := accessRetentionImageHTTPClient
	accessRetentionImageHTTPClient = &http.Client{
		Timeout:       2 * time.Second,
		Transport:     http.DefaultTransport,
		CheckRedirect: accessRetentionImageRedirectPolicy,
	}
	defer func() { accessRetentionImageHTTPClient = oldClient }()

	imageURL := redirectServer.URL + "/qwen.png"
	repo := &fakeAccessContentRepo{
		fileMetadataJSON: []byte(`[{"source":"response_url","stage":"response","download_url":"` + imageURL + `","content_type":"image/png"}]`),
	}
	deps := &Dependencies{AccessContentRepo: repo}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/image-proxy", GetAccessRetentionImageProxy(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_qwen_image/image-proxy?url="+url.QueryEscape(imageURL), nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for private redirect target, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportForwardProxyAccessListErrorLogsInternalErrorWithoutLeaking(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{listErr: errors.New("database secret detail")}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}
	var logs strings.Builder
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/export?format=json", nil)
	req.Header.Set("X-Request-ID", "req-log-export")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin"}))
	w := httptest.NewRecorder()
	ExportForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(logs.String(), "access retention export list failed") || !strings.Contains(logs.String(), "database secret detail") {
		t.Fatalf("expected internal export list error in logs, got %q", logs.String())
	}
	if strings.Contains(w.Body.String(), "database secret detail") {
		t.Fatalf("response leaked internal error: %s", w.Body.String())
	}
}

func TestExportForwardProxyAccessCSV(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	repo.records = []repository.ForwardProxyAccessRecord{
		{
			RequestID:       "req_export_001",
			TenantID:        "tenant_default",
			CreatedAt:       time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC),
			SourceIP:        "10.0.0.9",
			TargetHost:      "api.deepseek.com",
			Provider:        "deepseek",
			ProviderCN:      "DeepSeek",
			AccessType:      "llm",
			Status:          "success",
			RiskState:       "risk",
			ActionTaken:     "audit",
			RetentionLevel:  "content",
			ContentRetained: true,
			AccessDirection: "forward",
			AgentType:       "workbuddy",
		},
	}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/export?format=csv&direction=reverse&risk_state=risk&provider=deepseek&target_host=api.deepseek.com&source_ip=10.0.0.9&agent_type=workbuddy&content_only=true&keyword=%E7%99%BB%E5%BD%95%E5%A4%B1%E8%B4%A5&from=2026-06-01T00%3A00%3A00Z&to=2026-06-30T00%3A00%3A00Z&limit=100000&offset=0", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ExportForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("expected text/csv content type, got %q", ct)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Fatalf("expected csv attachment disposition, got %q", cd)
	}
	body := w.Body.String()
	if !strings.Contains(body, "请求ID") {
		t.Fatalf("expected csv header with 请求ID, got: %s", body)
	}
	if !strings.Contains(body, "req_export_001") || !strings.Contains(body, "api.deepseek.com") {
		t.Fatalf("expected csv data row, got: %s", body)
	}
	if !strings.Contains(body, "正向代理") {
		t.Fatalf("expected direction label 正向代理 in csv, got: %s", body)
	}
	if !strings.Contains(body, "智能体") {
		t.Fatalf("expected csv header with 智能体 column, got: %s", body)
	}
	if !strings.Contains(body, "WorkBuddy") {
		t.Fatalf("expected agent label WorkBuddy cell in csv, got: %s", body)
	}
	if repo.capturedFilter.Direction != "reverse" {
		t.Fatalf("expected direction filter 'reverse', got %q", repo.capturedFilter.Direction)
	}
	if repo.capturedFilter.RiskState != "risk" || repo.capturedFilter.Provider != "deepseek" || repo.capturedFilter.TargetHost != "api.deepseek.com" || repo.capturedFilter.SourceIP != "10.0.0.9" || repo.capturedFilter.AgentType != "workbuddy" {
		t.Fatalf("expected export filters to be preserved, got risk=%q provider=%q target=%q source=%q agent=%q", repo.capturedFilter.RiskState, repo.capturedFilter.Provider, repo.capturedFilter.TargetHost, repo.capturedFilter.SourceIP, repo.capturedFilter.AgentType)
	}
	if !repo.capturedFilter.ContentOnly {
		t.Fatal("expected content_only filter to be preserved for export")
	}
	if repo.capturedFilter.Keyword != "登录失败" {
		t.Fatalf("expected keyword filter to be preserved for export, got %q", repo.capturedFilter.Keyword)
	}
	if !repo.capturedFilter.AllowLargeLimit || repo.capturedFilter.Limit != 5000 || repo.capturedFilter.Offset != 0 {
		t.Fatalf("expected bounded all-record export, got allow_large=%t limit=%d offset=%d", repo.capturedFilter.AllowLargeLimit, repo.capturedFilter.Limit, repo.capturedFilter.Offset)
	}
	if got := repo.capturedFilter.StartTime.Format(time.RFC3339); got != "2026-06-01T00:00:00Z" {
		t.Fatalf("expected export from filter to be preserved, got %s", got)
	}

	if got := repo.capturedFilter.EndTime.Format(time.RFC3339); got != "2026-06-30T00:00:00Z" {
		t.Fatalf("expected export to filter to be preserved, got %s", got)
	}
}

func TestExportForwardProxyAccessJSON(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	repo.records = []repository.ForwardProxyAccessRecord{
		{
			RequestID:       "req_export_json_001",
			TenantID:        "tenant_default",
			CreatedAt:       time.Date(2026, 6, 7, 11, 0, 0, 0, time.UTC),
			TargetHost:      "api.openai.com",
			Provider:        "openai",
			AccessType:      "llm",
			AccessDirection: "reverse",
		},
	}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/export?format=json", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ExportForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json content type, got %q", ct)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".json") {
		t.Fatalf("expected json attachment disposition, got %q", cd)
	}

	var resp struct {
		Data []struct {
			RequestID       string `json:"request_id"`
			TargetHost      string `json:"target_host"`
			AccessDirection string `json:"access_direction"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Data) != 1 {
		t.Fatalf("unexpected export response: %+v", resp)
	}
	if resp.Data[0].RequestID != "req_export_json_001" || resp.Data[0].TargetHost != "api.openai.com" || resp.Data[0].AccessDirection != "reverse" {
		t.Fatalf("unexpected export record: %+v", resp.Data[0])
	}
}

func TestExportForwardProxyAccessDefaultsToRecentTimeWindow(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	before := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/export?format=csv&access_type=llm", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ExportForwardProxyAccess(deps).ServeHTTP(w, req)
	after := time.Now().UTC()

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.capturedFilter.EndTime.Before(before) || repo.capturedFilter.EndTime.After(after.Add(time.Second)) {
		t.Fatalf("expected default export end time to be near now, got %s", repo.capturedFilter.EndTime.Format(time.RFC3339Nano))
	}
	expectedStart := repo.capturedFilter.EndTime.Add(-30 * 24 * time.Hour)
	if repo.capturedFilter.StartTime.Before(expectedStart.Add(-time.Second)) || repo.capturedFilter.StartTime.After(expectedStart.Add(time.Second)) {
		t.Fatalf("expected default export start time to be 30 days before end time, start=%s end=%s", repo.capturedFilter.StartTime.Format(time.RFC3339Nano), repo.capturedFilter.EndTime.Format(time.RFC3339Nano))
	}
}

func TestListForwardProxyAccessReturnsAIDevelopmentToolSummary(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{
		records: []repository.ForwardProxyAccessRecord{
			{RequestID: "req_cursor", TenantID: "tenant_default", CreatedAt: time.Date(2026, 6, 10, 9, 0, 0, 0, time.UTC), SourceIP: "10.0.0.8", TargetHost: "api5.cursor.sh", TargetPath: "/aiserver.v1.AgentService/StreamBidi", Method: "POST", Provider: "cursor", Product: "cursor_agent", AccessType: "ai_ide", EndpointKind: "coding", Status: "success", StatusCode: 200, TLSInspected: true, RetentionLevel: "content", ContentRetained: true, RiskState: "normal", ActionTaken: "allow", DispositionStatus: "open"},
		},
		summary: &repository.ForwardProxyAccessSummary{Total: 1, AIIdeCount: 1, RetainedContentCount: 1},
	}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?access_type=ai_ide", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin"}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.accessType != "ai_ide" {
		t.Fatalf("expected access_type filter ai_ide, got %q", repo.accessType)
	}
	var resp struct {
		Data []struct {
			AccessType string `json:"access_type"`
			Provider   string `json:"provider"`
			Product    string `json:"product"`
		} `json:"data"`
		Summary struct {
			AIIdeCount           int `json:"ai_ide_count"`
			RetainedContentCount int `json:"retained_content_count"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].AccessType != "ai_ide" || resp.Data[0].Provider != "cursor" || resp.Data[0].Product != "cursor_agent" {
		t.Fatalf("unexpected AI IDE response: %+v", resp)
	}
	if resp.Summary.AIIdeCount != 1 || resp.Summary.RetainedContentCount != 1 {
		t.Fatalf("unexpected AI IDE summary: %+v", resp.Summary)
	}
}

// 安全告警页(UnifiedAlerts)只用列表行，丢弃 summary 与 total。当它带上
// skip_summary/skip_total 退订参数时，处理器必须跳过整表汇总(GetForwardProxyAccessSummary)
// 并向仓储传 SkipTotal=true（让仓储跳过无界 COUNT），从而把这页从 ~13s 降到 ~4s。
func TestListForwardProxyAccessUsesAuthoritativeOverviewForUnfilteredQuery(t *testing.T) {
	bucket := time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC)
	repo := &fakeForwardProxyAccessRepo{summary: &repository.ForwardProxyAccessSummary{
		Total:            9,
		LLMCount:         8,
		RiskCount:        2,
		UniqueModelCount: 3,
		EvidenceQuality: repository.ForwardProxyEvidenceQuality{
			CompleteCount: 9,
		},
		Timeline: []repository.ForwardProxyAccessTimelinePoint{{Bucket: bucket, TotalCount: 9, NormalCount: 7, RiskCount: 2}},
	}}
	rollup := &fakeAccessRollupSummaryRepo{out: repository.ForwardProxyAccessSummary{Total: 9, LLMCount: 8, RiskCount: 2, ForwardCount: 9, DataFreshUntil: &bucket}}
	deps := &Dependencies{ForwardProxyAccessRepo: repo, AccessRollupRepo: rollup}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_admin", TenantID: "tenant_default", Role: "platform_admin"}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if rollup.called || !repo.summaryCalled {
		t.Fatalf("overview must use authoritative raw summary, rollup=%v raw=%v", rollup.called, repo.summaryCalled)
	}
	var resp types.ForwardProxyAccessListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 1 || resp.Summary.Total != 9 || resp.Summary.UniqueModelCount != 3 || resp.Summary.EvidenceQuality.CompleteCount != 9 || len(resp.Summary.Timeline) != 1 {
		t.Fatalf("unexpected authoritative overview response: %+v", resp)
	}
}

func TestListForwardProxyAccessIgnoresIncompleteRollupWhenEmpty(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{summary: &repository.ForwardProxyAccessSummary{Total: 3, BlockedCount: 1}}
	rollup := &fakeAccessRollupSummaryRepo{out: repository.ForwardProxyAccessSummary{}}
	deps := &Dependencies{ForwardProxyAccessRepo: repo, AccessRollupRepo: rollup}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_admin", TenantID: "tenant_default", Role: "platform_admin"}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if rollup.called || !repo.summaryCalled {
		t.Fatalf("expected authoritative raw summary only, rollup=%v raw=%v", rollup.called, repo.summaryCalled)
	}
	var resp types.ForwardProxyAccessListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Summary.Total != 3 || resp.Summary.BlockedCount != 1 {
		t.Fatalf("unexpected fallback summary: %+v", resp.Summary)
	}
}

func TestListForwardProxyAccessSkipSummarySkipsAccessRollup(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	rollup := &fakeAccessRollupSummaryRepo{out: repository.ForwardProxyAccessSummary{Total: 9}}
	deps := &Dependencies{ForwardProxyAccessRepo: repo, AccessRollupRepo: rollup}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?skip_summary=true", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_admin", TenantID: "tenant_default", Role: "platform_admin"}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if rollup.called || repo.summaryCalled {
		t.Fatalf("skip_summary should skip both rollup and legacy summary, rollup=%v legacy=%v", rollup.called, repo.summaryCalled)
	}
}

func TestListForwardProxyAccessSummaryOnlySkipsList(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{
		summary: &repository.ForwardProxyAccessSummary{Total: 42, LLMCount: 42, RetainedContentCount: 42},
	}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?summary_only=true&content_only=true", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.listCalled {
		t.Fatal("summary_only must not query paginated detail rows")
	}
	if !repo.summaryCalled {
		t.Fatal("summary_only must query the overview")
	}

	var resp struct {
		Data    []json.RawMessage `json:"data"`
		Total   int               `json:"total"`
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 0 || resp.Total != 42 || resp.Summary.Total != 42 {
		t.Fatalf("unexpected summary-only response: %+v", resp)
	}
}

func TestListForwardProxyAccessCountsSummarySkipsExpensiveBreakdown(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?summary_only=true&summary_detail=counts&access_type=all", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !repo.countsCalled || repo.summaryCalled || repo.listCalled {
		t.Fatalf("counts summary must avoid list and full breakdown, counts=%v summary=%v list=%v", repo.countsCalled, repo.summaryCalled, repo.listCalled)
	}
	if repo.tenantID != "tenant_default" || repo.capturedFilter.AccessType != "all" {
		t.Fatalf("counts summary must preserve tenant and all-access scope: tenant=%q filter=%+v", repo.tenantID, repo.capturedFilter)
	}
}

func TestListForwardProxyAccessSkipsSummaryAndCountWhenOptedOut(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?risk_state=risk&limit=500&skip_summary=true&skip_total=true", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.summaryCalled {
		t.Fatal("expected GetForwardProxyAccessSummary to be skipped when skip_summary=true")
	}
	if !repo.capturedFilter.SkipTotal {
		t.Fatal("expected SkipTotal=true to be passed to repository when skip_total=true")
	}

	var resp struct {
		Data []struct {
			RequestID string `json:"request_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].RequestID != "req_forward_001" {
		t.Fatalf("list rows must still be returned when summary/count are skipped: %+v", resp)
	}
}

func TestListForwardProxyAccessDefaultsToRecentTimeWindow(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	before := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?access_type=llm&direction=forward&content_only=true&skip_total=true", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)
	after := time.Now().UTC()

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if repo.capturedFilter.EndTime.Before(before) || repo.capturedFilter.EndTime.After(after.Add(time.Second)) {
		t.Fatalf("expected default end time to be near now, got %s", repo.capturedFilter.EndTime.Format(time.RFC3339Nano))
	}
	expectedStart := repo.capturedFilter.EndTime.Add(-30 * 24 * time.Hour)
	if repo.capturedFilter.StartTime.Before(expectedStart.Add(-time.Second)) || repo.capturedFilter.StartTime.After(expectedStart.Add(time.Second)) {
		t.Fatalf("expected default start time to be 30 days before end time, start=%s end=%s", repo.capturedFilter.StartTime.Format(time.RFC3339Nano), repo.capturedFilter.EndTime.Format(time.RFC3339Nano))
	}
}

func TestListForwardProxyAccessKeepsExplicitTimeWindow(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}
	from := "2026-06-01T00:00:00Z"
	to := "2026-06-21T08:00:00Z"

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?from="+url.QueryEscape(from)+"&to="+url.QueryEscape(to), nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := repo.capturedFilter.StartTime.Format(time.RFC3339); got != from {
		t.Fatalf("expected explicit from to be preserved, got %s", got)
	}
	if got := repo.capturedFilter.EndTime.Format(time.RFC3339); got != to {
		t.Fatalf("expected explicit to to be preserved, got %s", got)
	}
}

// 反向：留存详情页(AccessRetention)与内容审计页仍要 summary+total，所以默认不退订时
// 处理器必须照旧调用 GetForwardProxyAccessSummary 并保持 SkipTotal=false，确保改动只惠及
// 安全告警页、不破坏其它消费者。
func TestListForwardProxyAccessKeepsSummaryAndCountByDefault(t *testing.T) {
	repo := &fakeForwardProxyAccessRepo{}
	deps := &Dependencies{ForwardProxyAccessRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention?risk_state=risk&limit=500", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		Username: "admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	ListForwardProxyAccess(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !repo.summaryCalled {
		t.Fatal("expected GetForwardProxyAccessSummary to still be called by default")
	}
	if repo.capturedFilter.SkipTotal {
		t.Fatal("expected SkipTotal=false by default so AccessRetention/ContentAudit are unaffected")
	}
}
