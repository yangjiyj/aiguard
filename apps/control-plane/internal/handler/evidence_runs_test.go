package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type fakeEvidenceRunRepo struct {
	view, tenant string
	filter       repository.ForwardProxyAccessFilter
}

func (f *fakeEvidenceRunRepo) ListEvidenceRuns(_ context.Context, tenantID, view string, filter repository.ForwardProxyAccessFilter) ([]repository.EvidenceRunRecord, int, error) {
	f.tenant, f.view, f.filter = tenantID, view, filter
	return []repository.EvidenceRunRecord{{
		RunID: "evr_1", Kind: "agent_task", CorrelationSource: "responses_prompt_cache_key",
		CorrelationConfidence: "exact", RepresentativeRequestID: "req-2",
		MemberRequestIDs: []string{"req-1", "req-2"}, Title: "制作政企版安全网关 PPT",
		StartedAt: time.Date(2026, 8, 5, 2, 40, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 8, 5, 2, 50, 0, 0, time.UTC),
		AgentType: "openai-codex", AgentRuntime: "vscode", AgentDetectionSource: "content",
		AgentDetectionConfidence: 0.98, Models: []string{"gpt-5.6-sol"},
		AccessDirections: []string{"chat_completion"}, RequestCount: 12,
		EvidenceStatus: "complete", RiskState: "normal",
	}}, 1, nil
}

func TestListEvidenceRunsReturnsTaskLevelEvidence(t *testing.T) {
	repo := &fakeEvidenceRunRepo{}
	deps := &Dependencies{EvidenceRunRepo: repo}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/runs?view=agent_tasks&keyword=%E7%99%BB%E5%BD%95%E5%A4%B1%E8%B4%A5&limit=20", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant-1"}))
	w := httptest.NewRecorder()

	ListEvidenceRuns(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.tenant != "tenant-1" || repo.view != "agent_tasks" || !repo.filter.ContentOnly {
		t.Fatalf("repo call tenant=%q view=%q filter=%+v", repo.tenant, repo.view, repo.filter)
	}
	if repo.filter.Keyword != "登录失败" {
		t.Fatalf("keyword=%q want 登录失败", repo.filter.Keyword)
	}
	if !repo.filter.SkipTotal || !repo.filter.ProbeHasMore {
		t.Fatalf("evidence run pagination must use limit+1 without exact total: %+v", repo.filter)
	}
	var body struct {
		Data []struct {
			RunID                 string   `json:"run_id"`
			Title                 string   `json:"title"`
			AgentLabel            string   `json:"agent_label"`
			AgentRuntime          string   `json:"agent_runtime"`
			CorrelationConfidence string   `json:"correlation_confidence"`
			MemberRequestIDs      []string `json:"member_request_ids"`
			RequestCount          int      `json:"request_count"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Data) != 1 || body.Data[0].RunID != "evr_1" {
		t.Fatalf("body=%s", w.Body.String())
	}
	item := body.Data[0]
	if item.Title != "制作政企版安全网关 PPT" || item.AgentLabel != "OpenAI Codex" || item.AgentRuntime != "vscode" || item.CorrelationConfidence != "exact" || item.RequestCount != 12 || len(item.MemberRequestIDs) != 2 {
		t.Fatalf("item=%+v body=%s", item, w.Body.String())
	}
}

func TestListEvidenceRunsKeepsExactCountWithinRequestedLimit(t *testing.T) {
	repo := &fakeEvidenceRunRepo{}
	deps := &Dependencies{EvidenceRunRepo: repo}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/runs?view=agent_tasks&skip_total=false&limit=20", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant-1"}))
	w := httptest.NewRecorder()

	ListEvidenceRuns(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.filter.SkipTotal || repo.filter.ProbeHasMore {
		t.Fatalf("exact-count pagination must not request a limit+1 probe: %+v", repo.filter)
	}
	var body struct {
		TotalKnown bool `json:"total_known"`
		HasMore    bool `json:"has_more"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.TotalKnown || body.HasMore {
		t.Fatalf("unexpected exact-count response: %s", w.Body.String())
	}
}

func TestMapEvidenceRunInfoMarksCodexMemorySynthesisAsBackgroundTask(t *testing.T) {
	got := mapEvidenceRunInfo(repository.EvidenceRunRecord{
		RunID: "evr_memory", Kind: "agent_task", AgentType: "openai-codex",
		Title:     "Analyze this rollout and extract durable memory for future Codex tasks.",
		StartedAt: time.Date(2026, 8, 5, 2, 40, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 8, 5, 2, 41, 0, 0, time.UTC),
	})
	if got.TaskClass != "codex_background_memory" || got.Title != "Codex 后台记忆整理" {
		t.Fatalf("background task=%+v", got)
	}
}

func TestMapEvidenceRunInfoProjectsVSCodeRuntimeTitle(t *testing.T) {
	got := mapEvidenceRunInfo(repository.EvidenceRunRecord{
		RunID: "evr_vscode", Kind: "agent_task", AgentType: "vscode",
		Title: `<current_datetime>2026-09-03T04:51:10.219+08:00</current_datetime>
继续
<system_reminder><sql_tables>todos, todo_deps</sql_tables></system_reminder>
你在干嘛`,
		StartedAt: time.Date(2026, 9, 3, 4, 51, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 3, 4, 58, 0, 0, time.UTC),
	})
	if got.Title != "继续\n你在干嘛" || strings.Contains(got.Title, "sql_tables") {
		t.Fatalf("projected VS Code title=%q", got.Title)
	}
}

func TestMapEvidenceRunInfoProjectsWorkBuddySessionTitles(t *testing.T) {
	complete := mapEvidenceRunInfo(repository.EvidenceRunRecord{
		RunID: "evr_workbuddy_complete", Kind: "agent_task", AgentType: "workbuddy",
		Title: "<session>\n@image#1:Clipboard_Screenshot.png 这个是什么意思\n</session>",
	})
	if complete.Title != "这个是什么意思" {
		t.Fatalf("complete WorkBuddy title=%q", complete.Title)
	}

	prefix := "<session>\n历史长任务正文"
	truncated := prefix + strings.Repeat("任", 160-len([]rune(prefix)))
	projected := mapEvidenceRunInfo(repository.EvidenceRunRecord{
		RunID: "evr_workbuddy_truncated", Kind: "agent_task", AgentType: "workbuddy", Title: truncated,
	})
	if strings.HasPrefix(projected.Title, "<session>") || !strings.HasPrefix(projected.Title, "历史长任务正文") {
		t.Fatalf("truncated WorkBuddy title=%q", projected.Title)
	}

	crlfPrefix := "<session>\r\nCRLF 历史标题"
	crlfTruncated := crlfPrefix + strings.Repeat("任", 160-len([]rune(crlfPrefix))-1) + " "
	crlfProjected := mapEvidenceRunInfo(repository.EvidenceRunRecord{
		RunID: "evr_workbuddy_crlf", Kind: "agent_task", AgentType: "workbuddy", Title: crlfTruncated,
	})
	if strings.HasPrefix(crlfProjected.Title, "<session>") || !strings.HasPrefix(crlfProjected.Title, "CRLF 历史标题") {
		t.Fatalf("CRLF/space-truncated WorkBuddy title=%q", crlfProjected.Title)
	}
}

func TestMapEvidenceRunInfoProjectsStrictClineTaskTitle(t *testing.T) {
	got := mapEvidenceRunInfo(repository.EvidenceRunRecord{
		RunID: "evr_cline", Kind: "agent_task", AgentType: "cline",
		Title: "<task> 可以啊 </task>\n\n# task_progress RECOMMENDED\nWhen starting a task, include task_progress.",
	})
	if got.Title != "可以啊" {
		t.Fatalf("Cline title=%q", got.Title)
	}
}

func TestMapEvidenceRunInfoPreservesOrdinarySessionAndTaskMarkup(t *testing.T) {
	for _, test := range []struct {
		agent string
		title string
	}{
		{agent: "workbuddy", title: "<session> 是什么"},
		{agent: "workbuddy", title: "<session>ordinary XML</session>"},
		{agent: "cline", title: "<task>ordinary XML</task>"},
		{agent: "cline", title: "```xml\n<task>example</task>\n# task_progress RECOMMENDED\n```"},
	} {
		got := mapEvidenceRunInfo(repository.EvidenceRunRecord{
			RunID: "evr_xml", Kind: "agent_task", AgentType: test.agent, Title: test.title,
		})
		if got.Title != test.title {
			t.Fatalf("ordinary %s title changed: got %q want %q", test.agent, got.Title, test.title)
		}
	}
}

type backgroundEvidenceRunRepo struct{}

func (backgroundEvidenceRunRepo) ListEvidenceRuns(_ context.Context, _ string, _ string, _ repository.ForwardProxyAccessFilter) ([]repository.EvidenceRunRecord, int, error) {
	base := time.Date(2026, 8, 5, 2, 40, 0, 0, time.UTC)
	return []repository.EvidenceRunRecord{
		{
			RunID: "evr_memory", Kind: "agent_task", AgentType: "openai-codex",
			Title:     "Analyze this rollout and extract durable memory for future Codex tasks.",
			StartedAt: base, EndedAt: base.Add(time.Minute),
		},
		{
			RunID: "evr_customer", Kind: "agent_task", AgentType: "openai-codex",
			Title: "Fix the customer retention view", StartedAt: base, EndedAt: base.Add(time.Minute),
		},
	}, 2, nil
}

func TestListEvidenceRunsOmitsCodexBackgroundMemory(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/runs?view=agent_tasks", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant-1"}))
	w := httptest.NewRecorder()

	ListEvidenceRuns(&Dependencies{EvidenceRunRepo: backgroundEvidenceRunRepo{}}).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Data []struct {
			RunID string `json:"run_id"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Data) != 1 || body.Data[0].RunID != "evr_customer" {
		t.Fatalf("background memory leaked: %s", w.Body.String())
	}
}

func TestListEvidenceRunsRejectsUnknownView(t *testing.T) {
	deps := &Dependencies{EvidenceRunRepo: &fakeEvidenceRunRepo{}}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/runs?view=guess", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant-1"}))
	w := httptest.NewRecorder()
	ListEvidenceRuns(deps).ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

type fakeLongEvidenceTimelineRepo struct {
	members []string
}

func (f *fakeLongEvidenceTimelineRepo) ListEvidenceTimeline(_ context.Context, _ string, requestIDs []string) ([]repository.EvidenceTimelineEvent, error) {
	f.members = append([]string(nil), requestIDs...)
	return []repository.EvidenceTimelineEvent{{
		ID: "summary:model_calls", Type: "model_calls", Title: "模型交互", Count: len(requestIDs), Timestamp: time.Now(),
	}}, nil
}

func TestGetEvidenceTimelineAcceptsLongAgentTasksWithinBoundedLimit(t *testing.T) {
	const memberCount = 253
	members := make([]string, memberCount)
	for i := range members {
		members[i] = fmt.Sprintf("req-%03d", i)
	}
	repo := &fakeLongEvidenceTimelineRepo{}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req-000/timeline?members="+url.QueryEscape(strings.Join(members, ",")), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", "req-000")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{TenantID: "tenant-1"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	GetEvidenceTimeline(&Dependencies{EvidenceTimelineRepo: repo}).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(repo.members) != memberCount {
		t.Fatalf("members=%d want=%d", len(repo.members), memberCount)
	}
}

func TestGetEvidenceTimelineAcceptsLargeTaskMembersInJSONBody(t *testing.T) {
	const memberCount = 1221
	members := make([]string, memberCount)
	for i := range members {
		members[i] = fmt.Sprintf("req-%04d", i)
	}
	body, err := json.Marshal(map[string]interface{}{"members": members})
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeLongEvidenceTimelineRepo{}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/audit/access-retention/req-0000/timeline", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", "req-0000")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{TenantID: "tenant-1"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	GetEvidenceTimeline(&Dependencies{EvidenceTimelineRepo: repo}).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(repo.members) != memberCount {
		t.Fatalf("members=%d want=%d", len(repo.members), memberCount)
	}
}

func TestGetAccessRetentionContentAcceptsLargeTaskMembersInJSONBody(t *testing.T) {
	const memberCount = 1221
	members := make([]string, memberCount)
	for i := range members {
		members[i] = fmt.Sprintf("req-%04d", i)
	}
	body, err := json.Marshal(map[string]interface{}{"members": members})
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeAccessContentRepo{}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/audit/access-retention/req-0000/content", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", "req-0000")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{TenantID: "tenant-1"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	GetAccessRetentionContent(&Dependencies{AccessContentRepo: repo}).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(repo.requestIDs) != memberCount {
		t.Fatalf("members=%d want=%d", len(repo.requestIDs), memberCount)
	}
}

func TestEvidenceRunClassifiesNewBackgroundPrompts(t *testing.T) {
	if got := evidenceRunTaskClass("openai-codex", "## Memory Writing Agent: Phase 2 (Consolidation)\n\nYou are a Memory Writing Agent."); got != "codex_background_memory" {
		t.Fatal(got)
	}
	if got := evidenceRunTaskClass("openai-codex", "Heartbeat poll: check pending work"); got != "agent_background_poll" {
		t.Fatal(got)
	}
	if got := evidenceRunTaskClass("openai-codex", "解释一下 Memory Writing Agent 的作用"); got != "" {
		t.Fatal(got)
	}
}

func TestListEvidenceRunsProbeKnowsCompleteFirstPageTotal(t *testing.T) {
	deps := &Dependencies{EvidenceRunRepo: &fakeEvidenceRunRepo{}}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/runs?view=agent_tasks&skip_total=true&limit=20", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{TenantID: "tenant-1"}))
	w := httptest.NewRecorder()
	ListEvidenceRuns(deps).ServeHTTP(w, req)
	var got struct {
		TotalKnown bool `json:"total_known"`
		HasMore    bool `json:"has_more"`
		Total      int  `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || !got.TotalKnown || got.HasMore || got.Total != 1 {
		t.Fatalf("unexpected complete first page: %s", w.Body.String())
	}
}
