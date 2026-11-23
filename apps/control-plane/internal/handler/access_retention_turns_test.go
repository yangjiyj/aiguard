package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
	"github.com/go-chi/chi/v5"
)

func TestRetentionTurnsCollapseLoopAndPreserveRepeatedHumanOccurrences(t *testing.T) {
	rows := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{RequestID: "r1", Role: "user", Content: "继续", CreatedAt: time.Unix(10, 0)},
		{RequestID: "r1", Role: "assistant", Content: "正在检查", CreatedAt: time.Unix(11, 0)},
		{RequestID: "r2", Role: "user", Content: "继续", CreatedAt: time.Unix(20, 0)},
		{RequestID: "r2", Role: "assistant", Content: "正在检查", CreatedAt: time.Unix(20, 0)},
		{RequestID: "r2", Role: "tool", Content: "内部工具回执", CreatedAt: time.Unix(20, 0)},
		{RequestID: "r2", Role: "assistant", Content: "第一轮结果", CreatedAt: time.Unix(21, 0)},
		{RequestID: "r3", Role: "user", Content: "继续", CreatedAt: time.Unix(30, 0)},
		{RequestID: "r3", Role: "assistant", Content: "第一轮结果", CreatedAt: time.Unix(30, 0)},
		{RequestID: "r3", Role: "user", Content: "继续", CreatedAt: time.Unix(30, 0)},
		{RequestID: "r3", Role: "assistant", Content: "第二轮结果", CreatedAt: time.Unix(31, 0)},
	}}
	projection, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: rows}, "tenant", []string{"r3", "r1", "r2"}, nil, "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.Turns) != 2 {
		t.Fatalf("turns=%+v", projection.Turns)
	}
	first, second := projection.Turns[0], projection.Turns[1]
	if first.UserInput != "继续" || second.UserInput != "继续" || first.ID == second.ID {
		t.Fatalf("repeated occurrences merged: %+v", projection.Turns)
	}
	if first.Answer == nil || first.Answer.Content != "第一轮结果" || second.Answer == nil || second.Answer.Content != "第二轮结果" {
		t.Fatalf("answers=%+v", projection.Turns)
	}
	if first.Status != "unconfirmed" || first.FinalitySource != "last_observed_response" {
		t.Fatalf("must not claim client completion: %+v", first)
	}
	process := projection.Process[first.ID]
	if len(process) != 1 || process[0].Content != "正在检查" {
		t.Fatalf("process=%+v", process)
	}
	serialized, _ := json.Marshal(projection.Turns)
	if strings.Contains(string(serialized), "内部工具回执") || strings.Contains(string(serialized), "正在检查") {
		t.Fatalf("summary leaked process: %s", serialized)
	}
}

func TestRetentionTurnsDoNotReuseStaleAnswerAfterResponseGap(t *testing.T) {
	items := []repository.AccessContentLog{
		{RequestID: "r1", SectionID: "turn-1", RequestContent: "修复", ResponseContent: "开始修复", CreatedAt: time.Unix(10, 0)},
		{RequestID: "r2", SectionID: "turn-1", RequestContent: "修复", CreatedAt: time.Unix(20, 0)},
	}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{}, "tenant", []string{"r2", "r1"}, items, "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Turns) != 1 || p.Turns[0].Answer != nil || p.Turns[0].Status != "response_unavailable" || p.Turns[0].RequestCount != 2 {
		t.Fatalf("stale response treated as answer: %+v", p.Turns)
	}
	if len(p.Process[p.Turns[0].ID]) != 1 {
		t.Fatal("lost earlier progress")
	}
}

func TestRetentionTurnsKeepDistinctSectionsAndUnlinkedRequestsSeparate(t *testing.T) {
	items := []repository.AccessContentLog{
		{RequestID: "r1", SectionID: "turn-1", RequestContent: "继续", ResponseContent: "一"},
		{RequestID: "r2", SectionID: "turn-2", RequestContent: "继续", ResponseContent: "二"},
		{RequestID: "r3", RequestContent: "继续", ResponseContent: "三"},
		{RequestID: "r4", RequestContent: "继续", ResponseContent: "四"},
	}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{}, "tenant", []string{"r1", "r2", "r3", "r4"}, items, "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Turns) != 4 {
		t.Fatalf("unrelated requests merged: %+v", p.Turns)
	}
}

func TestRetentionTurnsScopedEndpointAndProcessPagination(t *testing.T) {
	reader := &fallbackContentLogReader{logs: []repository.ContentLog{{RequestID: "r1", Role: "user", Content: "问题"}, {RequestID: "r1", Role: "assistant", Content: "答复"}}}
	serve := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/audit/access-retention/r1/content?"+query, nil)
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("request_id", "r1")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "admin", Role: "platform_admin", TenantID: "tenant-a"}))
		w := httptest.NewRecorder()
		GetAccessRetentionContent(&Dependencies{AccessContentRepo: &nilAccessContentRepo{}, ContentLogReader: reader}).ServeHTTP(w, r)
		return w
	}
	w := serve("view=turns")
	if w.Code != 200 {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	var payload types.AccessRetentionContentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Turns) != 1 || len(payload.Messages) != 0 {
		t.Fatalf("payload=%s", w.Body.String())
	}
	if reader.gotTenantID != "tenant-a" || reader.gotRequestID != "r1" {
		t.Fatal("scope lost")
	}
	w = serve("view=turn_process&turn_id=" + payload.Turns[0].ID + "&offset=0&limit=20")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "\"has_more\":false") {
		t.Fatalf("process=%d %s", w.Code, w.Body.String())
	}
	if w = serve("view=turn_process&turn_id=foreign"); w.Code != 404 {
		t.Fatalf("unknown turn status=%d", w.Code)
	}
	if w = serve("view=turn_process&turn_id=x&offset=-1"); w.Code != 400 {
		t.Fatalf("negative offset=%d", w.Code)
	}
}

func TestRetentionTurnsLongToolResultDoesNotBreakHumanBoundary(t *testing.T) {
	reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{RequestID: "r1", Role: "user", Content: "检查", CreatedAt: time.Unix(1, 0)},
		{RequestID: "r1", Role: "assistant", Content: "检查中", CreatedAt: time.Unix(2, 0)},
		{RequestID: "r2", Role: "user", Content: "检查", CreatedAt: time.Unix(3, 0)},
		{RequestID: "r2", Role: "assistant", Content: "检查中", CreatedAt: time.Unix(3, 0)},
		{RequestID: "r2", Role: "tool", Content: "large...[truncated]", ContentTruncated: true, CreatedAt: time.Unix(3, 0)},
		{RequestID: "r2", Role: "assistant", Content: "检查结果", CreatedAt: time.Unix(4, 0)},
	}}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "t", []string{"r1", "r2"}, nil, "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Turns) != 1 || p.Turns[0].EvidenceStatus != "partial" {
		t.Fatalf("tool truncation split human occurrence: %+v", p.Turns)
	}
}

func TestRetentionTurnsDoNotTrimIndependentHumanInput(t *testing.T) {
	reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{RequestID: "r1", UserID: "a", SessionID: "session-a", Role: "user", Content: "第一行", CreatedAt: time.Unix(1, 0)},
		{RequestID: "r1", UserID: "a", SessionID: "session-a", Role: "assistant", Content: "收到", CreatedAt: time.Unix(2, 0)},
		{RequestID: "r2", UserID: "b", SessionID: "session-b", Role: "user", Content: "第一行\n第二行", CreatedAt: time.Unix(3, 0)},
		{RequestID: "r2", UserID: "b", SessionID: "session-b", Role: "assistant", Content: "好的", CreatedAt: time.Unix(4, 0)},
	}}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "t", []string{"r1", "r2"}, nil, "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Turns) != 2 || p.Turns[1].UserInput != "第一行\n第二行" {
		t.Fatalf("original question altered: %+v", p.Turns)
	}
}

func TestRetentionTurnsIgnoreRequestScopedSessionFallbackAndRequireCausalReplay(t *testing.T) {
	reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{RequestID: "r1", SessionID: "r1", Role: "user", Content: "继续", CreatedAt: time.Unix(1, 0)},
		{RequestID: "r1", SessionID: "r1", Role: "assistant", Content: "检查中", CreatedAt: time.Unix(2, 0)},
		{RequestID: "r2", SessionID: "r2", Role: "user", Content: "继续", CreatedAt: time.Unix(3, 0)},
		{RequestID: "r2", SessionID: "r2", Role: "assistant", Content: "检查中", CreatedAt: time.Unix(3, 0)},
		{RequestID: "r2", SessionID: "r2", Role: "tool", Content: "结果", CreatedAt: time.Unix(3, 0)},
		{RequestID: "r2", SessionID: "r2", Role: "assistant", Content: "完成检查", CreatedAt: time.Unix(4, 0)},
		{RequestID: "r3", SessionID: "r3", Role: "user", Content: "继续", CreatedAt: time.Unix(5, 0)},
		{RequestID: "r3", SessionID: "r3", Role: "assistant", Content: "独立请求", CreatedAt: time.Unix(6, 0)},
	}}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "t", []string{"r1", "r2", "r3"}, nil, "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Turns) != 2 || p.Turns[0].RequestCount != 2 || p.Turns[1].RequestCount != 1 {
		t.Fatalf("synthetic session broke correlation or unrelated submission merged: %+v", p.Turns)
	}
}

type turnStateReader struct {
	orderedBatchContentLogReader
	states              []repository.RetentionRequestState
	gotTenant, gotScope string
	gotStart, gotEnd    time.Time
}

func (r *turnStateReader) ListRetentionRequestStatesScoped(_ context.Context, tenant string, _ []string, start, end time.Time, scope string) ([]repository.RetentionRequestState, error) {
	r.gotTenant, r.gotScope, r.gotStart, r.gotEnd = tenant, scope, start, end
	return r.states, nil
}
func TestRetentionTurnsUseRequestFailureFactsWithoutClaimingTaskCompletion(t *testing.T) {
	for raw, want := range map[string]string{"success": "unconfirmed", "failed": "request_failed", "provider_timeout": "request_failed", "stream_aborted": "interrupted", "client_canceled": "interrupted", "blocked": "blocked"} {
		t.Run(raw, func(t *testing.T) {
			reader := &turnStateReader{orderedBatchContentLogReader: orderedBatchContentLogReader{logs: []repository.ContentLog{
				{RequestID: "r1", Role: "user", Content: "问题"}, {RequestID: "r1", Role: "assistant", Content: "已完成"},
			}}, states: []repository.RetentionRequestState{{RequestID: "r1", Status: raw, CreatedAt: time.Unix(10, 0), LatencyMS: 500}}}
			start, end := time.Unix(0, 0), time.Unix(100, 0)
			p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant-a", []string{"r1"}, nil, "customer", start, end)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Turns) != 1 || p.Turns[0].Status != want || p.Turns[0].FinalitySource == "client_completion" {
				t.Fatalf("states=%+v", p.Turns)
			}
			if reader.gotTenant != "tenant-a" || reader.gotScope != "customer" || !reader.gotStart.Equal(start) || !reader.gotEnd.Equal(end) {
				t.Fatal("request state scope lost")
			}
		})
	}
}

func TestRetentionTurnsProcessPaginationDoesNotDuplicateOrLeakAnswer(t *testing.T) {
	items := []repository.AccessContentLog{}
	ids := []string{}
	for i := 0; i < 55; i++ {
		id := fmt.Sprintf("r%03d", i)
		ids = append(ids, id)
		items = append(items, repository.AccessContentLog{RequestID: id, SectionID: "human-submission", RequestContent: "检查", ResponseContent: fmt.Sprintf("reply-%d", i), CreatedAt: time.Unix(int64(i+1), 0)})
	}
	deps := &Dependencies{}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), deps, "tenant", ids, items, "", time.Time{}, time.Time{})
	if err != nil || len(p.Turns) != 1 {
		t.Fatalf("projection=%+v err=%v", p, err)
	}
	seen := map[string]bool{}
	for _, offset := range []int{0, 50, 100} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", fmt.Sprintf("/?view=turn_process&turn_id=%s&offset=%d&limit=50", p.Turns[0].ID, offset), nil)
		serveAccessRetentionTurns(w, r, deps, nil, "tenant", ids[0], ids, items, "", time.Time{}, time.Time{})
		if w.Code != 200 {
			t.Fatalf("page=%s", w.Body.String())
		}
		var page struct {
			Data    []types.AccessRetentionMessageInfo
			Total   int
			HasMore bool `json:"has_more"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.Total != 54 || page.HasMore != (offset == 0) {
			t.Fatalf("page=%+v", page)
		}
		for _, message := range page.Data {
			if seen[message.ID] || message.Content == "reply-54" {
				t.Fatalf("duplicate or main answer in process: %+v", message)
			}
			seen[message.ID] = true
		}
	}
	if len(seen) != 54 {
		t.Fatalf("lost process rows: %d", len(seen))
	}
}

func TestRetentionTurnsPreserveLegacyArtifactRequestAndArtifactOnlyExpansion(t *testing.T) {
	items := []repository.AccessContentLog{
		{RequestID: "r1", RequestContent: "第一问", ResponseContent: "第一答"},
		{RequestID: "r2", FileMetadataJSON: []byte(`[{"file_name":"second.pdf"}]`)},
	}
	w := httptest.NewRecorder()
	serveAccessRetentionTurns(w, httptest.NewRequest("GET", "/?view=turns", nil), &Dependencies{}, nil, "tenant", "r1", []string{"r1", "r2"}, items, "", time.Time{}, time.Time{})
	var info types.AccessRetentionContentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if len(info.Artifacts) != 1 || info.Artifacts[0].RequestID != "r2" || len(info.Turns) != 2 {
		t.Fatalf("misassigned file: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	serveAccessRetentionTurns(w, httptest.NewRequest("GET", "/?view=turn_process&turn_id="+info.Turns[1].ID, nil), &Dependencies{}, nil, "tenant", "r1", []string{"r1", "r2"}, items, "", time.Time{}, time.Time{})
	if w.Code != 200 {
		t.Fatalf("artifact-only expansion: %d %s", w.Code, w.Body.String())
	}
}

func TestRetentionTurnsNormalizeAgentEnvelopesThroughSharedProjection(t *testing.T) {
	for _, agent := range []string{"codex", "claude-code", "workbuddy", "opencode", "vscode"} {
		t.Run(agent, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "packages", "shared-go", "aimsg", "testdata", "agent-envelope-"+agent+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			input, status := safeRetentionUserInput(string(raw))
			if status != "complete" || input == "" {
				t.Fatalf("fixture projection %s: %q", status, input)
			}
			reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
				{RequestID: "r1", Role: "user", Content: string(raw), CreatedAt: time.Unix(1, 0)},
				{RequestID: "r1", Role: "assistant", Content: "正在检查", CreatedAt: time.Unix(2, 0)},
				{RequestID: "r2", Role: "user", Content: string(raw), CreatedAt: time.Unix(3, 0)},
				{RequestID: "r2", Role: "assistant", Content: "正在检查", CreatedAt: time.Unix(3, 0)},
				{RequestID: "r2", Role: "tool", Content: "工具回执", CreatedAt: time.Unix(3, 0)},
				{RequestID: "r2", Role: "assistant", Content: "检查结果", CreatedAt: time.Unix(4, 0)},
			}}
			p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant", []string{"r1", "r2"}, nil, "", time.Time{}, time.Time{})
			if err != nil || len(p.Turns) != 1 || p.Turns[0].UserInput != input || p.Turns[0].RequestCount != 2 || p.Turns[0].Answer == nil || p.Turns[0].Answer.Content != "检查结果" {
				t.Fatalf("agent %s: %+v err=%v", agent, p.Turns, err)
			}
		})
	}
}

func TestRetentionTurnsDoNotChooseBetweenAmbiguousParallelHistories(t *testing.T) {
	reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{RequestID: "r1", Role: "user", Content: "继续", CreatedAt: time.Unix(1, 0)},
		{RequestID: "r1", Role: "assistant", Content: "检查中", CreatedAt: time.Unix(2, 0)},
		{RequestID: "r2", Role: "user", Content: "继续", CreatedAt: time.Unix(3, 0)},
		{RequestID: "r2", Role: "assistant", Content: "检查中", CreatedAt: time.Unix(4, 0)},
		{RequestID: "r3", Role: "user", Content: "继续", CreatedAt: time.Unix(5, 0)},
		{RequestID: "r3", Role: "assistant", Content: "检查中", CreatedAt: time.Unix(5, 0)},
		{RequestID: "r3", Role: "tool", Content: "工具结果", CreatedAt: time.Unix(5, 0)},
		{RequestID: "r3", Role: "assistant", Content: "结果", CreatedAt: time.Unix(6, 0)},
	}}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant", []string{"r1", "r2", "r3"}, nil, "", time.Time{}, time.Time{})
	if err != nil || len(p.Turns) != 3 || p.Turns[2].CorrelationSource != "unlinked" {
		t.Fatalf("ambiguous history merged: %+v err=%v", p.Turns, err)
	}
}

func TestRetentionTurnsAcrossIngressContextsMergeToolOnlyRoundAndSplitNewQuestion(t *testing.T) {
	for _, ingress := range []string{"forward_proxy", "reverse_proxy", "chat_completion"} {
		t.Run(ingress, func(t *testing.T) {
			firstRequest := &retentionturn.Request{IdentityKey: retentionturn.Digest(ingress), HistoryKey: retentionturn.Digest("one-question"), UserCount: 1}
			link := retentionturn.Digest("tool-id\x00call-1")
			nextRequest := *firstRequest
			nextRequest.Links = []string{link}
			repeated := *firstRequest
			repeated.HistoryKey = retentionturn.Digest("two-questions")
			repeated.UserCount = 2
			reader := &turnStateReader{states: []repository.RetentionRequestState{
				{RequestID: "r1", CreatedAt: time.Unix(1, 0), TurnContext: retentionturn.Patch(firstRequest, &retentionturn.Response{Links: []string{link}})},
				{RequestID: "r2", CreatedAt: time.Unix(2, 0), TurnContext: retentionturn.Patch(&nextRequest, retentionturn.BuildResponse(nil, "第一轮结果"))},
				{RequestID: "r3", CreatedAt: time.Unix(3, 0), TurnContext: retentionturn.Patch(&repeated, retentionturn.BuildResponse(nil, "第二轮结果"))},
			}}
			items := []repository.AccessContentLog{{RequestID: "r1", RequestContent: "继续"}, {RequestID: "r2", RequestContent: "继续", ResponseContent: "第一轮结果"}, {RequestID: "r3", RequestContent: "继续", ResponseContent: "第二轮结果"}}
			p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant", []string{"r1", "r2", "r3"}, items, "customer", time.Unix(0, 0), time.Unix(10, 0))
			if err != nil || len(p.Turns) != 2 || p.Turns[0].RequestCount != 2 || p.Turns[1].RequestCount != 1 || p.Turns[0].Answer == nil || p.Turns[0].Answer.Content != "第一轮结果" || p.Turns[0].CorrelationSource != "ingress_context" {
				t.Fatalf("projection=%+v err=%v", p.Turns, err)
			}
		})
	}
}

func TestRetentionTurnsLinkIncrementalToolResultsOnlyWithinCaller(t *testing.T) {
	root := &retentionturn.Request{IdentityKey: "caller-a", HistoryKey: "history", UserCount: 1}
	followup := &retentionturn.Request{IdentityKey: "caller-a", UserCount: 0, Links: []string{"tool-link"}}
	foreign := &retentionturn.Request{IdentityKey: "caller-b", UserCount: 0, Links: []string{"tool-link"}}
	reader := &turnStateReader{states: []repository.RetentionRequestState{
		{RequestID: "r1", CreatedAt: time.Unix(1, 0), TurnContext: retentionturn.Patch(root, &retentionturn.Response{Links: []string{"tool-link"}})},
		{RequestID: "r2", CreatedAt: time.Unix(2, 0), TurnContext: retentionturn.Patch(followup, retentionturn.BuildResponse(nil, "最终观察到的答复"))},
		{RequestID: "r3", CreatedAt: time.Unix(3, 0), TurnContext: retentionturn.Patch(foreign, retentionturn.BuildResponse(nil, "无关调用者的答复"))},
	}}
	items := []repository.AccessContentLog{{RequestID: "r1", RequestContent: "原始问题"}, {RequestID: "r2", ResponseContent: "最终观察到的答复"}, {RequestID: "r3", ResponseContent: "无关调用者的答复"}}
	// Typed retention can contain response-only rows for linked incremental calls.
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant", []string{"r1", "r2", "r3"}, items, "customer", time.Unix(0, 0), time.Unix(10, 0))
	if err != nil || len(p.Turns) != 2 || p.Turns[0].RequestCount != 2 || p.Turns[0].UserInput != "原始问题" || p.Turns[0].Answer == nil || p.Turns[0].Answer.Content != "最终观察到的答复" || p.Turns[1].CorrelationSource != "unlinked" {
		t.Fatalf("projection=%+v err=%v", p.Turns, err)
	}
}

// Production writes can persist the response before the asynchronously recorded
// numbered history. Tool definitions must not turn a real response into a gap.
func TestRetentionTurnsSortResponseAfterNumberedHistory(t *testing.T) {
	zero, one, two := 0, 1, 2
	reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{RequestID: "r1", Role: "assistant", Content: "已修复协议转换", CreatedAt: time.Unix(11, 0)},
		{RequestID: "r1", Role: "user", Content: "看起来是协议转换的问题啊", MessageIndex: &zero, CreatedAt: time.Unix(12, 0)},
		{RequestID: "r1", Role: "system", Content: "Write", MessageIndex: &one, CreatedAt: time.Unix(12, 0)},
		{RequestID: "r1", Role: "system", Content: "tool schema", MessageIndex: &two, CreatedAt: time.Unix(12, 0)},
	}}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant", []string{"r1"}, nil, "", time.Time{}, time.Time{})
	if err != nil || len(p.Turns) != 1 || p.Turns[0].Answer == nil || p.Turns[0].Answer.Content != "已修复协议转换" {
		t.Fatalf("response lost: %+v %v", p.Turns, err)
	}
}

func TestRetentionTurnsKeepCausalAnchorAcrossToolOnlyRequest(t *testing.T) {
	reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{RequestID: "r1", Role: "user", Content: "修复", CreatedAt: time.Unix(10, 0)},
		{RequestID: "r1", Role: "assistant", Content: "开始检查", CreatedAt: time.Unix(11, 0)},
		{RequestID: "r2", Role: "user", Content: "修复", CreatedAt: time.Unix(20, 0)},
		{RequestID: "r2", Role: "assistant", Content: "开始检查", CreatedAt: time.Unix(20, 0)},
		{RequestID: "r2", Role: "system", Content: "工具定义", CreatedAt: time.Unix(20, 0)},
		{RequestID: "r3", Role: "user", Content: "修复", CreatedAt: time.Unix(30, 0)},
		{RequestID: "r3", Role: "assistant", Content: "开始检查", CreatedAt: time.Unix(30, 0)},
		{RequestID: "r3", Role: "tool", Content: "结果", CreatedAt: time.Unix(30, 0)},
		{RequestID: "r3", Role: "assistant", Content: "修复完成", CreatedAt: time.Unix(31, 0)},
	}}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant", []string{"r1", "r2", "r3"}, nil, "", time.Time{}, time.Time{})
	if err != nil || len(p.Turns) != 1 || p.Turns[0].RequestCount != 3 || p.Turns[0].Answer == nil || p.Turns[0].Answer.Content != "修复完成" {
		t.Fatalf("tool-only call split human question: %+v %v", p.Turns, err)
	}
}

func TestRetentionTurnsExcludeMachineWorkloadsAndTheirResponses(t *testing.T) {
	for _, noise := range []string{
		"## Memory Writing Agent: Phase 2 (Consolidation)\n\nYou are a Memory Writing Agent.\nYour job: consolidate raw memories and rollout summaries.\nWHAT COUNTS AS HIGH-SIGNAL MEMORY",
		"Heartbeat poll: check whether there is new work.",
		"[Thu 2026-09-10 09:07 GMT+8] [OpenClaw heartbeat poll]",
		"CRITICAL: Respond with TEXT ONLY. Do NOT call any tools.\nCreate a summary of this conversation.",
	} {
		reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
			{RequestID: "r1", Role: "user", Content: "真实问题"},
			{RequestID: "r1", Role: "assistant", Content: "真实回答"},
			{RequestID: "r2", Role: "user", Content: "真实问题"},
			{RequestID: "r2", Role: "assistant", Content: "真实回答"},
			{RequestID: "r2", Role: "user", Content: noise},
			{RequestID: "r2", Role: "assistant", Content: "内部总结，不是用户答复"},
		}}
		p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant", []string{"r1", "r2"}, nil, "", time.Time{}, time.Time{})
		if err != nil || len(p.Turns) != 1 || p.Turns[0].UserInput != "真实问题" || p.Turns[0].Answer == nil || p.Turns[0].Answer.Content != "真实回答" {
			t.Fatalf("machine workload leaked: %+v %v", p.Turns, err)
		}
	}
	for _, text := range []string{"解释一下 Memory Writing Agent 的作用", "帮我排查 heartbeat poll 日志", "请总结我们的对话"} {
		if got, status := safeRetentionUserInput(text); got != text || status != "complete" {
			t.Fatalf("human question hidden: %q", text)
		}
	}
}

func TestRetentionTurnsProtectedProductionReplay(t *testing.T) {
	path := os.Getenv("RETENTION_REPLAY_FIXTURE")
	if path == "" {
		t.Skip("explicit protected read-only fixture not configured")
	}
	var fixture struct {
		Logs   []repository.ContentLog
		States []repository.RetentionRequestState
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Logs) == 0 {
		t.Fatal("empty fixture")
	}
	reader := &turnStateReader{orderedBatchContentLogReader: orderedBatchContentLogReader{logs: fixture.Logs}, states: fixture.States}
	ids := []string{}
	for _, state := range fixture.States {
		ids = append(ids, state.RequestID)
	}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, fixture.Logs[0].TenantID, ids, nil, "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	answers, questionCount := 0, 0
	for _, turn := range p.Turns {
		if strings.Contains(turn.UserInput, "看起来是协议转换的问题啊") {
			questionCount++
		}
		if turn.Answer != nil {
			answers++
		}
		if isRetentionBackgroundWorkload(turn.UserInput) {
			t.Fatal("background prompt leaked")
		}
	}
	t.Logf("requests=%d turns=%d answers=%d target_question_occurrences=%d", len(ids), len(p.Turns), answers, questionCount)
	if answers == 0 {
		t.Fatal("lost every response")
	}
	if dest := os.Getenv("RETENTION_REPLAY_OUTPUT"); dest != "" {
		body, _ := json.Marshal(p)
		if err = os.WriteFile(dest, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRetentionVerifiedHistoryCollapsesPhysicalCallsAcrossChannels(t *testing.T) {
	for _, channel := range []string{"forward", "reverse", "chat_completion"} {
		t.Run(channel, func(t *testing.T) {
			question := "请修复 <problem>"
			framed, _ := json.Marshal([]string{question})
			history := retentionturn.Digest(string(framed))
			reader := &turnStateReader{}
			items := []repository.AccessContentLog{}
			ids := []string{}
			for i := 0; i < 430; i++ {
				id := fmt.Sprintf("r-%03d", i)
				ids = append(ids, id)
				req := &retentionturn.Request{IdentityKey: channel, HistoryKey: history, UserCount: 1, Partial: true}
				reader.states = append(reader.states, repository.RetentionRequestState{RequestID: id, ConversationID: "conversation-a", CreatedAt: time.Unix(int64(i), 0), TurnContext: retentionturn.Patch(req, nil)})
				output := "过程进度"
				if i == 429 {
					output = "修复完成的答复"
				}
				items = append(items, repository.AccessContentLog{RequestID: id, RequestContent: question, ResponseContent: output})
			}
			// A second real submission has a different complete history even if its words repeat.
			framed, _ = json.Marshal([]string{question, question})
			req := &retentionturn.Request{IdentityKey: channel, HistoryKey: retentionturn.Digest(string(framed)), UserCount: 2}
			reader.states = append(reader.states, repository.RetentionRequestState{RequestID: "next", ConversationID: "conversation-a", CreatedAt: time.Unix(500, 0), TurnContext: retentionturn.Patch(req, nil)})
			items = append(items, repository.AccessContentLog{RequestID: "next", RequestContent: question, ResponseContent: "下一轮答复"})
			ids = append(ids, "next")
			p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "t", ids, items, "customer", time.Unix(0, 0), time.Unix(1000, 0))
			if err != nil || len(p.Turns) != 2 || p.Turns[0].RequestCount != 430 || p.Turns[0].Answer.Content != "修复完成的答复" || len(p.Process[p.Turns[0].ID]) != 429 {
				t.Fatalf("physical calls were displayed as questions: turns=%d err=%v", len(p.Turns), err)
			}
		})
	}
}

func TestRetentionPartialUnverifiedHistoryCannotMerge(t *testing.T) {
	reader := &turnStateReader{states: []repository.RetentionRequestState{}}
	items := []repository.AccessContentLog{}
	for i, id := range []string{"r1", "r2"} {
		reader.states = append(reader.states, repository.RetentionRequestState{RequestID: id, ConversationID: "c", CreatedAt: time.Unix(int64(i), 0), TurnContext: retentionturn.Patch(&retentionturn.Request{IdentityKey: "i", HistoryKey: "unverifiable", UserCount: 1, Partial: true}, nil)})
		items = append(items, repository.AccessContentLog{RequestID: id, RequestContent: "截断输入"})
	}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "t", []string{"r1", "r2"}, items, "customer", time.Time{}, time.Time{})
	if err != nil || len(p.Turns) != 2 {
		t.Fatal("unverified history merged")
	}
}

func TestRetentionActual430RequestReplay(t *testing.T) {
	path := os.Getenv("RETENTION_DIALOGUE_FIXTURE")
	if path == "" {
		t.Skip("protected fixture not configured")
	}
	var fixture struct {
		States []repository.RetentionRequestState
		Items  []repository.AccessContentLog
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	reader := &turnStateReader{states: fixture.States}
	ids := []string{}
	for _, state := range fixture.States {
		ids = append(ids, state.RequestID)
	}
	p, err := buildAccessRetentionTurnsScoped(context.Background(), &Dependencies{ContentLogReader: reader}, "replay", ids, fixture.Items, "customer", time.Time{}, time.Time{})
	if err != nil || len(p.Turns) != 1 || p.Turns[0].RequestCount != 430 || p.Turns[0].Answer == nil {
		t.Fatalf("requests=%d turns=%d err=%v", len(ids), len(p.Turns), err)
	}
	t.Logf("actual requests=%d questions=%d process_replies=%d answer_present=%t", len(ids), len(p.Turns), p.Turns[0].ProcessCount, p.Turns[0].Answer != nil)
}
