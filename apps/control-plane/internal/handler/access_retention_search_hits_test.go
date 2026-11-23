package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetentionSearchHitsExplainHistoricalMatchWithoutInventingCurrentAnswer(t *testing.T) {
	one, two, three := 1, 2, 3
	reader := &fallbackContentLogReader{logs: []repository.ContentLog{
		{TenantID: "tenant", RequestID: "r1", Role: "user", Content: "继续", MessageIndex: &one},
		{TenantID: "tenant", RequestID: "r1", Role: "assistant", Content: "我会继续检查之前的问题", MessageIndex: &two},
		{TenantID: "tenant", RequestID: "r1", Role: "user", Content: "来吧。搞", MessageIndex: &three},
		{TenantID: "tenant", RequestID: "r1", Role: "assistant", Content: "计划已单独提交"},
		{TenantID: "other", RequestID: "r1", Role: "assistant", Content: "继续 cross-tenant-secret"},
		{TenantID: "tenant", RequestID: "unrequested", Role: "assistant", Content: "继续 unrequested-secret"},
		{TenantID: "tenant", RequestID: "r1", Role: "tool", Content: "继续 tool-secret", MessageIndex: &one},
		{TenantID: "tenant", RequestID: "r1", Role: "system", Content: "继续 system-secret", MessageIndex: &one},
	}}
	for _, scope := range []string{"all", "request", "response"} {
		w := httptest.NewRecorder()
		serveAccessRetentionTurns(w, httptest.NewRequest("GET", "/?view=turns&keyword=继续&keyword_scope="+scope, nil), &Dependencies{ContentLogReader: reader}, nil, "tenant", "r1", []string{"r1"}, nil, "", time.Time{}, time.Time{})
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var info types.AccessRetentionContentInfo
		if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		if len(info.Turns) != 1 || info.Turns[0].UserInput != "来吧。搞" || info.Turns[0].Answer == nil || info.Turns[0].Answer.Content != "计划已单独提交" {
			t.Fatalf("changed current dialogue: %+v", info.Turns)
		}
		expected := 1
		if scope == "all" {
			expected = 2
		}
		if len(info.SearchHits) != expected {
			t.Fatalf("scope=%s hits=%+v", scope, info.SearchHits)
		}
		for _, h := range info.SearchHits {
			if h.Kind != "request_context" || h.TurnID != "" || h.MessageIndex == nil {
				t.Fatalf("history mislabeled: %+v", h)
			}
		}
		if strings.Contains(w.Body.String(), "secret") {
			t.Fatal("unsafe rows exposed")
		}
	}
}
func TestRetentionSearchHitsCurrentAndProcessLocations(t *testing.T) {
	p := retentionTurnProjection{Turns: []types.AccessRetentionTurnInfo{{ID: "t1", UserInput: "请继续", RequestIDs: []string{"r1"}, Answer: &types.AccessRetentionMessageInfo{RequestID: "r1", Content: "继续完成"}}}, Process: map[string][]types.AccessRetentionMessageInfo{"t1": {{RequestID: "r1", Content: "继续读取文件"}}}}
	q := retentionSearchQuery{keyword: "继续", scope: "all"}
	q.complete(&p, nil, nil)
	if len(p.SearchHits) != 3 {
		t.Fatal(p.SearchHits)
	}
	for _, h := range p.SearchHits {
		if h.TurnID != "t1" {
			t.Fatal(h)
		}
	}
}
func TestRetentionSearchSnippetLiteralUnicodeAndBounded(t *testing.T) {
	text := strings.Repeat("中文", 200) + "A+B[继续]" + strings.Repeat("尾", 200)
	got := retentionKeywordSnippet(text, "a+b[继续]")
	if !strings.Contains(got, "A+B[继续]") || len([]rune(got)) > 220 || !strings.HasPrefix(got, "…") {
		t.Fatal(got)
	}
	if retentionKeywordSnippet("axxb继续", "a+b") != "" {
		t.Fatal("interpreted regexp")
	}
	p := retentionTurnProjection{}
	q := retentionSearchQuery{keyword: "继续"}
	for i := 0; i < 100; i++ {
		q.appendHit(&p, types.AccessRetentionSearchHit{RequestID: strings.Repeat("x", i), Role: "user", Kind: "request_context"}, "继续")
	}
	if len(p.SearchHits) != 60 || !p.SearchHitsTruncated {
		t.Fatal("unbounded matches")
	}
}
