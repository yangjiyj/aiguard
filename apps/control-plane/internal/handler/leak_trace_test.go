package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/aicontentlabel"
)

const leakTraceTestSecret = "synthetic-internal-secret"

type fakeLeakTraceStore struct {
	meta     map[string]*repository.RequestEvidenceMetadata
	content  []repository.ContentLog
	searched []string
	tenants  []string
}

func (f *fakeLeakTraceStore) evidenceMetadata(_ context.Context, tenantID, requestID string) (*repository.RequestEvidenceMetadata, error) {
	f.tenants = append(f.tenants, tenantID)
	if tenantID != "t_1" {
		return nil, nil
	}
	return f.meta[requestID], nil
}

func (f *fakeLeakTraceStore) searchAssistant(_ context.Context, tenantID, keyword string, _, _ time.Time) ([]repository.ContentLog, error) {
	f.searched = append(f.searched, keyword)
	f.tenants = append(f.tenants, tenantID)
	var out []repository.ContentLog
	for _, l := range f.content {
		if l.TenantID == tenantID && strings.Contains(l.Content, keyword) {
			out = append(out, l)
		}
	}
	return out, nil
}

func runLeakTrace(t *testing.T, store *fakeLeakTraceStore, tenant string, body map[string]string) (int, leakTraceResponse) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/audit/leak-trace", bytes.NewReader(raw))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u_admin", TenantID: tenant, Role: "platform_admin"}))
	w := httptest.NewRecorder()
	leakTraceHandler(&Dependencies{SecurityEngineInternalToken: leakTraceTestSecret}, store)(w, req)
	var resp leakTraceResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func TestLeakTraceLocatesRequestByWatermark(t *testing.T) {
	requestID := "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	frame, ok := aicontentlabel.Encode(requestID, aicontentlabel.DeriveKey(leakTraceTestSecret))
	if !ok {
		t.Fatal("encode failed")
	}
	store := &fakeLeakTraceStore{meta: map[string]*repository.RequestEvidenceMetadata{
		requestID: {RequestID: requestID, UserID: "u_7", Username: "zhangsan", AgentType: "enterprise-portal", Target: "gpt-4"},
	}}
	code, resp := runLeakTrace(t, store, "t_1", map[string]string{"text": "被转发出去的回答" + frame + "（以上内容由 AI 生成）"})
	if code != http.StatusOK || resp.Method != "watermark" || resp.Watermark != "verified" {
		t.Fatalf("code=%d resp=%+v", code, resp)
	}
	if len(resp.Matches) != 1 || resp.Matches[0].Username != "zhangsan" || resp.Matches[0].RequestID != requestID {
		t.Fatalf("matches = %+v", resp.Matches)
	}
	if len(store.searched) != 0 {
		t.Fatal("verified watermark must not fall back to keyword search")
	}

	// 其他租户的管理员拿着同一段文本，只能看到“校验通过但不属于当前租户”。
	_, other := runLeakTrace(t, store, "t_other", map[string]string{"text": "x" + frame})
	if other.Method != "watermark" || len(other.Matches) != 0 || other.Note == "" {
		t.Fatalf("cross-tenant resp = %+v", other)
	}
}

func TestLeakTraceRejectsForgedWatermarkAndFallsBackToFragments(t *testing.T) {
	forged, _ := aicontentlabel.Encode("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", aicontentlabel.DeriveKey("someone-else"))
	leaked := "零信任架构要求对每一次访问请求都进行身份校验和权限评估，不因网络位置而默认信任。"
	store := &fakeLeakTraceStore{
		meta: map[string]*repository.RequestEvidenceMetadata{"req_a": {RequestID: "req_a", Username: "lisi"}},
		content: []repository.ContentLog{
			{RequestID: "req_a", TenantID: "t_1", Role: "assistant", Content: "### 结论\n" + leaked, CreatedAt: time.Now()},
			{RequestID: "req_b", TenantID: "t_2", Role: "assistant", Content: leaked, CreatedAt: time.Now()},
		},
	}
	code, resp := runLeakTrace(t, store, "t_1", map[string]string{"text": "## 摘录\n" + leaked + forged})
	if code != http.StatusOK || resp.Watermark != "forged" || resp.Method != "fragments" {
		t.Fatalf("code=%d resp=%+v", code, resp)
	}
	if len(resp.Fragments) != 1 || strings.Contains(resp.Fragments[0], "#") {
		t.Fatalf("fragments = %q", resp.Fragments)
	}
	if len(resp.Matches) != 1 || resp.Matches[0].RequestID != "req_a" || resp.Matches[0].Username != "lisi" {
		t.Fatalf("matches = %+v (must not include other tenant)", resp.Matches)
	}
	for _, tenant := range store.tenants {
		if tenant != "t_1" {
			t.Fatalf("queried tenant %q", tenant)
		}
	}
}

func TestLeakTraceValidation(t *testing.T) {
	store := &fakeLeakTraceStore{}
	if code, _ := runLeakTrace(t, store, "t_1", map[string]string{"text": "  "}); code != http.StatusBadRequest {
		t.Fatalf("blank text code=%d", code)
	}
	if code, _ := runLeakTrace(t, store, "t_1", map[string]string{"text": strings.Repeat("长", 20001)}); code != http.StatusBadRequest {
		t.Fatalf("oversized text code=%d", code)
	}
	code, resp := runLeakTrace(t, store, "t_1", map[string]string{"text": "太短"})
	if code != http.StatusOK || resp.Method != "none" || resp.Note == "" {
		t.Fatalf("short text: code=%d resp=%+v", code, resp)
	}
	long := "这是一段足够长、可以拿来做留存正文检索的连续文字，没有句号打断"
	if code, _ := runLeakTrace(t, store, "t_1", map[string]string{"text": long, "from": "2026-01-01T00:00:00Z", "to": "2026-12-31T00:00:00Z"}); code != http.StatusBadRequest {
		t.Fatalf("window over 180 days should be rejected, code=%d", code)
	}
}

func TestLeakTraceFragments(t *testing.T) {
	text := "# 标题\n\n- 第一条要点非常长，长到超过二十个字符的门槛可以被选中。\n短句。\n" +
		"```\ncode\n```\n**第二段加粗的内容同样足够长，可以作为第二个检索片段使用。**"
	got := leakTraceFragments(text)
	if len(got) != 2 || !strings.HasPrefix(got[0], "第一条要点") || !strings.HasPrefix(got[1], "第二段加粗") {
		t.Fatalf("fragments = %q", got)
	}
	for _, f := range got {
		if strings.ContainsAny(f, "*#-`") {
			t.Fatalf("markdown noise left in %q", f)
		}
	}
	if long := leakTraceFragments(strings.Repeat("字", 300)); len(long) != 1 || len([]rune(long[0])) != leakTraceFragmentMax {
		t.Fatalf("long fragment = %q", long)
	}
}

func TestNormalizeAIContentLabelSettings(t *testing.T) {
	settings := map[string]string{
		aicontentlabel.KeyExplicitEnabled: " TRUE ",
		aicontentlabel.KeyAgentTypes:      `["Enterprise_Portal"]`,
		"block_response_mode":             "message",
	}
	if err := normalizeAIContentLabelSettings(settings); err != nil {
		t.Fatal(err)
	}
	if settings[aicontentlabel.KeyExplicitEnabled] != "true" || settings[aicontentlabel.KeyAgentTypes] != `["enterprise-portal"]` {
		t.Fatalf("settings = %v", settings)
	}
	if settings["block_response_mode"] != "message" {
		t.Fatal("unrelated key changed")
	}
	if err := normalizeAIContentLabelSettings(map[string]string{aicontentlabel.KeyExplicitText: "含\n换行"}); err == nil {
		t.Fatal("invalid text accepted")
	}
	data := map[string]any{aicontentlabel.KeyWatermarkEnabled: "true"}
	fillAIContentLabelDefaults(data)
	if data[aicontentlabel.KeyWatermarkEnabled] != "true" || data[aicontentlabel.KeyExplicitEnabled] != "false" ||
		data[aicontentlabel.KeyExplicitText] != aicontentlabel.DefaultExplicitText || data[aicontentlabel.KeyAgentTypes] != `["enterprise-portal"]` {
		t.Fatalf("defaults = %v", data)
	}
}
