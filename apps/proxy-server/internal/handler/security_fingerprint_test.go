package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

func newFPTestRequest() *http.Request {
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"same customer prompt"}]}`
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestProxyCheckInput_FingerprintReuse(t *testing.T) {
	var checkCalls, applyCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/check-input/":
			atomic.AddInt32(&checkCalls, 1)
			io.WriteString(w, `{"action":"audit",
				"findings":[{"rule_id":"pi-1","severity":"high"}],
				"semantic_status":"completed","engine_build":"b1","rule_pack_version":"rp1",
				"raw_findings":[{"rule_id":"pi-1","severity":"high"}]}`)
		case "/apply-context/":
			atomic.AddInt32(&applyCalls, 1)
			io.WriteString(w, `{"action":"audit","findings":[{"rule_id":"pi-1","severity":"high"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := NewSecurityClient(srv.URL)
	s.WithFingerprintStore(scanfp.NewStore(nil, 16))

	_, findings1, meta1 := s.CheckInput(context.Background(), "t1", "req-1", newFPTestRequest())
	if meta1 != nil && meta1.ScanMode != "" {
		t.Fatal("首见不得标重放")
	}
	if len(findings1) != 1 {
		t.Fatalf("findings1 = %v", findings1)
	}

	action2, findings2, meta2 := s.CheckInput(context.Background(), "t1", "req-2", newFPTestRequest())
	if atomic.LoadInt32(&checkCalls) != 1 {
		t.Fatalf("引擎 check-input 应只调一次, got %d", checkCalls)
	}
	if atomic.LoadInt32(&applyCalls) != 1 {
		t.Fatalf("第二次应走 apply-context, got %d", applyCalls)
	}
	if meta2 == nil || meta2.ScanMode != "fingerprint_reuse" || meta2.FirstSeenRequestID != "req-1" {
		t.Fatalf("meta2 = %+v", meta2)
	}
	if action2 != "audit" || len(findings2) != 1 {
		t.Fatalf("重放结果异常: %s %v", action2, findings2)
	}
}

func TestProxyCheckInput_NoFindingsRepeatSilent(t *testing.T) {
	var checkCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			atomic.AddInt32(&checkCalls, 1)
			io.WriteString(w, `{"action":"allow","findings":[],"semantic_status":"completed","engine_build":"b1","rule_pack_version":"rp1","raw_findings":[]}`)
			return
		}
		t.Errorf("无 findings 重复不应有其它引擎调用: %s", r.URL.Path)
	}))
	defer srv.Close()

	s := NewSecurityClient(srv.URL)
	s.WithFingerprintStore(scanfp.NewStore(nil, 16))

	s.CheckInput(context.Background(), "t1", "req-1", newFPTestRequest())
	action, findings, meta := s.CheckInput(context.Background(), "t1", "req-2", newFPTestRequest())
	if atomic.LoadInt32(&checkCalls) != 1 {
		t.Fatalf("引擎应只调一次, got %d", checkCalls)
	}
	if action != "allow" || len(findings) != 0 || meta != nil {
		t.Fatalf("静默跳过应返回 allow/空: %s %v %+v", action, findings, meta)
	}
}

func TestProxyCheckInput_ReplayMaskFallsBack(t *testing.T) {
	var checkCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/check-input/":
			atomic.AddInt32(&checkCalls, 1)
			io.WriteString(w, `{"action":"mask","findings":[{"rule_id":"dl-1"}],
				"semantic_status":"completed","engine_build":"b1","rule_pack_version":"rp1","raw_findings":[{"rule_id":"dl-1"}]}`)
		case "/apply-context/":
			io.WriteString(w, `{"action":"mask","findings":[{"rule_id":"dl-1"}]}`)
		}
	}))
	defer srv.Close()

	s := NewSecurityClient(srv.URL)
	s.WithFingerprintStore(scanfp.NewStore(nil, 16))

	s.CheckInput(context.Background(), "t1", "req-1", newFPTestRequest())
	_, _, meta := s.CheckInput(context.Background(), "t1", "req-2", newFPTestRequest())
	if atomic.LoadInt32(&checkCalls) != 2 {
		t.Fatalf("重放判 mask 必须回退全量送检, checkCalls=%d", checkCalls)
	}
	if meta != nil && meta.ScanMode != "" {
		t.Fatal("回退路径不得标重放")
	}
}

func TestProxyCheckInput_NoStoreBehavesAsBefore(t *testing.T) {
	var checkCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		atomic.AddInt32(&checkCalls, 1)
		io.WriteString(w, `{"action":"audit","findings":[]}`)
	}))
	defer srv.Close()

	s := NewSecurityClient(srv.URL) // 未注入 store = 开关关
	s.CheckInput(context.Background(), "t1", "req-1", newFPTestRequest())
	s.CheckInput(context.Background(), "t1", "req-2", newFPTestRequest())
	if atomic.LoadInt32(&checkCalls) != 2 {
		t.Fatalf("未注入 store 时每次都送检（现状）, got %d", checkCalls)
	}
}

func TestBuildSecurityEventSummary_IncludesScanMode(t *testing.T) {
	record := ProxyAuditRecord{
		TargetHost: "api.openai.com",
		ScanMode:   "fingerprint_reuse", FirstSeenRequestID: "req-1",
	}
	summary := buildSecurityEventSummaryForRecord(record, "input", nil)
	if summary["scan_mode"] != "fingerprint_reuse" || summary["first_seen_request_id"] != "req-1" {
		t.Fatalf("summary = %+v", summary)
	}
	plain := buildSecurityEventSummaryForRecord(ProxyAuditRecord{TargetHost: "x"}, "input", nil)
	if _, ok := plain["scan_mode"]; ok {
		t.Fatal("非重放不得带 scan_mode")
	}
}
