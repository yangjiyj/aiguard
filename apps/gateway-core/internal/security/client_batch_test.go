package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckInputBatchRetriesIncompleteItemsIndividually(t *testing.T) {
	var singleCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check-input/" {
			singleCalls.Add(1)
			var request CheckInputRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.RequestID != "req:1" {
				t.Fatalf("single retry request=%+v", request)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_id":"req:1","findings":[],"action":"allow","latency_ms":3,"inspection_status":"completed"}`))
			return
		}
		if r.URL.Path != "/check-input/batch" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		var requests []*CheckInputRequest
		if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
			t.Fatal(err)
		}
		if len(requests) != 2 || requests[0].RequestID != "req:0" || requests[1].RequestID != "req:1" {
			t.Fatalf("requests=%+v", requests)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte("[" +
			"{\"request_id\":\"req:0\",\"findings\":[],\"action\":\"allow\",\"latency_ms\":2,\"inspection_status\":\"completed\"}," +
			"{\"request_id\":\"req:1\",\"findings\":[],\"action\":\"audit\",\"latency_ms\":8,\"inspection_status\":\"incomplete\",\"inspection_reason\":\"batch_timeout\"}" +
			"]"))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	client.sleep = func(context.Context, time.Duration) error { return nil }
	results, err := client.CheckInputBatch(context.Background(), []*CheckInputRequest{
		{RequestID: "req:0", Content: "first"},
		{RequestID: "req:1", Content: "second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].InspectionStatus != "completed" {
		t.Fatalf("results=%+v", results)
	}
	if results[1].InspectionStatus != "completed" || results[1].Action != "allow" {
		t.Fatalf("retried result=%+v", results[1])
	}
	if singleCalls.Load() != 1 {
		t.Fatalf("single retry calls=%d want=1", singleCalls.Load())
	}
}

func TestCheckInputBatchPreservesIncompleteWhenSingleRetryFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte(`[{"request_id":"req:0","findings":[],"action":"audit","latency_ms":8,"inspection_status":"incomplete","inspection_reason":"batch_timeout"}]`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	client.sleep = func(context.Context, time.Duration) error { return nil }
	results, err := client.CheckInputBatch(context.Background(), []*CheckInputRequest{{RequestID: "req:0", Content: "first"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].InspectionStatus != "incomplete" || results[0].InspectionReason != "batch_timeout" {
		t.Fatalf("results=%+v", results)
	}
}

func TestCheckInputBatchRejectsResponseOrderMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[" +
			"{\"request_id\":\"req:1\",\"findings\":[],\"action\":\"allow\",\"latency_ms\":1}," +
			"{\"request_id\":\"req:0\",\"findings\":[],\"action\":\"allow\",\"latency_ms\":1}" +
			"]"))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	_, err := client.CheckInputBatch(context.Background(), []*CheckInputRequest{
		{RequestID: "req:0", Content: "first"},
		{RequestID: "req:1", Content: "second"},
	})
	if err == nil {
		t.Fatal("reordered batch response must be rejected")
	}
}

func TestBatchRetriesSemanticTimeoutWithoutHidingFailedRecovery(t *testing.T) {
	for _, recovered := range []bool{true, false} {
		t.Run(fmt.Sprint(recovered), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/check-input/batch" {
					_, _ = w.Write([]byte(`[{"request_id":"req","findings":[],"action":"audit","inspection_status":"completed","semantic_status":"incomplete","semantic_reason":"judge_timeout"}]`))
					return
				}
				calls++
				status, reason := "incomplete", "judge_timeout"
				if recovered {
					status, reason = "completed", ""
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"request_id": "req", "findings": []any{}, "action": "audit", "inspection_status": "completed", "semantic_status": status, "semantic_reason": reason})
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			fc := NewClient(server.URL)
			fc.sleep = func(context.Context, time.Duration) error { return nil }
			got, err := fc.CheckInputBatch(ctx, []*CheckInputRequest{{RequestID: "req", Content: "tool history"}})
			wantCalls := 2
			if recovered {
				wantCalls = 1
			}
			if err != nil || calls != wantCalls || len(got) != 1 {
				t.Fatalf("recovery failed: calls=%d err=%v", calls, err)
			}
			want := "incomplete"
			if recovered {
				want = "completed"
			}
			if got[0].SemanticStatus != want {
				t.Fatalf("coverage fabricated: %+v", got[0])
			}
		})
	}
}
