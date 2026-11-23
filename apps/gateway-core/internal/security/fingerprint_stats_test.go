package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// echoBatchResponses mirrors the engine contract: exactly one completed
// response per request, in the same order.
func echoBatchResponses(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	var requests []CheckInputRequest
	if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
		t.Errorf("decode batch request: %v", err)
	}
	responses := make([]CheckInputResponse, len(requests))
	for i, req := range requests {
		responses[i] = CheckInputResponse{
			RequestID: req.RequestID, Action: "allow", LatencyMs: 1,
			InspectionStatus: "completed",
		}
	}
	data, err := json.Marshal(responses)
	if err != nil {
		t.Errorf("marshal batch response: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func TestFingerprintStatsHeadersAreAppliedExactlyOncePerBatch(t *testing.T) {
	ctx := WithFingerprintStats(context.Background(), FingerprintStats{Checks: 10, Hits: 7})
	for chunk := 0; chunk < 2; chunk++ {
		req := httptest.NewRequest(http.MethodPost, "http://engine/check-input/batch", nil)
		applyFingerprintStatsHeaders(ctx, req)
		wantChecks, wantHits := "10", "7"
		if chunk > 0 {
			wantChecks, wantHits = "", ""
		}
		if got := req.Header.Get(FingerprintChecksHeader); got != wantChecks {
			t.Fatalf("chunk %d checks header = %q, want %q", chunk, got, wantChecks)
		}
		if got := req.Header.Get(FingerprintHitsHeader); got != wantHits {
			t.Fatalf("chunk %d hits header = %q, want %q", chunk, got, wantHits)
		}
	}
}

func TestFingerprintStatsAreClampedAndHitsNeverExceedChecks(t *testing.T) {
	ctx := WithFingerprintStats(context.Background(), FingerprintStats{Checks: -1, Hits: 99})
	req := httptest.NewRequest(http.MethodPost, "http://engine/check-input/batch", nil)
	applyFingerprintStatsHeaders(ctx, req)
	if req.Header.Get(FingerprintChecksHeader) != "" {
		t.Fatal("zero/negative checks must not emit a header")
	}

	ctx = WithFingerprintStats(context.Background(), FingerprintStats{Checks: 999999, Hits: 999999})
	req = httptest.NewRequest(http.MethodPost, "http://engine/check-input/batch", nil)
	applyFingerprintStatsHeaders(ctx, req)
	if got := req.Header.Get(FingerprintChecksHeader); got != "10000" {
		t.Fatalf("checks header = %q, want 10000", got)
	}
	if got := req.Header.Get(FingerprintHitsHeader); got != "10000" {
		t.Fatalf("hits header = %q, want 10000", got)
	}
}

func TestCheckInputBatchReportsFingerprintStatsToEngine(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get(FingerprintChecksHeader)+"/"+r.Header.Get(FingerprintHitsHeader))
		mu.Unlock()
		echoBatchResponses(t, w, r)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	requests := []*CheckInputRequest{{RequestID: "r1", Content: "hello"}}
	ctx := WithFingerprintStats(context.Background(), FingerprintStats{Checks: 4, Hits: 3})
	if _, err := client.CheckInputBatch(ctx, requests); err != nil {
		t.Fatalf("CheckInputBatch: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "4/3" {
		t.Fatalf("engine saw fingerprint headers %v, want [4/3]", seen)
	}
}

func TestCheckInputBatchWithoutFingerprintStatsSendsNoHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(FingerprintChecksHeader) != "" || r.Header.Get(FingerprintHitsHeader) != "" {
			t.Error("unexpected advisory headers on a plain batch")
		}
		echoBatchResponses(t, w, r)
	}))
	defer server.Close()
	client := NewClient(server.URL)
	if _, err := client.CheckInputBatch(context.Background(),
		[]*CheckInputRequest{{RequestID: "r1", Content: "hello"}}); err != nil {
		t.Fatalf("CheckInputBatch: %v", err)
	}
}
