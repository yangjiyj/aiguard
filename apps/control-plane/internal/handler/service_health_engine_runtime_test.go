package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// engineHealthFixture is decoded through encoding/json exactly like a real
// probe, so numeric fields arrive as float64 rather than Go ints.
func engineHealthFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	const payload = `{
	  "status":"healthy","service":"security-engine","secret_internal_url":"http://10.0.0.1:8000",
	  "runtime":{
	    "node_id":"engine-a#1234",
	    "resource_profile":{
	      "profile":"auto","resolved":"xlarge-cpu64","detected_cpus":"64",
	      "judge_budget_status":"within_budget","tier1_concurrency_status":"within_limit",
	      "tier1_replicas":"2","tier1_scale_mode":"cpu",
	      "effective":{"web_concurrency":"16","input_workers":"8","tier1_workers":"8",
	        "tier1_threads":"4","tier1_inference_workers":"8","tier1_inference_capacity":"256",
	        "judge_capacity":"16","judge_global_concurrency":"96"}
	    },
	    "tier1_runtime":{"probed":true,"reachable":true,"model_loaded":true,
	      "execution_provider":"cuda","threads":4,"batch_windows":16,
	      "inference_workers":12,"inference_capacity":192,"uvicorn_workers":3,
	      "capacity_matches_profile":false},
	    "metrics":{"scope":"cluster","judge_calls_per_request_avg":1.4,
	      "effective":{"judge_calls_per_request_avg":1.4,"fingerprint_hit_rate":0.82,"requests_observed":250}},
	    "shared_state":{"healthy":true},
	    "cascade_warnings":["tier1_cascade_disabled: low<0.05"],
	    "degradation_reasons":["file_id_registry_unavailable"]
	  }
	}`
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	return parsed
}

func TestApplyEngineRuntimeExposesProfileAndC2Metrics(t *testing.T) {
	comp := map[string]interface{}{"component": "security-engine"}
	applyEngineRuntime(comp, engineHealthFixture(t))
	for key, want := range map[string]interface{}{
		"engine_node_id":                  "engine-a#1234",
		"engine_resource_profile":         "xlarge-cpu64",
		"engine_resource_profile_mode":    "auto",
		"engine_detected_cpus":            "64",
		"engine_web_concurrency":          "16",
		"engine_judge_global_concurrency": "96",
		"engine_judge_budget_status":      "within_budget",
		"engine_metrics_scope":            "cluster",
		"judge_calls_per_request_avg":     1.4,
		"fingerprint_hit_rate":            0.82,
		"engine_metrics_requests":         float64(250),
		"engine_shared_state_healthy":     true,
		// R3: the tier1 container's own shape, not an engine-side mirror.
		"engine_tier1_inference_workers":  "8",
		"engine_tier1_inference_capacity": "256",
		"engine_tier1_concurrency_status": "within_limit",
		// U2: the configured topology (tier1-scale.sh), not a live replica count.
		"engine_tier1_replicas":           "2",
		"engine_tier1_scale_mode":         "cpu",
		"engine_tier1_live_reachable":     true,
		"engine_tier1_live_model_loaded":  true,
		"engine_tier1_live_provider":      "cuda",
		"engine_tier1_live_threads":       float64(4),
		"engine_tier1_live_batch_windows": float64(16),
		// S1: the real pool plus the derived consistency flag.
		"engine_tier1_live_inference_workers":   float64(12),
		"engine_tier1_live_inference_capacity":  float64(192),
		"engine_tier1_live_uvicorn_workers":     float64(3),
		"engine_tier1_capacity_matches_profile": false,
	} {
		if comp[key] != want {
			t.Errorf("%s = %#v, want %#v", key, comp[key], want)
		}
	}
	warnings, _ := comp["engine_cascade_warnings"].([]string)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "tier1_cascade_disabled") {
		t.Fatalf("cascade warnings = %v", warnings)
	}
	reasons, _ := comp["engine_degradation_reasons"].([]string)
	if len(reasons) != 1 || reasons[0] != "file_id_registry_unavailable" {
		t.Fatalf("degradation reasons = %v", reasons)
	}
	if _, ok := comp["engine_metrics_note"]; ok {
		t.Fatal("cluster-scope metrics must not be labelled process-local")
	}
}

func TestApplyEngineRuntimeNeverForwardsRawPayload(t *testing.T) {
	comp := map[string]interface{}{"component": "security-engine"}
	applyEngineRuntime(comp, engineHealthFixture(t))
	if _, ok := comp["runtime"]; ok {
		t.Fatal("raw runtime payload leaked to the console")
	}
	if _, ok := comp["secret_internal_url"]; ok {
		t.Fatal("unallowlisted upstream field leaked to the console")
	}
	for key, value := range comp {
		if strings.Contains(strings.ToLower(key), "url") || strings.Contains(strings.ToLower(key), "raw") {
			t.Errorf("forbidden field %s = %v", key, value)
		}
	}
}

func TestApplyEngineRuntimeMarksProcessLocalMetrics(t *testing.T) {
	body := engineHealthFixture(t)
	runtime := body["runtime"].(map[string]interface{})
	metrics := runtime["metrics"].(map[string]interface{})
	metrics["scope"] = "process"
	comp := map[string]interface{}{"component": "security-engine"}
	applyEngineRuntime(comp, body)
	if note, _ := comp["engine_metrics_note"].(string); note == "" {
		t.Fatal("process-local metrics must carry an explicit note")
	}
}

func TestProbeHTTPCapturesHealthBodyButOnlyOn200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/bad") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy","service":"security-engine","runtime":{}}`))
	}))
	defer server.Close()
	client := newReadModelHTTPClient(readModelProbeTimeout)
	good := probeHTTP(context.Background(), client, server.URL+"/health")
	if good.Body == nil {
		t.Fatal("200 /health body was not captured")
	}
	bad := probeHTTP(context.Background(), client, server.URL+"/bad")
	if bad.Body != nil {
		t.Fatal("non-200 body must not be treated as runtime evidence")
	}
}

func TestApplyProbeMergesEngineRuntimeForCachedAndFreshProbes(t *testing.T) {
	body := engineHealthFixture(t)
	res := probeResult{HTTPCode: http.StatusOK, CheckedAt: time.Now().UTC(), Body: body}
	for _, cached := range []bool{false, true} {
		comp := map[string]interface{}{"component": "security-engine"}
		applyProbe(comp, res, cached, 0)
		if comp["engine_resource_profile"] != "xlarge-cpu64" || comp["fingerprint_hit_rate"] != 0.82 {
			t.Fatalf("cached=%v runtime not merged: %#v", cached, comp)
		}
	}
	other := map[string]interface{}{"component": "gateway-core"}
	applyProbe(other, res, false, 0)
	if _, ok := other["engine_resource_profile"]; ok {
		t.Fatal("engine runtime leaked into gateway-core")
	}
}
