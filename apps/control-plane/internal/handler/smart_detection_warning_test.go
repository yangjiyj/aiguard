package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSmartThresholdWarningsFlagsCascadeDisablingLow(t *testing.T) {
	cases := []struct {
		low  float64
		want int
	}{
		{0, 1},
		{0.04, 1},
		{0.05, 0},
		{0.2, 0},
		{0.3, 0},
	}
	for _, c := range cases {
		got := smartThresholdWarnings(c.low)
		if len(got) != c.want {
			t.Fatalf("low=%v warnings=%v want %d", c.low, got, c.want)
		}
		if c.want > 0 && got[0] != "tier1_cascade_disabled" {
			t.Fatalf("low=%v warning code=%q", c.low, got[0])
		}
	}
}

func TestSmartThresholdWarningsNeverNil(t *testing.T) {
	if smartThresholdWarnings(0.3) == nil {
		t.Fatal("warnings must marshal as [] so the console needs no null guard")
	}
}

func TestGetSmartDetectionOverviewExposesCascadeWarning(t *testing.T) {
	// Unreachable sidecar: the probe degrades and must not hide the warning.
	t.Setenv("TIER1_CLASSIFIER_URL", "http://127.0.0.1:9")
	repo := &capturingSystemRepo{settings: map[string]string{
		"tier1_low_threshold": "0",
	}}
	deps := &Dependencies{SystemRepo: repo}

	w := httptest.NewRecorder()
	GetSmartDetectionOverview(deps).ServeHTTP(w,
		adminCtxRequest(http.MethodGet, "/admin/v1/security/smart-detection/overview", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var got struct {
		Status struct {
			Thresholds struct {
				Low float64 `json:"low"`
			} `json:"thresholds"`
			Warnings []string `json:"warnings"`
		} `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status.Thresholds.Low != 0 {
		t.Fatalf("stored value must be echoed unchanged, got %v", got.Status.Thresholds.Low)
	}
	if len(got.Status.Warnings) != 1 || got.Status.Warnings[0] != "tier1_cascade_disabled" {
		t.Fatalf("warnings = %v", got.Status.Warnings)
	}
}

func TestGetSmartDetectionOverviewWarnsNothingAtHealthyThreshold(t *testing.T) {
	t.Setenv("TIER1_CLASSIFIER_URL", "http://127.0.0.1:9")
	repo := &capturingSystemRepo{settings: map[string]string{
		"tier1_low_threshold": "0.30",
	}}
	deps := &Dependencies{SystemRepo: repo}

	w := httptest.NewRecorder()
	GetSmartDetectionOverview(deps).ServeHTTP(w,
		adminCtxRequest(http.MethodGet, "/admin/v1/security/smart-detection/overview", nil))
	var got struct {
		Status struct {
			Warnings []string `json:"warnings"`
		} `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status.Warnings == nil {
		t.Fatal("warnings must be [] not null so the console needs no null guard")
	}
	if len(got.Status.Warnings) != 0 {
		t.Fatalf("warnings = %v", got.Status.Warnings)
	}
}

// The dedicated route is the deliberate way to set a lower bound under 0.05, so it
// accepts it -- but the caller has to be told in the response itself.
func TestUpdateSmartDetectionConfigAnswersWithTheCascadeWarning(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(&Dependencies{SystemRepo: repo}).ServeHTTP(w,
		adminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config",
			smartConfigBody(t, map[string]interface{}{"tier1_low_threshold": 0.0})))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Message  string   `json:"message"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Warnings) != 1 || got.Warnings[0] != "tier1_cascade_disabled" {
		t.Fatalf("warnings = %v; body=%s", got.Warnings, w.Body.String())
	}
	if repo.settings["tier1_low_threshold"] != "0" {
		t.Fatalf("a warning must not rewrite the saved value, got %q", repo.settings["tier1_low_threshold"])
	}
}

func TestUpdateSmartDetectionConfigKeepsItsResponseShapeWithoutAWarning(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(&Dependencies{SystemRepo: repo}).ServeHTTP(w,
		adminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config",
			smartConfigBody(t, map[string]interface{}{"tier1_low_threshold": 0.3})))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, has := got["warnings"]; has {
		t.Fatalf("a healthy threshold must not add a warnings key: %v", got)
	}
}
