package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// R4: production evidence shows tier1_low_threshold=0.0 was written through the
// generic settings route, not the smart-detection endpoint. These tests pin the
// shared [0,1] contract on that route and its refusal to disable the cascade.

func putSystemSettings(t *testing.T, repo *capturingSystemRepo, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w,
		adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", smartConfigBody(t, body)))
	return w
}

func TestGenericSettingsRejectsOutOfRangeTier1Threshold(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	w := putSystemSettings(t, repo, map[string]interface{}{"tier1_low_threshold": 2})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if _, stored := repo.settings["tier1_low_threshold"]; stored {
		t.Fatal("an out-of-range threshold must not be persisted")
	}
}

func TestGenericSettingsRejectsLowAboveStoredHigh(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{"tier1_high_threshold": "0.4"}}
	w := putSystemSettings(t, repo, map[string]interface{}{"tier1_low_threshold": 0.7})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestGenericSettingsRejectsNonNumericThreshold(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	w := putSystemSettings(t, repo, map[string]interface{}{"tier1_low_threshold": "zero"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// The 2026-09-17 value. This route takes arbitrary keys, so nobody reads an audit
// warning on it; the "0.0" written here switched the cascade off and cost a judge
// call per window until someone diffed raw settings. Disabling the cascade is
// refused on this route (the smart-detection configuration is the deliberate path),
// and a refused write persists nothing and leaves no audit entry.
func TestGenericSettingsRejectsCascadeDisablingThreshold(t *testing.T) {
	for _, value := range []interface{}{0, 0.0, "0.0", 0.04999} {
		repo := &capturingSystemRepo{settings: map[string]string{}}
		w := putSystemSettings(t, repo, map[string]interface{}{"tier1_low_threshold": value})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("value %v: status = %d, want 400; body=%s", value, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "disables the tier-1 cascade") {
			t.Fatalf("value %v: the refusal must say why: %s", value, w.Body.String())
		}
		if _, stored := repo.settings["tier1_low_threshold"]; stored {
			t.Fatalf("value %v: a refused threshold must not be persisted", value)
		}
		if len(repo.auditOps) != 0 {
			t.Fatalf("value %v: a refused write must not leave an audit entry, got %d", value, len(repo.auditOps))
		}
	}
}

func TestGenericSettingsAcceptsTheCutOffItself(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	w := putSystemSettings(t, repo, map[string]interface{}{"tier1_low_threshold": 0.05})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if repo.settings["tier1_low_threshold"] != "0.05" {
		t.Fatalf("stored value = %q, want \"0.05\"", repo.settings["tier1_low_threshold"])
	}
}

func TestGenericSettingsHealthyThresholdCarriesNoWarning(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	w := putSystemSettings(t, repo, map[string]interface{}{"tier1_low_threshold": 0.3})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(repo.auditOps) != 1 {
		t.Fatalf("audit ops = %d, want 1", len(repo.auditOps))
	}
	if _, warned := repo.auditOps[0].ActionDetail["warning"]; warned {
		t.Fatalf("a healthy threshold must not raise a cascade warning: %v", repo.auditOps[0].ActionDetail)
	}
}

func TestGenericSettingsAllowsClearingThresholdToFallBack(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{"tier1_low_threshold": "0.2"}}
	w := putSystemSettings(t, repo, map[string]interface{}{"tier1_low_threshold": ""})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if repo.settings["tier1_low_threshold"] != "" {
		t.Fatalf("cleared value = %q, want empty (fall back to the deployed default)",
			repo.settings["tier1_low_threshold"])
	}
}
