package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeQuickEngine struct {
	matches []quickMatch
	err     error
}

func (f fakeQuickEngine) PreviewQuickMatcher(_ context.Context, input quickEngineRequest) (*quickEngineResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.matches != nil {
		return &quickEngineResponse{Matches: f.matches}, nil
	}
	matches := make([]quickMatch, len(input.Samples))
	for i := range input.Samples {
		matches[i] = quickMatch{SampleIndex: i, Matched: true}
	}
	return &quickEngineResponse{Matches: matches}, nil
}

func TestQuickNumberPatternStructureAndBoundaries(t *testing.T) {
	for _, samples := range [][]string{
		nil, {"12010199"}, {"12010199", "12010199"},
		{"12010199", "120101999"}, {"??????", "??????"},
		{"AB.12010199-X", "AC.12020299-X"}, {"AB.12010199-X", "AB.12A20299-X"},
		{"AB.12010199-X", "AB.12020299-7"},
	} {
		if _, _, ok := quickNumberPattern(samples); ok {
			t.Fatalf("invalid samples accepted: %q", samples)
		}
	}
	matcher, segments, ok := quickMatcher(quickCreateRequest{Kind: "number", PositiveSamples: []string{"12010199", "12020299"}})
	if !ok || matcher.Type != "regex" {
		t.Fatal("number matcher not generated")
	}
	var config struct {
		Regex string `json:"regex"`
	}
	if err := json.Unmarshal(matcher.Config, &config); err != nil || config.Regex != `(?<![A-Za-z0-9_])[0-9]{8}(?![A-Za-z0-9_])` {
		t.Fatalf("unexpected matcher %s", matcher.Config)
	}
	if len(segments) != 1 || segments[0].Kind != "digits" || segments[0].Length != 8 {
		t.Fatalf("wrong segments %+v", segments)
	}
	pattern, segments, ok := quickNumberPattern([]string{"AB.12010199-X", "AB.12020299-X"})
	if !ok || pattern != `(?<![A-Za-z0-9_])AB\.[0-9]{8}-X(?![A-Za-z0-9_])` || len(segments) != 3 || segments[0].Value != "AB." {
		t.Fatalf("literal punctuation must be escaped: %s %+v", pattern, segments)
	}
	pattern, segments, ok = quickNumberPattern([]string{"AB/12010199_X", "AB/12020299_X"})
	if !ok || pattern != `(?<![A-Za-z0-9_])AB/[0-9]{8}_X(?![A-Za-z0-9_])` || len(segments) != 3 {
		t.Fatalf("slash in Python regex should remain literal: %s %+v", pattern, segments)
	}

}

func TestQuickGenerateAndPreviewWithoutSaving(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	h := &quickCreateHandler{policies: newSecurityPoliciesHandler(&Dependencies{SecurityEngineInternalToken: "test-quick-authoring-secret"}, store, &fakeRegexValidator{valid: true}), engine: fakeQuickEngine{matches: []quickMatch{{SampleIndex: 0, Matched: true, Location: quickString("content[2:16]"), RedactedEvidence: quickString("<REDACTED>")}, {SampleIndex: 1}}}}
	generation := `{"kind":"number","positive_samples":["HT-2026-000123","HT-2026-000456"],"request_version":"42"}`
	denied := httptest.NewRecorder()
	h.generate(denied, policyHandlerRequest(http.MethodPost, "/generate", generation, "auditor"))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("auditor status=%d", denied.Code)
	}
	generated := httptest.NewRecorder()
	h.generate(generated, policyHandlerRequest(http.MethodPost, "/generate", generation, "platform_admin"))
	var result struct {
		Matcher     securityPolicyMatcherRequest `json:"matcher"`
		Segments    []quickNumberSegment         `json:"segments"`
		Explanation string                       `json:"explanation"`
		Version     string                       `json:"request_version"`
		Proof       string                       `json:"authoring_proof"`
	}
	if generated.Code != http.StatusOK || json.Unmarshal(generated.Body.Bytes(), &result) != nil || result.Matcher.Type != "regex" || len(result.Segments) != 4 || result.Explanation == "" || result.Version != "42" || result.Proof == "" {
		t.Fatalf("generation status=%d body=%s", generated.Code, generated.Body.String())
	}
	var generatedConfig struct {
		Regex string `json:"regex"`
	}
	if json.Unmarshal(result.Matcher.Config, &generatedConfig) != nil || !verifyQuickAuthoring("test-quick-authoring-secret", result.Proof, "tenant-a", "", generatedConfig.Regex, result.Segments) || verifyQuickAuthoring("test-quick-authoring-secret", result.Proof, "tenant-a", "existing-policy", generatedConfig.Regex, result.Segments) {
		t.Fatal("new creation proof must bind an empty policy id")
	}
	previewBody, err := json.Marshal(map[string]any{"matcher": result.Matcher, "samples": []string{"编号HT-2026-000123已核实", "ordinary text"}, "request_version": "43"})
	if err != nil {
		t.Fatal(err)
	}
	preview := httptest.NewRecorder()
	h.execute(preview, policyHandlerRequest(http.MethodPost, "/preview", string(previewBody), "platform_admin"))
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"request_version":"43"`) || !strings.Contains(preview.Body.String(), `"matched":false`) || store.created.Matcher != nil {
		t.Fatalf("read-only preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	if strings.Contains(preview.Body.String(), "ordinary text") || strings.Contains(preview.Body.String(), "HT-2026-000123") {
		t.Fatal("trial sample leaked in response")
	}
}

func TestQuickPreviewMissesNotBlockingAndEngineFailure(t *testing.T) {
	h := &quickCreateHandler{policies: newSecurityPoliciesHandler(&Dependencies{SecurityEngineInternalToken: "test-quick-authoring-secret"}, &fakeSecurityPolicyStore{}, &fakeRegexValidator{valid: true}), engine: fakeQuickEngine{matches: []quickMatch{{SampleIndex: 0}}}}
	body := `{"matcher":{"type":"keyword","config":{"keywords":["foo"]}},"samples":["ordinary text"]}`
	response := httptest.NewRecorder()
	h.execute(response, policyHandlerRequest(http.MethodPost, "/preview", body, "platform_admin"))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"matched":false`) {
		t.Fatalf("miss status=%d body=%s", response.Code, response.Body.String())
	}
	h.engine = fakeQuickEngine{err: errors.New("engine down")}
	failed := httptest.NewRecorder()
	h.execute(failed, policyHandlerRequest(http.MethodPost, "/preview", body, "platform_admin"))
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("engine failure status=%d", failed.Code)
	}
}

func TestQuickPreviewClientRejectsMalformedEngineResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(InternalAPISecretHeader) != "shared-secret" {
			t.Error("missing internal token")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"matches":[{"sample_index":0,"matched":true,"location":"content[0:2]","redacted_evidence":"<REDACTED>"}]}`))
	}))
	defer server.Close()
	client := newSecurityEngineClient(server.URL, "shared-secret")
	matcher := securityPolicyMatcherRequest{Type: "keyword", Config: json.RawMessage(`{"keywords":["ab"]}`)}
	response, err := client.PreviewQuickMatcher(context.Background(), quickEngineRequest{Matcher: &matcher, Samples: []string{"ab"}})
	if err != nil || !response.Matches[0].Matched {
		t.Fatalf("preview failed: %v", err)
	}
	_, err = client.PreviewQuickMatcher(context.Background(), quickEngineRequest{Matcher: &matcher, Samples: []string{"ab", "cd"}})
	if err == nil {
		t.Fatal("incomplete engine response must fail closed")
	}
}

func TestQuickInvalidInputAndRequestIsolation(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	h := &quickCreateHandler{policies: newSecurityPoliciesHandler(&Dependencies{SecurityEngineInternalToken: "test-quick-authoring-secret"}, store, &fakeRegexValidator{valid: true}), engine: fakeQuickEngine{}}
	generateCases := []struct{ body, code string }{
		{`{"kind":"number","positive_samples":["HT-2026-000123"]}`, "invalid_matcher"},
		{`{"kind":"number","positive_samples":["HT-2026-000123","HT-2026-000123"]}`, "invalid_matcher"},
		{`{"kind":"number","positive_samples":["HT-2026-000123","HT-2026-0004567"]}`, "invalid_matcher"},
		{`{"kind":"number","positive_samples":["HT-2026-000123","AT-2026-000456"]}`, "invalid_matcher"},
		{`{"kind":"number","positive_samples":["HT-2026-000123","HT-2026-000456"],"segments":[{"kind":"fixed","value":"AT-2026-"},{"kind":"digits","length":6}]}`, "invalid_matcher"},
		{`{"kind":"number","positive_samples":["HT-2026-000123","HT-2026-000456"],"name":"ignored"}`, "invalid_request"},
		{`{"kind":"number","positive_samples":["HT-2026-000123","HT-2026-000456"],"subject_binding":{"tenant_ids":["foreign"]}}`, "invalid_request"},
	}
	for _, tc := range generateCases {
		response := httptest.NewRecorder()
		h.generate(response, policyHandlerRequest(http.MethodPost, "/generate", tc.body, "platform_admin"))
		if response.Code < 400 || !strings.Contains(response.Body.String(), tc.code) || strings.Contains(response.Body.String(), "HT-2026-000123") {
			t.Fatalf("input %s status=%d response=%s", tc.code, response.Code, response.Body.String())
		}
	}
	preview := httptest.NewRecorder()
	h.execute(preview, policyHandlerRequest(http.MethodPost, "/preview", `{"matcher":{"type":"keyword","config":{"keywords":["foo"]}},"samples":["foo"],"subject_binding":{"tenant_ids":["foreign"]}}`, "platform_admin"))
	if preview.Code != http.StatusBadRequest || store.created.Matcher != nil {
		t.Fatalf("invalid preview status=%d body=%s", preview.Code, preview.Body.String())
	}
}
func quickString(value string) *string { return &value }

func TestQuickGenerateWithoutTrialSamples(t *testing.T) {
	h := &quickCreateHandler{policies: newSecurityPoliciesHandler(&Dependencies{SecurityEngineInternalToken: "test-quick-authoring-secret"}, &fakeSecurityPolicyStore{}, &fakeRegexValidator{valid: true}), engine: fakeQuickEngine{err: errors.New("engine must not be called")}}
	response := httptest.NewRecorder()
	h.generate(response, policyHandlerRequest(http.MethodPost, "/generate", `{"kind":"number","positive_samples":["HT-2026-000123","HT-2026-000456"]}`, "platform_admin"))
	if response.Code != http.StatusOK {
		t.Fatalf("generation without trial status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestQuickNumberPatternGeneralizesEntireFinalDigitRun(t *testing.T) {
	pattern, segments, ok := quickNumberPattern([]string{"HT-2026-000123", "HT-2026-000456"})
	if !ok || pattern != `(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])` {
		t.Fatalf("final digit run must generalize: %q %+v", pattern, segments)
	}
	if len(segments) != 4 || segments[0].Value != "HT-" || segments[1].Kind != "fixed" || segments[1].Value != "2026" || segments[2].Value != "-" || segments[3].Kind != "digits" || segments[3].Length != 6 {
		t.Fatalf("unexpected segment contract: %+v", segments)
	}
}

func TestQuickNumberEditedSegmentsCanGeneralizeFixedYear(t *testing.T) {
	samples := []string{"HT-2026-000123", "HT-2026-000456"}
	_, segments, ok := quickNumberPattern(samples)
	if !ok || len(segments) != 4 {
		t.Fatalf("unexpected segments: %+v", segments)
	}
	segments[1] = quickNumberSegment{Kind: "digits", Length: 4}
	pattern, ok := quickNumberEditedPattern(samples, segments)
	if !ok || pattern != `(?<![A-Za-z0-9_])HT-[0-9]{4}-[0-9]{6}(?![A-Za-z0-9_])` {
		t.Fatalf("fixed year edit failed: %q", pattern)
	}
	cases := [][]quickNumberSegment{
		{{Kind: "fixed", Value: "HT-"}, {Kind: "digits", Length: 3}, {Kind: "fixed", Value: "-"}, {Kind: "digits", Length: 6}},
		{{Kind: "fixed", Value: "AT-"}, {Kind: "digits", Length: 4}, {Kind: "fixed", Value: "-"}, {Kind: "digits", Length: 6}},
		{{Kind: "fixed", Value: "HT-"}, {Kind: "letters", Length: 4}, {Kind: "fixed", Value: "-"}, {Kind: "digits", Length: 6}},
		{{Kind: "fixed", Value: "HT-"}, {Kind: "digits", Length: 4}, {Kind: "fixed", Value: "-"}, {Kind: "digits", Length: 19}},
	}
	for _, edited := range cases {
		if pattern, valid := quickNumberEditedPattern(samples, edited); valid {
			t.Fatalf("invalid edit accepted: %q", pattern)
		}
	}
}

func TestQuickGenerateExistingTenantPolicyWithSamples(t *testing.T) {
	secret := "test-quick-authoring-secret"
	policyID := "existing-keyword"
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: policyID, Source: "tenant", RuleType: "keyword"}}}
	h := &quickCreateHandler{policies: newSecurityPoliciesHandler(&Dependencies{SecurityEngineInternalToken: secret}, store, &fakeRegexValidator{valid: true})}
	response := httptest.NewRecorder()
	request := policyHandlerRequest(http.MethodPost, "/generate", `{"kind":"number","policy_id":"existing-keyword","positive_samples":["HT-2026-000123","HT-2026-000456"]}`, "platform_admin")
	auth.GetUser(request.Context()).TenantID = "tenant-quick-existing"
	h.generate(response, request)
	var generated struct {
		Matcher  securityPolicyMatcherRequest `json:"matcher"`
		Segments []quickNumberSegment         `json:"segments"`
		Proof    string                       `json:"authoring_proof"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &generated) != nil || generated.Proof == "" {
		t.Fatalf("existing policy generation status=%d body=%s", response.Code, response.Body.String())
	}
	var config struct {
		Regex string `json:"regex"`
	}
	if err := json.Unmarshal(generated.Matcher.Config, &config); err != nil || !verifyQuickAuthoring(secret, generated.Proof, "tenant-quick-existing", policyID, config.Regex, generated.Segments) {
		t.Fatal("proof must bind generated authoring to current tenant and existing policy")
	}
	if verifyQuickAuthoring(secret, generated.Proof, "tenant-b", policyID, config.Regex, generated.Segments) || verifyQuickAuthoring(secret, generated.Proof, "tenant-quick-existing", "another-policy", config.Regex, generated.Segments) || verifyQuickAuthoring(secret, generated.Proof, "tenant-quick-existing", "", config.Regex, generated.Segments) {
		t.Fatal("proof must not authorize another tenant, policy or new creation")
	}
	if store.created.Matcher != nil || store.updatedID != "" {
		t.Fatal("generation must not save or update the policy")
	}
}

type quickTenantRestrictedStore struct{ fakeSecurityPolicyStore }

func (s *quickTenantRestrictedStore) GetSecurityPolicy(ctx context.Context, tenantID, id string) (*repository.SecurityPolicy, error) {
	if tenantID != "tenant-quick-invalid" {
		return nil, repository.ErrSecurityPolicyNotFound
	}
	return s.fakeSecurityPolicyStore.GetSecurityPolicy(ctx, tenantID, id)
}

func TestQuickGenerateWithSamplesRejectsInvalidPolicyIDs(t *testing.T) {
	store := &quickTenantRestrictedStore{fakeSecurityPolicyStore: fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: "system-policy", Source: "system", RuleType: "keyword"}, {ID: "tenant-policy", Source: "tenant", RuleType: "regex"}}}}
	h := &quickCreateHandler{policies: newSecurityPoliciesHandler(&Dependencies{SecurityEngineInternalToken: "test-quick-authoring-secret"}, store, &fakeRegexValidator{valid: true})}
	for _, tc := range []struct{ name, policyID, tenant string }{
		{"missing", "missing-policy", "tenant-quick-invalid"},
		{"system", "system-policy", "tenant-quick-invalid"},
		{"another tenant", "tenant-policy", "tenant-quick-foreign"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := policyHandlerRequest(http.MethodPost, "/generate", `{"kind":"number","policy_id":"`+tc.policyID+`","positive_samples":["HT-2026-000123","HT-2026-000456"]}`, "platform_admin")
			auth.GetUser(request.Context()).TenantID = tc.tenant
			response := httptest.NewRecorder()
			h.generate(response, request)
			if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "invalid_matcher") || strings.Contains(response.Body.String(), "authoring_proof") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestQuickSegmentsOnlyRegenerationRequiresSavedAuthoring(t *testing.T) {
	pattern := `(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])`
	segments := []repository.SecurityPolicyNumberSegment{{Kind: "fixed", Value: "HT-", Length: 3}, {Kind: "fixed", Value: "2026", Length: 4}, {Kind: "fixed", Value: "-", Length: 1}, {Kind: "digits", Length: 6}}
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: "policy-1", Source: "tenant", RuleType: "regex", MatchConfigJSON: json.RawMessage(`{"regex":"(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])"}`), Authoring: &repository.SecurityPolicyAuthoring{Version: 1, Kind: "number", MatcherPattern: pattern, Segments: segments}}}}
	validator := &fakeRegexValidator{valid: true}
	h := &quickCreateHandler{policies: newSecurityPoliciesHandler(&Dependencies{SecurityEngineInternalToken: "test-quick-authoring-secret"}, store, validator)}
	body := `{"kind":"number","segments":[{"kind":"fixed","value":"HT-"},{"kind":"digits","length":4},{"kind":"fixed","value":"-"},{"kind":"digits","length":6}]}`
	for _, invalid := range []string{body, `{"kind":"number","policy_id":"missing","segments":[{"kind":"fixed","value":"HT-"},{"kind":"digits","length":6}]}`} {
		rec := httptest.NewRecorder()
		h.generate(rec, policyHandlerRequest(http.MethodPost, "/generate", invalid, "platform_admin"))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("unauthorized regeneration accepted: %d %s", rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.generate(rec, policyHandlerRequest(http.MethodPost, "/generate", strings.Replace(body, `"segments"`, `"policy_id":"policy-1","segments"`, 1), "platform_admin"))
	if rec.Code != http.StatusOK || len(validator.patterns) != 1 {
		t.Fatalf("saved edit: %d %s", rec.Code, rec.Body.String())
	}
	store.policies[0].MatchConfigJSON = json.RawMessage(`{"regex":".*"}`)
	tampered := httptest.NewRecorder()
	h.generate(tampered, policyHandlerRequest(http.MethodPost, "/generate", strings.Replace(body, `"segments"`, `"policy_id":"policy-1","segments"`, 1), "platform_admin"))
	if tampered.Code != 422 {
		t.Fatalf("stale authoring accepted: %d %s", tampered.Code, tampered.Body.String())
	}
	store.policies[0].MatchConfigJSON = json.RawMessage(`{"regex":"(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])"}`)
	store.policies[0].Authoring = nil
	missing := httptest.NewRecorder()
	h.generate(missing, policyHandlerRequest(http.MethodPost, "/generate", strings.Replace(body, `"segments"`, `"policy_id":"policy-1","segments"`, 1), "platform_admin"))
	if missing.Code != 422 {
		t.Fatalf("missing authoring accepted: %d %s", missing.Code, missing.Body.String())
	}
}
