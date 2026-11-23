package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const quickRequestLimit = 8 << 10

type quickAuthoringProof struct {
	TenantID string               `json:"tenant_id"`
	PolicyID string               `json:"policy_id"`
	Pattern  string               `json:"pattern"`
	Segments []quickNumberSegment `json:"segments"`
	Expires  int64                `json:"expires"`
}

func signQuickAuthoring(secret string, proof quickAuthoringProof) string {
	if secret == "" {
		return ""
	}
	data, _ := json.Marshal(proof)
	signature := hmac.New(sha256.New, []byte(secret))
	_, _ = signature.Write(data)
	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(signature.Sum(nil))
}

func verifyQuickAuthoring(secret, token, tenantID, policyID, pattern string, segments []quickNumberSegment) bool {
	if secret == "" || len(token) > 4096 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(data) > 2048 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(data)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return false
	}
	var proof quickAuthoringProof
	if json.Unmarshal(data, &proof) != nil || proof.TenantID != tenantID || proof.PolicyID != policyID || proof.Pattern != pattern || proof.Expires <= time.Now().Unix() {
		return false
	}
	expected, _ := json.Marshal(segments)
	actual, _ := json.Marshal(proof.Segments)
	return hmac.Equal(expected, actual)
}

type quickCreateRequest struct {
	Kind            string                        `json:"kind"`
	PositiveSamples []string                      `json:"positive_samples"`
	Samples         []string                      `json:"samples"`
	Segments        []quickNumberSegment          `json:"segments"`
	RequestVersion  string                        `json:"request_version"`
	PolicyID        string                        `json:"policy_id"`
	Matcher         *securityPolicyMatcherRequest `json:"matcher"`
}
type quickNumberSegment struct {
	Kind   string `json:"kind"`
	Value  string `json:"value,omitempty"`
	Length int    `json:"length,omitempty"`
}

type quickMatch struct {
	SampleIndex      int     `json:"sample_index"`
	Matched          bool    `json:"matched"`
	Location         *string `json:"location"`
	RedactedEvidence *string `json:"redacted_evidence"`
}
type quickEngineRequest struct {
	Matcher              *securityPolicyMatcherRequest `json:"matcher,omitempty"`
	CapabilityCategories []string                      `json:"capability_categories,omitempty"`
	Stage                string                        `json:"stage"`
	Samples              []string                      `json:"samples"`
}
type quickEngineResponse struct {
	Matches []quickMatch `json:"matches"`
}
type quickMatcherEngine interface {
	PreviewQuickMatcher(context.Context, quickEngineRequest) (*quickEngineResponse, error)
}
type quickCreateHandler struct {
	policies *securityPoliciesHandler
	engine   quickMatcherEngine
}

func quickHandlerFromDependencies(deps *Dependencies) *quickCreateHandler {
	return &quickCreateHandler{policies: securityPoliciesHandlerFromDependencies(deps), engine: newSecurityEngineClient(deps.SecurityEngineURL, deps.SecurityEngineInternalToken)}
}

var quickBudget = struct {
	sync.Mutex
	tenants map[string][]time.Time
}{tenants: make(map[string][]time.Time)}

func allowQuickRequest(tenant string) bool {
	quickBudget.Lock()
	defer quickBudget.Unlock()
	now := time.Now()
	for key, times := range quickBudget.tenants {
		kept := times[:0]
		for _, at := range times {
			if now.Sub(at) < time.Minute {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(quickBudget.tenants, key)
		} else {
			quickBudget.tenants[key] = kept
		}
	}
	if len(quickBudget.tenants[tenant]) >= 20 {
		return false
	}
	if _, exists := quickBudget.tenants[tenant]; !exists && len(quickBudget.tenants) >= 1024 {
		return false
	}
	quickBudget.tenants[tenant] = append(quickBudget.tenants[tenant], now)
	return true
}
func decodeQuickRequest(w http.ResponseWriter, r *http.Request, out *quickCreateRequest) error {
	r.Body = http.MaxBytesReader(w, r.Body, quickRequestLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
func quickSamplesValid(req quickCreateRequest) bool {
	if len(req.Samples) > 12 || len(req.PositiveSamples) > 12 || len(req.Samples)+len(req.PositiveSamples) > 12 {
		return false
	}
	total := 0
	for _, sample := range append(append([]string{}, req.PositiveSamples...), req.Samples...) {
		total += len(sample)
		if len(sample) > 1024 || !utf8.ValidString(sample) {
			return false
		}
	}
	return total <= 4096
}

func quickEscapePythonLiteral(value string) string {
	var escaped strings.Builder
	for _, char := range value {
		if strings.ContainsRune(`\.+*?^$()[]{}|`, char) {
			escaped.WriteByte('\\')
		}
		escaped.WriteRune(char)
	}
	return escaped.String()
}

func quickNumberPattern(samples []string) (string, []quickNumberSegment, bool) {
	if len(samples) < 2 || len(samples) > 12 {
		return "", nil, false
	}
	length := len(samples[0])
	if length < 6 || length > 32 {
		return "", nil, false
	}
	allowed := regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	unique := make(map[string]bool, len(samples))
	for _, sample := range samples {
		if len(sample) != length || !allowed.MatchString(sample) {
			return "", nil, false
		}
		unique[sample] = true
		for pos := range sample {
			digit := sample[pos] >= '0' && sample[pos] <= '9'
			firstDigit := samples[0][pos] >= '0' && samples[0][pos] <= '9'
			if digit != firstDigit || (!digit && sample[pos] != samples[0][pos]) {
				return "", nil, false
			}
		}
	}
	if len(unique) < 2 {
		return "", nil, false
	}
	changed := make([]bool, length)
	for pos := 0; pos < length; pos++ {
		for _, sample := range samples[1:] {
			if sample[pos] != samples[0][pos] {
				changed[pos] = true
				break
			}
		}
	}
	segments := make([]quickNumberSegment, 0, length)
	for pos := 0; pos < length; {
		end := pos + 1
		digit := samples[0][pos] >= '0' && samples[0][pos] <= '9'
		for end < length && (samples[0][end] >= '0' && samples[0][end] <= '9') == digit {
			end++
		}
		variable := false
		for _, diff := range changed[pos:end] {
			variable = variable || diff
		}
		if variable {
			if !digit || end-pos > 18 {
				return "", nil, false
			}
			segments = append(segments, quickNumberSegment{Kind: "digits", Length: end - pos})
		} else {
			fixed := samples[0][pos:end]
			segments = append(segments, quickNumberSegment{Kind: "fixed", Value: fixed, Length: len(fixed)})
		}
		pos = end
	}
	return quickPatternForSegments(segments), segments, true
}

func quickPatternForSegments(segments []quickNumberSegment) string {
	var parts strings.Builder
	parts.WriteString(`(?<![A-Za-z0-9_])`)
	for _, segment := range segments {
		switch segment.Kind {
		case "fixed":
			parts.WriteString(quickEscapePythonLiteral(segment.Value))
		case "digits":
			parts.WriteString(`[0-9]{` + strconv.Itoa(segment.Length) + `}`)
		case "letters":
			parts.WriteString(`[A-Za-z]{` + strconv.Itoa(segment.Length) + `}`)
		}
	}
	parts.WriteString(`(?![A-Za-z0-9_])`)
	return parts.String()
}

func quickNumberEditedPattern(samples []string, segments []quickNumberSegment) (string, bool) {
	if len(segments) == 0 || len(segments) > 32 {
		return "", false
	}
	if len(samples) > 0 {
		if _, _, valid := quickNumberPattern(samples); !valid {
			return "", false
		}
	}
	total, variable := 0, false
	for _, segment := range segments {
		switch segment.Kind {
		case "fixed":
			if segment.Value == "" || !regexp.MustCompile(`^[A-Za-z0-9._/-]+$`).MatchString(segment.Value) || (segment.Length != 0 && segment.Length != len(segment.Value)) {
				return "", false
			}
			total += len(segment.Value)
		case "digits", "letters":
			if segment.Value != "" || segment.Length < 1 || segment.Length > 18 {
				return "", false
			}
			variable = true
			total += segment.Length
		default:
			return "", false
		}
	}
	if !variable || total < 6 || total > 32 || (len(samples) > 0 && total != len(samples[0])) {
		return "", false
	}
	for _, sample := range samples {
		offset := 0
		for _, segment := range segments {
			length := segment.Length
			if segment.Kind == "fixed" {
				length = len(segment.Value)
			}
			part := sample[offset : offset+length]
			switch segment.Kind {
			case "fixed":
				if part != segment.Value {
					return "", false
				}
			case "digits":
				if !regexp.MustCompile(`^[0-9]+$`).MatchString(part) {
					return "", false
				}
			case "letters":
				if !regexp.MustCompile(`^[A-Za-z]+$`).MatchString(part) {
					return "", false
				}
			}
			offset += length
		}
	}
	return quickPatternForSegments(segments), true
}

func quickMatcher(req quickCreateRequest) (securityPolicyMatcherRequest, []quickNumberSegment, bool) {
	var matcher securityPolicyMatcherRequest
	if req.Kind != "number" {
		return matcher, nil, false
	}
	pattern, segments, ok := quickNumberPattern(req.PositiveSamples)
	if len(req.PositiveSamples) == 0 && req.Segments != nil {
		pattern, ok = quickNumberEditedPattern(nil, req.Segments)
		segments = req.Segments
	} else if ok && req.Segments != nil {
		pattern, ok = quickNumberEditedPattern(req.PositiveSamples, req.Segments)
		segments = req.Segments
	}
	if !ok {
		return matcher, nil, false
	}
	matcher.Type = "regex"
	matcher.Config, _ = json.Marshal(map[string]string{"regex": pattern})
	return matcher, segments, true
}

func (c *securityEngineClient) PreviewQuickMatcher(ctx context.Context, input quickEngineRequest) (*quickEngineResponse, error) {
	if c == nil || c.baseURL == "" || c.internalToken == "" || c.client == nil {
		return nil, errors.New("engine unavailable")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("invalid preview request")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/v1/internal/policies/quick-create/preview/", bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid preview request")
	}
	c.setRequestHeaders(req)
	response, err := c.client.Do(req)
	if err != nil {
		return nil, errors.New("engine unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("engine rejected preview")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("invalid engine response")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 {
		return nil, errors.New("invalid engine response")
	}
	var parsed quickEngineResponse
	if err := json.Unmarshal(raw, &parsed); err != nil || len(parsed.Matches) != len(input.Samples) {
		return nil, errors.New("invalid engine response")
	}
	for i, item := range parsed.Matches {
		if item.SampleIndex != i || (item.Matched && (item.Location == nil || item.RedactedEvidence == nil)) || (!item.Matched && (item.Location != nil || item.RedactedEvidence != nil)) {
			return nil, errors.New("invalid engine response")
		}
		if item.Matched {
			if !regexp.MustCompile("^content\\[[0-9]+:[0-9]+\\]$").MatchString(*item.Location) || *item.RedactedEvidence != "<REDACTED>" {
				return nil, errors.New("invalid engine response")
			}
		}
	}
	return &parsed, nil
}

func (h *quickCreateHandler) quickInput(w http.ResponseWriter, r *http.Request, input *quickCreateRequest) bool {
	user := requirePolicyWriter(w, r)
	if user == nil {
		return false
	}
	if !allowQuickRequest(user.TenantID) {
		writeErrorWithStatus(w, 429, "quick_create_rate_limited", "too many quick-create requests")
		return false
	}
	if err := decodeQuickRequest(w, r, input); err != nil {
		writeErrorWithStatus(w, 400, "invalid_request", "invalid quick-create request")
		return false
	}
	if !quickSamplesValid(*input) || len(input.RequestVersion) > 64 || !utf8.ValidString(input.RequestVersion) {
		writeErrorWithStatus(w, 422, "invalid_samples", "samples exceed quick-create limits")
		return false
	}
	return true
}

func (h *quickCreateHandler) generate(w http.ResponseWriter, r *http.Request) {
	var input quickCreateRequest
	if !h.quickInput(w, r, &input) {
		return
	}
	if input.Kind != "number" || len(input.Samples) > 0 || input.Matcher != nil {
		writeErrorWithStatus(w, 422, "invalid_request", "only number samples are supported for generation")
		return
	}
	if len(input.PositiveSamples) == 0 {
		user := auth.GetUser(r.Context())
		if input.PolicyID == "" || input.Segments == nil {
			writeErrorWithStatus(w, 422, "invalid_matcher", "saved number policy and edited segments are required")
			return
		}
		policy, err := h.policies.store.GetSecurityPolicy(r.Context(), user.TenantID, input.PolicyID)
		if err != nil || policy == nil || policy.Source != "tenant" || policy.Authoring == nil || policy.Authoring.Version != 1 || policy.Authoring.Kind != "number" || policy.RuleType != "regex" {
			writeErrorWithStatus(w, 422, "invalid_matcher", "saved number policy authoring is unavailable")
			return
		}
		oldSegments := make([]quickNumberSegment, 0, len(policy.Authoring.Segments))
		for _, seg := range policy.Authoring.Segments {
			oldSegments = append(oldSegments, quickNumberSegment{Kind: seg.Kind, Value: seg.Value, Length: seg.Length})
		}
		oldPattern, valid := quickNumberEditedPattern(nil, oldSegments)
		stored, ok := repository.NormalizeRuntimeMatcher(policy.RuleType, policy.MatchConfigJSON)
		if !valid || !ok || stored.Regex != oldPattern || policy.Authoring.MatcherPattern != oldPattern {
			writeErrorWithStatus(w, 422, "invalid_matcher", "saved number policy authoring is unavailable")
			return
		}
	} else if input.PolicyID != "" {
		user := auth.GetUser(r.Context())
		policy, err := h.policies.store.GetSecurityPolicy(r.Context(), user.TenantID, input.PolicyID)
		if err != nil || policy == nil || policy.Source != "tenant" {
			writeErrorWithStatus(w, 422, "invalid_matcher", "editable tenant policy is unavailable")
			return
		}
	}
	matcher, segments, ok := quickMatcher(input)
	if !ok {
		writeErrorWithStatus(w, 422, "invalid_matcher", "provide two distinct equal-length ASCII identifiers with the same structure; adjust fixed and numeric segments to align with every sample")
		return
	}
	if _, err := h.policies.matcherInput(r.Context(), &matcher, false); err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	var config struct {
		Regex string `json:"regex"`
	}
	_ = json.Unmarshal(matcher.Config, &config)
	secret := ""
	if h.policies.deps != nil {
		secret = h.policies.deps.SecurityEngineInternalToken
	}
	if secret == "" {
		writeErrorWithStatus(w, 503, "authoring_proof_unavailable", "number authoring proof is unavailable")
		return
	}
	user := auth.GetUser(r.Context())
	proof := signQuickAuthoring(secret, quickAuthoringProof{TenantID: user.TenantID, PolicyID: input.PolicyID, Pattern: config.Regex, Segments: segments, Expires: time.Now().Add(15 * time.Minute).Unix()})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"matcher": matcher, "segments": segments, "authoring_proof": proof,
		"explanation":     "Entire changing digit runs are generalized by width; fixed segments stay literal, and fixed year segments may be changed to equal-width digits. ASCII letter, digit or underscore adjacency does not match; review false positives and misses.",
		"request_version": input.RequestVersion,
	})
}

func (h *quickCreateHandler) execute(w http.ResponseWriter, r *http.Request) {
	var input quickCreateRequest
	if !h.quickInput(w, r, &input) {
		return
	}
	if input.Kind != "" || input.PolicyID != "" || len(input.PositiveSamples) > 0 || input.Segments != nil || len(input.Samples) == 0 {
		writeErrorWithStatus(w, 422, "invalid_request", "provide a matcher and trial samples")
		return
	}
	var matcher securityPolicyMatcherRequest
	if input.Matcher == nil {
		writeErrorWithStatus(w, 422, "invalid_matcher", "provide a matcher")
		return
	}
	matcher = *input.Matcher
	if _, err := h.policies.matcherInput(r.Context(), &matcher, false); err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	result, err := h.engine.PreviewQuickMatcher(r.Context(), quickEngineRequest{Matcher: &matcher, Stage: "input", Samples: input.Samples})
	if err != nil {
		writeErrorWithStatus(w, 503, "preview_unavailable", "exact runtime preview is unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"matches":         result.Matches,
		"warnings":        []string{"Preview is advisory; unmatched trial text does not prevent saving in the policy editor. Review false positives and misses."},
		"request_version": input.RequestVersion,
	})
}

func GenerateQuickSecurityPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { quickHandlerFromDependencies(deps).generate(w, r) }
}

func PreviewQuickSecurityPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { quickHandlerFromDependencies(deps).execute(w, r) }
}
