package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
	"github.com/go-chi/chi/v5"
)

const maxSecurityPolicyRequestBytes = 64 << 10

type securityPolicyStore interface {
	ListSecurityPolicies(context.Context, string) ([]repository.SecurityPolicy, error)
	GetSecurityPolicy(context.Context, string, string) (*repository.SecurityPolicy, error)
	ListSecurityCapabilities(context.Context) ([]repository.SecurityPolicyCapability, error)
	CreateSecurityPolicy(context.Context, string, repository.CreateSecurityPolicyInput) (*repository.SecurityPolicy, error)
	UpdateSecurityPolicy(context.Context, string, string, repository.SecurityPolicyUpdate) (*repository.SecurityPolicy, error)
	BatchUpdateSecurityPolicies(context.Context, string, []repository.SecurityPolicyBatchUpdate) error
	DeleteSecurityPolicy(context.Context, string, string) error
}

type securityPolicyRegexValidator interface {
	ValidateRegex(context.Context, string) (bool, string, error)
}

type securityPolicyRuntimeProof struct {
	RulePackVersion    string
	RuntimeVerified    bool
	RuntimeStatus      string
	Degraded           bool
	ActualSkippedCount *int
	ActivePolicyIDs    map[string]struct{}
}

type securityPolicyRuntimeProofProvider func(context.Context, string) (securityPolicyRuntimeProof, error)

func unavailableSecurityPolicyRuntimeProof() securityPolicyRuntimeProof {
	return securityPolicyRuntimeProof{
		RuntimeStatus:   runtimeStatusUnavailable,
		ActivePolicyIDs: map[string]struct{}{},
	}
}

func (proof securityPolicyRuntimeProof) complete() bool {
	return proof.RuntimeVerified && !proof.Degraded &&
		proof.RuntimeStatus != runtimeStatusAppliedWithStaleNodes &&
		proof.ActualSkippedCount != nil && *proof.ActualSkippedCount == 0
}

func securityPolicyRuntimeProofFromDependencies(deps *Dependencies) securityPolicyRuntimeProofProvider {
	return func(ctx context.Context, tenantID string) (securityPolicyRuntimeProof, error) {
		pack, err := compileTenantRulePack(ctx, deps, tenantID)
		if err != nil {
			return securityPolicyRuntimeProof{}, err
		}
		status := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
		capabilities, err := deps.RuleRepo.ListSecurityCapabilities(ctx)
		if err != nil {
			return securityPolicyRuntimeProof{}, fmt.Errorf(
				"load capability catalog for runtime proof: %w", err,
			)
		}
		activePolicyIDs := activePolicyIDsWithCapabilityHealth(
			pack,
			capabilities,
			unavailableSecurityPolicyCapabilityComponents(ctx, deps),
		)
		return securityPolicyRuntimeProof{
			RulePackVersion:    pack.Version,
			RuntimeVerified:    status.RuntimeVerified,
			RuntimeStatus:      status.Status,
			Degraded:           status.Degraded,
			ActualSkippedCount: status.ActualSkippedCount,
			ActivePolicyIDs:    activePolicyIDs,
		}, nil
	}
}

func activeSecurityPolicyIDs(pack *rules.RulePack) map[string]struct{} {
	if pack == nil {
		return map[string]struct{}{}
	}
	ids := make(map[string]struct{}, len(pack.Policies)+len(pack.Rules))
	for _, policy := range pack.Policies {
		if id := strings.TrimSpace(policy.PolicyID); id != "" {
			ids[id] = struct{}{}
		}
	}
	// policy_code 为空的历史 matcher 只出现在 rules 数组。节点回执
	// 同样证明它们已被加载，不能在新策略页永久显示为未加载。
	for _, rule := range pack.Rules {
		if id := strings.TrimSpace(rule.RuleID); id != "" {
			ids[id] = struct{}{}
		}
	}
	return ids
}

type securityPoliciesHandler struct {
	deps         *Dependencies
	store        securityPolicyStore
	validator    securityPolicyRegexValidator
	runtimeProof securityPolicyRuntimeProofProvider
}

func newSecurityPoliciesHandler(deps *Dependencies, store securityPolicyStore, validator securityPolicyRegexValidator, providers ...securityPolicyRuntimeProofProvider) *securityPoliciesHandler {
	provider := securityPolicyRuntimeProofProvider(func(context.Context, string) (securityPolicyRuntimeProof, error) {
		return unavailableSecurityPolicyRuntimeProof(), nil
	})
	if len(providers) > 0 && providers[0] != nil {
		provider = providers[0]
	}
	return &securityPoliciesHandler{deps: deps, store: store, validator: validator, runtimeProof: provider}
}

func securityPoliciesHandlerFromDependencies(deps *Dependencies) *securityPoliciesHandler {
	return newSecurityPoliciesHandler(
		deps,
		deps.RuleRepo,
		newSecurityEngineClient(deps.SecurityEngineURL, deps.SecurityEngineInternalToken),
		securityPolicyRuntimeProofFromDependencies(deps),
	)
}

type securityPolicyMatcherRequest struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

type createSecurityPolicyRequest struct {
	Redaction            *repository.SecurityPolicyRedaction      `json:"redaction"`
	SemanticAction       string                                   `json:"semantic_action"`
	Name                 string                                   `json:"name"`
	Description          string                                   `json:"description"`
	Scene                string                                   `json:"scene"`
	Severity             string                                   `json:"severity"`
	Action               string                                   `json:"action"`
	Enabled              bool                                     `json:"enabled"`
	Matcher              *securityPolicyMatcherRequest            `json:"matcher"`
	CapabilityCategories []string                                 `json:"capability_categories"`
	BindingMode          string                                   `json:"binding_mode"`
	SubjectBinding       *repository.SecurityPolicySubjectBinding `json:"subject_binding"`
	Authoring            *repository.SecurityPolicyAuthoring      `json:"authoring"`
	AuthoringProof       string                                   `json:"authoring_proof"`
}

type updateSecurityPolicyRequest struct {
	Redaction            *repository.SecurityPolicyRedaction      `json:"redaction"`
	SemanticAction       *string                                  `json:"semantic_action"`
	Name                 *string                                  `json:"name"`
	Description          *string                                  `json:"description"`
	Scene                *string                                  `json:"scene"`
	Severity             *string                                  `json:"severity"`
	Action               *string                                  `json:"action"`
	Enabled              *bool                                    `json:"enabled"`
	Matcher              *securityPolicyMatcherRequest            `json:"matcher"`
	ClearMatcher         bool                                     `json:"clear_matcher"`
	CapabilityCategories *[]string                                `json:"capability_categories"`
	BindingMode          *string                                  `json:"binding_mode"`
	SubjectBinding       *repository.SecurityPolicySubjectBinding `json:"subject_binding"`
	ClearSubjectBinding  bool                                     `json:"clear_subject_binding"`
	Authoring            *repository.SecurityPolicyAuthoring      `json:"authoring"`
	AuthoringProof       string                                   `json:"authoring_proof"`
}

type batchSecurityPolicyItemRequest struct {
	Redaction *repository.SecurityPolicyRedaction `json:"redaction"`
	ID        string                              `json:"id"`
	Action    *string                             `json:"action"`
	Enabled   *bool                               `json:"enabled"`
}

type batchSecurityPolicyRequest struct {
	Updates []batchSecurityPolicyItemRequest `json:"updates"`
}

type securityPolicyMatcherResponse struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

type securityPolicyResponse struct {
	Redaction           *repository.SecurityPolicyRedaction      `json:"redaction"`
	SemanticAction      string                                   `json:"semantic_action"`
	ID                  string                                   `json:"id"`
	Name                string                                   `json:"name"`
	Description         string                                   `json:"description"`
	Scene               string                                   `json:"scene"`
	Severity            string                                   `json:"severity"`
	DefaultSeverity     string                                   `json:"default_severity"`
	SeverityOverridden  bool                                     `json:"severity_overridden"`
	Action              string                                   `json:"action"`
	Enabled             bool                                     `json:"enabled"`
	Source              string                                   `json:"source"`
	Ownership           string                                   `json:"ownership"`
	Origin              string                                   `json:"origin"`
	DetectionBasis      string                                   `json:"detection_basis"`
	DetectionConfigured bool                                     `json:"detection_configured"`
	DetectionReady      bool                                     `json:"detection_ready"`
	RuntimeActive       bool                                     `json:"runtime_active"`
	DetectionIssue      string                                   `json:"detection_issue,omitempty"`
	UnavailableCount    int                                      `json:"unavailable_capability_count"`
	Capabilities        []securityCapabilityResponse             `json:"capabilities"`
	Matcher             *securityPolicyMatcherResponse           `json:"matcher,omitempty"`
	SubjectBinding      *repository.SecurityPolicySubjectBinding `json:"subject_binding,omitempty"`
	Authoring           *repository.SecurityPolicyAuthoring      `json:"authoring,omitempty"`
}

type securityPoliciesResponse struct {
	Data              []securityPolicyResponse `json:"data"`
	Total             int                      `json:"total"`
	EnabledCount      int                      `json:"enabled_count"`
	ConfiguredCount   int                      `json:"configured_count"`
	ReadyCount        int                      `json:"ready_count"`
	ActiveCount       int                      `json:"active_count"`
	PendingCount      int                      `json:"pending_count"`
	UnconfiguredCount int                      `json:"unconfigured_count"`
	RuntimeVerified   bool                     `json:"runtime_verified"`
	RuntimeStatus     string                   `json:"runtime_status"`
}

type securityCapabilityResponse struct {
	Category        string   `json:"category"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	Enabled         bool     `json:"enabled"`
	SupportedStages []string `json:"supported_stages"`
	AllowedActions  []string `json:"allowed_actions"`
	MaskCapable     bool     `json:"mask_capable"`
	// SemanticJudge 表示该能力由语义裁判（智能分析）执行：是否拦截取决于策略的
	// semantic_action（高置信时拦截、分析不可用时放行），不取决于策略处置动作。
	SemanticJudge    bool   `json:"semantic_judge"`
	BindingMode      string `json:"binding_mode,omitempty"`
	BoundPolicyCount *int   `json:"bound_policy_count,omitempty"`
	// 以下四项来自检测能力说明目录；目录里没有这个能力时都为空，页面不显示“匹配什么”。
	Matches      string   `json:"matches,omitempty"`
	HitExamples  []string `json:"hit_examples,omitempty"`
	MissExamples []string `json:"miss_examples,omitempty"`
	JudgedByAI   bool     `json:"judged_by_ai,omitempty"`
}

// securityCapabilityFromRepository 不带匹配说明：策略里的 capabilities 用它，
// 避免每条策略都重复一份说明（前端按能力键到能力列表里取）。
func securityCapabilityFromRepository(capability repository.SecurityPolicyCapability) securityCapabilityResponse {
	return securityCapabilityResponse{
		Category: capability.Category, Name: capability.Name, Kind: capability.Kind,
		Enabled: capability.Enabled, SupportedStages: capability.SupportedStages,
		AllowedActions: capability.AllowedActions, MaskCapable: capability.MaskCapable,
		SemanticJudge: repository.IsSemanticJudgeCapability(capability),
		BindingMode:   capability.BindingMode,
	}
}

// securityCapabilityWithDocs 只给能力列表接口用，带上“匹配什么”的说明。
func securityCapabilityWithDocs(capability repository.SecurityPolicyCapability) securityCapabilityResponse {
	response := securityCapabilityFromRepository(capability)
	if doc, ok := repository.CapabilityDocFor(capability.Category); ok {
		response.Matches, response.HitExamples, response.MissExamples, response.JudgedByAI = doc.Matches, doc.HitExamples, doc.MissExamples, doc.JudgedByAI
	}
	return response
}

func securityPolicyCapabilities(capabilities []repository.SecurityPolicyCapability) []securityCapabilityResponse {
	result := make([]securityCapabilityResponse, 0, len(capabilities))
	for _, capability := range capabilities {
		result = append(result, securityCapabilityFromRepository(capability))
	}
	return result
}

func policyResponse(policy repository.SecurityPolicy, runtimeActive bool) securityPolicyResponse {
	detectionReady := policy.DetectionReady || runtimeActive
	detectionIssue := policy.DetectionIssue
	if runtimeActive {
		// 完整的规则包回执已经证明该策略被节点接收并加载。
		// 这只修正加载状态，不向数据库伪造 matcher validation stamp。
		detectionIssue = ""
	}
	response := securityPolicyResponse{
		ID: policy.ID, Name: policy.Name, Description: policy.Description,
		Scene: policy.Scene, Severity: policy.Severity, Action: policy.Action,
		DefaultSeverity: policy.DefaultSeverity, SeverityOverridden: policy.SeverityOverridden,
		Enabled: policy.Enabled, Source: policy.Source,
		Ownership: policy.Ownership, Origin: policy.Origin,
		DetectionBasis:      policy.DetectionBasis,
		DetectionConfigured: policy.DetectionConfigured,
		DetectionReady:      detectionReady,
		RuntimeActive:       runtimeActive,
		DetectionIssue:      detectionIssue,
		UnavailableCount:    policy.UnavailableCount,
		Capabilities:        securityPolicyCapabilities(policy.Capabilities),
		SubjectBinding:      policy.SubjectBinding,
		Authoring:           policy.Authoring,
		Redaction:           policy.Redaction,
		SemanticAction:      semanticActionOrDefault(policy.SemanticAction),
	}
	if policy.Source == "tenant" && len(policy.MatchConfigJSON) > 0 {
		response.Matcher = &securityPolicyMatcherResponse{
			Type:   policy.RuleType,
			Config: append(json.RawMessage(nil), policy.MatchConfigJSON...),
		}
	}
	if response.Capabilities == nil {
		response.Capabilities = []securityCapabilityResponse{}
	}
	return response
}

func decodeSecurityPolicyJSON(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecurityPolicyRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}

func decodeMatcherConfig(raw json.RawMessage, out any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("matcher config is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("matcher config must contain exactly one JSON value")
	}
	return nil
}

func (h *securityPoliciesHandler) matcherInput(ctx context.Context, request *securityPolicyMatcherRequest, allowUnvalidatedDraft bool) (*repository.SecurityPolicyMatcherInput, error) {
	if request == nil {
		return nil, nil
	}
	ruleType := strings.TrimSpace(request.Type)
	var canonical []byte
	validated := false
	switch ruleType {
	case "regex":
		var config struct {
			Regex string `json:"regex"`
		}
		if err := decodeMatcherConfig(request.Config, &config); err != nil {
			return nil, fmt.Errorf("invalid matcher configuration")
		}
		// Validate the exact value that the repository will persist and the
		// runtime will compile. A raw value such as backslash+space is valid in
		// Python before trimming but becomes an invalid trailing backslash after
		// repository normalization.
		config.Regex = strings.TrimSpace(config.Regex)
		if config.Regex == "" {
			return nil, fmt.Errorf("invalid matcher configuration")
		}
		encoded, _ := json.Marshal(config)
		canonical = encoded
		if h.validator == nil {
			if !allowUnvalidatedDraft {
				return nil, errRegexValidatorUnavailable
			}
			break
		}
		valid, errorCode, err := h.validator.ValidateRegex(ctx, config.Regex)
		if err != nil {
			if !allowUnvalidatedDraft {
				return nil, errRegexValidatorUnavailable
			}
			break
		}
		if !valid {
			if strings.Contains(strings.ToLower(errorCode), "unsafe") {
				return nil, errRegexUnsafe
			}
			return nil, errRegexInvalidSyntax
		}
		validated = true
	case "keyword":
		var config struct {
			Keywords []string `json:"keywords"`
		}
		if err := decodeMatcherConfig(request.Config, &config); err != nil {
			return nil, fmt.Errorf("invalid matcher configuration")
		}
		canonical, _ = json.Marshal(config)
	case "field_name":
		var config struct {
			FieldNames []string `json:"field_names"`
		}
		if err := decodeMatcherConfig(request.Config, &config); err != nil {
			return nil, fmt.Errorf("invalid matcher configuration")
		}
		canonical, _ = json.Marshal(config)
	default:
		return nil, fmt.Errorf("invalid matcher type")
	}
	return &repository.SecurityPolicyMatcherInput{Type: ruleType, ConfigJSON: canonical, RuntimeValidated: validated}, nil
}

var (
	errRegexInvalidSyntax        = errors.New("regex invalid syntax")
	errRegexUnsafe               = errors.New("regex unsafe")
	errRegexValidatorUnavailable = errors.New("regex validator unavailable")
)

func requirePolicyWriter(w http.ResponseWriter, r *http.Request) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found")
		return nil
	}
	if !roles.CanManageSecurityPolicy(user.Role) && user.Role != "platform_connector" {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform administrators can change security policies")
		return nil
	}
	return user
}

func policyReader(w http.ResponseWriter, r *http.Request) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found")
	}
	return user
}

func (h *securityPoliciesHandler) list(w http.ResponseWriter, r *http.Request) {
	user := policyReader(w, r)
	if user == nil {
		return
	}
	policies, err := h.store.ListSecurityPolicies(r.Context(), user.TenantID)
	if err != nil {
		log.Printf("ListSecurityPolicies failed: %v", err)
		writeErrorWithStatus(w, http.StatusInternalServerError, "policy_list_unavailable", "security policies are temporarily unavailable")
		return
	}
	proof, proofErr := h.runtimeProof(r.Context(), user.TenantID)
	if proofErr != nil {
		proof = unavailableSecurityPolicyRuntimeProof()
	} else if strings.TrimSpace(proof.RuntimeStatus) == "" {
		proof.RuntimeStatus = runtimeStatusUnavailable
	}
	runtimeVerified := proof.complete()
	response := securityPoliciesResponse{
		Data: make([]securityPolicyResponse, 0, len(policies)), Total: len(policies),
		RuntimeVerified: runtimeVerified, RuntimeStatus: proof.RuntimeStatus,
	}
	for _, policy := range policies {
		_, provenActive := proof.ActivePolicyIDs[policy.ID]
		provenActive = runtimeVerified && policy.Enabled && provenActive
		item := policyResponse(policy, provenActive)
		response.Data = append(response.Data, item)
		if policy.Enabled {
			response.EnabledCount++
		}
		if policy.DetectionConfigured {
			response.ConfiguredCount++
		}
		if item.DetectionReady {
			response.ReadyCount++
		}
		if provenActive {
			response.ActiveCount++
		}
		if policy.DetectionConfigured && !item.DetectionReady {
			response.PendingCount++
		}
		if !policy.DetectionConfigured {
			response.UnconfiguredCount++
		}
	}
	writeJSON(w, response)
}

func (h *securityPoliciesHandler) listCapabilities(w http.ResponseWriter, r *http.Request) {
	user := policyReader(w, r)
	if user == nil {
		return
	}
	capabilities, err := h.store.ListSecurityCapabilities(r.Context())
	if err != nil {
		log.Printf("ListSecurityCapabilities failed: %v", err)
		writeErrorWithStatus(w, http.StatusInternalServerError, "capability_list_unavailable", "detection capabilities are temporarily unavailable")
		return
	}
	policies, err := h.store.ListSecurityPolicies(r.Context(), user.TenantID)
	if err != nil {
		log.Printf("ListSecurityPolicies for capability usage failed: %v", err)
		writeErrorWithStatus(w, http.StatusInternalServerError, "capability_usage_unavailable", "detection capability usage is temporarily unavailable")
		return
	}
	usage := make(map[string]int)
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		seen := make(map[string]struct{}, len(policy.Capabilities))
		for _, capability := range policy.Capabilities {
			if _, duplicate := seen[capability.Category]; duplicate {
				continue
			}
			seen[capability.Category] = struct{}{}
			usage[capability.Category]++
		}
	}
	items := make([]securityCapabilityResponse, 0, len(capabilities))
	builtinTotal := 0
	extensionTotal := 0
	for _, capability := range capabilities {
		capability.BoundPolicyCount = usage[capability.Category]
		if capability.Kind == "static" {
			builtinTotal++
		} else {
			extensionTotal++
		}
		item := securityCapabilityWithDocs(capability)
		item.BoundPolicyCount = &capability.BoundPolicyCount
		items = append(items, item)
	}
	writeJSON(w, map[string]any{
		"data": items, "total": len(items),
		"builtin_total": builtinTotal, "extension_total": extensionTotal,
	})
}

func (h *securityPoliciesHandler) validAuthoringProof(tenantID, policyID string, authoring *repository.SecurityPolicyAuthoring, token string) bool {
	if authoring.IsAgentShield() {
		return token == ""
	}
	if authoring == nil {
		return token == ""
	}
	if h.deps == nil {
		return false
	}
	segments := make([]quickNumberSegment, 0, len(authoring.Segments))
	for _, segment := range authoring.Segments {
		segments = append(segments, quickNumberSegment{Kind: segment.Kind, Value: segment.Value, Length: segment.Length})
	}
	return verifyQuickAuthoring(h.deps.SecurityEngineInternalToken, token, tenantID, policyID, authoring.MatcherPattern, segments)
}

func (h *securityPoliciesHandler) create(w http.ResponseWriter, r *http.Request) {
	user := requirePolicyWriter(w, r)
	if user == nil {
		return
	}
	var request createSecurityPolicyRequest
	if err := decodeSecurityPolicyJSON(w, r, &request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body does not match the security policy contract")
		return
	}
	if request.Matcher != nil && len(request.CapabilityCategories) > 0 {
		writeErrorWithStatus(w, http.StatusBadRequest, "conflicting_detection_basis", "choose either built-in detectors or a custom matcher")
		return
	}
	matcher, err := h.matcherInput(r.Context(), request.Matcher, !request.Enabled)
	if err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	if !h.validAuthoringProof(user.TenantID, "", request.Authoring, request.AuthoringProof) {
		writeErrorWithStatus(w, 422, "invalid_authoring_proof", "generate number authoring before saving the policy")
		return
	}
	policy, err := h.store.CreateSecurityPolicy(r.Context(), user.TenantID, repository.CreateSecurityPolicyInput{
		Name: request.Name, Description: request.Description, Scene: request.Scene,
		Severity: request.Severity, Action: request.Action, Enabled: request.Enabled,
		Matcher: matcher, CapabilityCategories: request.CapabilityCategories,
		BindingMode:    request.BindingMode,
		SubjectBinding: request.SubjectBinding,
		Authoring:      request.Authoring,
		Redaction:      request.Redaction,
		SemanticAction: request.SemanticAction,
	})
	if err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	logAudit(r, h.deps, "security_policy.create", map[string]any{
		"scene": request.Scene, "severity": request.Severity, "action": request.Action,
		"enabled": request.Enabled, "has_matcher": matcher != nil,
		"capability_count": len(request.CapabilityCategories),
		"subject_bound":    request.SubjectBinding != nil,
		"semantic_action":  semanticActionOrDefault(request.SemanticAction),
	}, "security_policy", policy.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(policyResponse(*policy, false))
}

func (h *securityPoliciesHandler) update(w http.ResponseWriter, r *http.Request) {
	user := requirePolicyWriter(w, r)
	if user == nil {
		return
	}
	policyID := strings.TrimSpace(chi.URLParam(r, "id"))
	if policyID == "" {
		writeErrorWithStatus(w, http.StatusNotFound, "policy_not_found", "security policy was not found")
		return
	}
	var request updateSecurityPolicyRequest
	if err := decodeSecurityPolicyJSON(w, r, &request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body does not match the security policy contract")
		return
	}
	if request.Matcher != nil && request.CapabilityCategories != nil && len(*request.CapabilityCategories) > 0 {
		writeErrorWithStatus(w, http.StatusBadRequest, "conflicting_detection_basis", "choose either built-in detectors or a custom matcher")
		return
	}
	if (request.Authoring != nil || request.AuthoringProof != "") && ((!request.Authoring.IsAgentShield() && (request.Matcher == nil || request.ClearMatcher)) || !h.validAuthoringProof(user.TenantID, policyID, request.Authoring, request.AuthoringProof)) {
		writeErrorWithStatus(w, 422, "invalid_authoring_proof", "generate number authoring for this saved policy before changing its matcher")
		return
	}
	allowDraft := request.Enabled != nil && !*request.Enabled
	matcherRequest := request.Matcher
	var currentPolicy *repository.SecurityPolicy
	needsCurrent := request.Matcher != nil || request.Action != nil ||
		(request.Enabled != nil && *request.Enabled)
	if needsCurrent {
		current, err := h.store.GetSecurityPolicy(r.Context(), user.TenantID, policyID)
		if err != nil {
			writeSecurityPolicyError(w, err)
			return
		}
		if request.Enabled == nil {
			allowDraft = !current.Enabled
		}
		currentPolicy = current
		if request.Matcher != nil && current.Source == "system" {
			writeSecurityPolicyError(w, repository.ErrSystemPolicyFieldReadOnly)
			return
		}
		// Re-attest the exact stored regex before changing an enabled policy. This
		// also covers action-only updates to shipped system regexes; otherwise a
		// legacy unvalidated matcher could be escalated from audit to block.
		storedMatcher := current.InternalMatchConfigJSON
		if len(storedMatcher) == 0 && current.Source == "tenant" {
			storedMatcher = current.MatchConfigJSON
		}
		if matcherRequest == nil && current.RuleType == "regex" && len(storedMatcher) > 0 {
			matcherRequest = &securityPolicyMatcherRequest{Type: "regex", Config: storedMatcher}
		}
	}
	matcher, err := h.matcherInput(r.Context(), matcherRequest, allowDraft)
	if err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	runtimeValidated := false
	if currentPolicy != nil && currentPolicy.Source == "system" && matcher != nil {
		runtimeValidated = matcher.RuntimeValidated
		matcher = nil // system definitions remain read-only; only the hidden stamp changes
	}
	authoring := request.Authoring
	if request.Matcher == nil && !request.ClearMatcher && matcher != nil && currentPolicy != nil && currentPolicy.Source == "tenant" {
		authoring = currentPolicy.Authoring
	}
	update := repository.SecurityPolicyUpdate{
		Name: request.Name, Description: request.Description, Scene: request.Scene,
		Severity: request.Severity, Action: request.Action, Enabled: request.Enabled,
		Matcher: matcher, ClearMatcher: request.ClearMatcher,
		CapabilityCategories: request.CapabilityCategories, BindingMode: request.BindingMode,
		SubjectBinding: request.SubjectBinding, ClearSubjectBinding: request.ClearSubjectBinding,
		Authoring:        authoring,
		Redaction:        request.Redaction,
		SemanticAction:   request.SemanticAction,
		RuntimeValidated: runtimeValidated,
	}
	policy, err := h.store.UpdateSecurityPolicy(r.Context(), user.TenantID, policyID, update)
	if err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	fields := make([]string, 0, 9)
	for name, changed := range map[string]bool{
		"name": request.Name != nil, "description": request.Description != nil,
		"scene": request.Scene != nil, "severity": request.Severity != nil,
		"action": request.Action != nil, "enabled": request.Enabled != nil,
		"matcher":               request.Matcher != nil || request.ClearMatcher,
		"capabilities":          request.CapabilityCategories != nil,
		"binding_mode":          request.BindingMode != nil,
		"subject_binding":       request.SubjectBinding != nil,
		"clear_subject_binding": request.ClearSubjectBinding,
		"authoring":             request.Authoring != nil,
		"semantic_action":       request.SemanticAction != nil,
	} {
		if changed {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	detail := map[string]any{"fields": fields}
	if request.Severity != nil && policy.PreviousSeverity != "" {
		to := policy.UpdatedSeverity
		if to == "" {
			to = policy.Severity
		}
		if policy.PreviousSeverity != to {
			detail["severity"] = map[string]string{"from": policy.PreviousSeverity, "to": to}
		}
	}
	logAudit(r, h.deps, "security_policy.update", detail, "security_policy", policyID)
	writeJSON(w, policyResponse(*policy, false))
}

func (h *securityPoliciesHandler) batchUpdate(w http.ResponseWriter, r *http.Request) {
	user := requirePolicyWriter(w, r)
	if user == nil {
		return
	}
	var request batchSecurityPolicyRequest
	if err := decodeSecurityPolicyJSON(w, r, &request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body does not match the security policy batch contract")
		return
	}
	updates := make([]repository.SecurityPolicyBatchUpdate, 0, len(request.Updates))
	for _, item := range request.Updates {
		updates = append(updates, repository.SecurityPolicyBatchUpdate{
			ID:     item.ID,
			Update: repository.SecurityPolicyUpdate{Action: item.Action, Enabled: item.Enabled, Redaction: item.Redaction},
		})
	}
	if err := h.store.BatchUpdateSecurityPolicies(r.Context(), user.TenantID, updates); err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	logAudit(r, h.deps, "security_policy.batch_update", map[string]any{"count": len(updates)}, "security_policy", "batch")
	writeJSON(w, map[string]any{"updated": len(updates)})
}

func (h *securityPoliciesHandler) deleteOne(w http.ResponseWriter, r *http.Request) {
	user := requirePolicyWriter(w, r)
	if user == nil {
		return
	}
	policyID := strings.TrimSpace(chi.URLParam(r, "id"))
	if policyID == "" {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "policy id is required")
		return
	}
	existing, err := h.store.GetSecurityPolicy(r.Context(), user.TenantID, policyID)
	if err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	if err := h.store.DeleteSecurityPolicy(r.Context(), user.TenantID, policyID); err != nil {
		writeSecurityPolicyError(w, err)
		return
	}
	logAudit(r, h.deps, "security_policy.delete", map[string]any{"policy_id": policyID, "name": existing.Name}, "security_policy", policyID)
	w.WriteHeader(http.StatusNoContent)
}

func writeSecurityPolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrSecurityPolicyNotDeletable):
		writeErrorWithStatus(w, http.StatusConflict, "policy_not_deletable", "built-in policies cannot be deleted; disable the policy instead")
	case errors.Is(err, errRegexInvalidSyntax):
		writeErrorWithStatus(w, http.StatusUnprocessableEntity, "regex_invalid_syntax", "the regular expression is not valid in the runtime engine")
	case errors.Is(err, errRegexUnsafe):
		writeErrorWithStatus(w, http.StatusUnprocessableEntity, "regex_unsafe", "the regular expression does not satisfy the runtime safety policy")
	case errors.Is(err, errRegexValidatorUnavailable):
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "regex_validator_unavailable", "the runtime validator is unavailable; enabled regex policies cannot be saved")
	case errors.Is(err, repository.ErrSecurityPolicyNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "policy_not_found", "security policy was not found")
	case errors.Is(err, repository.ErrSystemPolicyFieldReadOnly):
		writeErrorWithStatus(w, http.StatusConflict, "system_policy_read_only", "built-in policy definition and detector bindings are read-only; only action, enabled state and severity can be configured")
	case errors.Is(err, repository.ErrPolicyDetectionRequired):
		writeErrorWithStatus(w, http.StatusUnprocessableEntity, "detection_basis_required", "an enabled policy must have a configured detection basis")
	case errors.Is(err, repository.ErrPolicyDetectionConflict):
		writeErrorWithStatus(w, http.StatusBadRequest, "conflicting_detection_basis", "choose either built-in detectors or a custom matcher")
	case errors.Is(err, repository.ErrPolicyRuntimeValidation):
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "runtime_validation_required", "the policy cannot be enabled until its matcher is validated by the runtime engine")
	case errors.Is(err, repository.ErrPolicyActionUnsupported):
		writeErrorWithStatus(w, http.StatusUnprocessableEntity, "action_not_supported", "the selected detection capability does not support this action")
	case errors.Is(err, repository.ErrInvalidSecurityPolicy):
		writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_policy", "the security policy configuration is invalid")
	case errors.Is(err, repository.ErrInvalidSubjectBinding):
		writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_subject_binding", "the security policy subject binding is invalid")
	case errors.Is(err, repository.ErrRuleSetNotFound):
		writeErrorWithStatus(w, http.StatusConflict, "policy_store_unavailable", "the tenant policy store is not initialized")
	default:
		log.Printf("security policy operation failed: %v", err)
		writeErrorWithStatus(w, http.StatusInternalServerError, "policy_operation_failed", "the security policy operation failed")
	}
}

func ListSecurityPolicies(deps *Dependencies) http.HandlerFunc {
	return securityPoliciesHandlerFromDependencies(deps).list
}

func ListSecurityPolicyCapabilities(deps *Dependencies) http.HandlerFunc {
	return securityPoliciesHandlerFromDependencies(deps).listCapabilities
}

func CreateSecurityPolicy(deps *Dependencies) http.HandlerFunc {
	return securityPoliciesHandlerFromDependencies(deps).create
}

func UpdateSecurityPolicy(deps *Dependencies) http.HandlerFunc {
	return securityPoliciesHandlerFromDependencies(deps).update
}

func DeleteSecurityPolicy(deps *Dependencies) http.HandlerFunc {
	return securityPoliciesHandlerFromDependencies(deps).deleteOne
}

func BatchUpdateSecurityPolicies(deps *Dependencies) http.HandlerFunc {
	return securityPoliciesHandlerFromDependencies(deps).batchUpdate
}

// semanticActionOrDefault 对外始终返回明确值：未配置即 audit（记录并告警）。
func semanticActionOrDefault(value string) string {
	if normalized, err := repository.NormalizeSecurityPolicySemanticAction(value); err == nil {
		return normalized
	}
	return repository.SemanticActionAudit
}
