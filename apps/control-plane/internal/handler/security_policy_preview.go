package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	securityrules "github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
)

const (
	maxSecurityPolicyPreviewRequestBytes  = 8 << 10
	maxSecurityPolicyPreviewResponseBytes = 2 << 20
	securityPolicyPreviewTimeout          = 3 * time.Second
)

type securityPolicyPreviewRequest struct {
	Stage         string `json:"stage"`
	ApplicationID string `json:"application_id"`
	KeyID         string `json:"key_id"`
	Protocol      string `json:"protocol"`
	EntryPoint    string `json:"entry_point"`
}

type securityPolicyPreviewEngineRequest struct {
	TenantID  string            `json:"tenant_id"`
	Stage     string            `json:"stage"`
	Principal principal.Context `json:"principal"`
}

type securityPolicyPreviewBindingDetail struct {
	Dimension        string   `json:"dimension"`
	ConfiguredValues []string `json:"configured_values"`
	Matched          bool     `json:"matched"`
	Reason           string   `json:"reason"`
	IncludeChildren  bool     `json:"include_children"`
}

type securityPolicyPreviewEngineItem struct {
	PolicyCode                string                               `json:"policy_code"`
	PolicyID                  string                               `json:"policy_id"`
	PolicyName                string                               `json:"policy_name"`
	PolicyVersion             string                               `json:"policy_version"`
	Enabled                   bool                                 `json:"enabled"`
	Matched                   bool                                 `json:"matched"`
	SubjectMatched            bool                                 `json:"subject_matched"`
	Stage                     string                               `json:"stage"`
	StageSupported            bool                                 `json:"stage_supported"`
	ConfiguredAction          string                               `json:"configured_action"`
	EffectiveAction           *string                              `json:"effective_action"`
	ConditionalAction         *string                              `json:"conditional_action"`
	RequiresFinding           bool                                 `json:"requires_finding"`
	ActionBasis               string                               `json:"action_basis"`
	CapabilityCategories      []string                             `json:"capability_categories"`
	StageCapabilityCategories []string                             `json:"stage_capability_categories"`
	MatcherRuleID             string                               `json:"matcher_rule_id"`
	BindingDetails            []securityPolicyPreviewBindingDetail `json:"binding_details"`
}

type securityPolicyPreviewEngineResponse struct {
	TenantID         string                            `json:"tenant_id"`
	Stage            string                            `json:"stage"`
	RulePackVersion  string                            `json:"rule_pack_version"`
	IdentityVersion  string                            `json:"identity_version"`
	ContentEvaluated bool                              `json:"content_evaluated"`
	Policies         []securityPolicyPreviewEngineItem `json:"policies"`
}

type securityPolicyPreviewEngine interface {
	PreviewPolicies(context.Context, securityPolicyPreviewEngineRequest) (*securityPolicyPreviewEngineResponse, error)
}

type securityPolicyPreviewDesiredProvider func(context.Context, string) (*securityrules.RulePack, rulePackConvergence, error)

type securityPolicyPreviewNodeSummary struct {
	Status              string `json:"status"`
	NodeCount           int    `json:"node_count"`
	FreshCount          int    `json:"fresh_count"`
	ConvergedCount      int    `json:"converged_count"`
	FreshConvergedCount int    `json:"fresh_converged_count"`
	StaleCount          int    `json:"stale_count"`
	AllConverged        bool   `json:"all_converged"`
}

type securityPolicyPreviewResponse struct {
	Stage                 string                            `json:"stage"`
	IdentityVersion       string                            `json:"identity_version"`
	DesiredVersion        string                            `json:"desired_version"`
	EngineRulePackVersion string                            `json:"engine_rule_pack_version"`
	ContentEvaluated      bool                              `json:"content_evaluated"`
	PublishedPolicyIDs    []string                          `json:"published_policy_ids"`
	Nodes                 securityPolicyPreviewNodeSummary  `json:"nodes"`
	Policies              []securityPolicyPreviewEngineItem `json:"policies"`
}

type securityPolicyPreviewHandler struct {
	deps            *Dependencies
	engine          securityPolicyPreviewEngine
	desiredProvider securityPolicyPreviewDesiredProvider
	timeout         time.Duration
}

func newSecurityPolicyPreviewHandler(deps *Dependencies, engine securityPolicyPreviewEngine, desiredProvider securityPolicyPreviewDesiredProvider) *securityPolicyPreviewHandler {
	return &securityPolicyPreviewHandler{
		deps: deps, engine: engine, desiredProvider: desiredProvider,
		timeout: securityPolicyPreviewTimeout,
	}
}

func securityPolicyPreviewHandlerFromDependencies(deps *Dependencies) *securityPolicyPreviewHandler {
	return newSecurityPolicyPreviewHandler(
		deps,
		newSecurityEngineClient(deps.SecurityEngineURL, deps.SecurityEngineInternalToken),
		func(ctx context.Context, tenantID string) (*securityrules.RulePack, rulePackConvergence, error) {
			pack, err := compileTenantRulePack(ctx, deps, tenantID)
			if err != nil {
				return nil, rulePackConvergence{}, err
			}
			return pack, evaluateRulePackConvergence(tenantID, pack.Version), nil
		},
	)
}

func decodeSecurityPolicyPreviewRequest(w http.ResponseWriter, r *http.Request, out *securityPolicyPreviewRequest) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecurityPolicyPreviewRequestBytes)
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

var previewProtocols = map[string]struct{}{
	"chat": {}, "messages": {}, "responses": {}, "embeddings": {},
	"images": {}, "mcp": {}, "openai": {}, "anthropic": {},
}

var previewEntryPoints = map[string]struct{}{
	"gateway_api": {}, "mcp_gateway": {}, "forward_proxy": {}, "reverse_proxy": {},
}

func normalizePreviewSelector(value string, allowed map[string]struct{}) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", true
	}
	_, ok := allowed[value]
	return value, ok
}

func previewProtocolMatchesEntry(protocol, entryPoint string) bool {
	if protocol == "" || entryPoint == "" {
		return true
	}
	switch entryPoint {
	case "gateway_api":
		return protocol == "chat" || protocol == "messages" ||
			protocol == "responses" || protocol == "embeddings" || protocol == "images"
	case "mcp_gateway":
		return protocol == "mcp"
	case "forward_proxy", "reverse_proxy":
		return protocol == "openai" || protocol == "anthropic"
	default:
		return false
	}
}

func previewKeyLookup(deps *Dependencies) ContentExceptionKeyLookup {
	if deps == nil {
		return nil
	}
	if deps.ContentExceptionKeyLookup != nil {
		return deps.ContentExceptionKeyLookup
	}
	if deps.KeyRepo != nil {
		return deps.KeyRepo
	}
	return nil
}

func (h *securityPolicyPreviewHandler) buildPrincipal(ctx context.Context, tenantID string, request securityPolicyPreviewRequest) (principal.Context, int, error) {
	stage := strings.ToLower(strings.TrimSpace(request.Stage))
	if stage != "input" && stage != "agent" && stage != "output" {
		return principal.Context{}, http.StatusUnprocessableEntity, errors.New("invalid stage")
	}
	protocol, ok := normalizePreviewSelector(request.Protocol, previewProtocols)
	if !ok {
		return principal.Context{}, http.StatusUnprocessableEntity, errors.New("invalid protocol")
	}
	entryPoint, ok := normalizePreviewSelector(request.EntryPoint, previewEntryPoints)
	if !ok {
		return principal.Context{}, http.StatusUnprocessableEntity, errors.New("invalid entry point")
	}
	if !previewProtocolMatchesEntry(protocol, entryPoint) {
		return principal.Context{}, http.StatusUnprocessableEntity, errors.New("invalid protocol and entry point")
	}

	applicationID := strings.TrimSpace(request.ApplicationID)
	keyID := strings.TrimSpace(request.KeyID)
	previewPrincipal := principal.Context{
		TenantID: tenantID, Protocol: protocol, EntryPoint: entryPoint,
		IdentitySource: principal.SourceUnknown, TrustLevel: principal.TrustUnknown,
	}
	if keyID != "" {
		lookup := previewKeyLookup(h.deps)
		if lookup == nil {
			return principal.Context{}, http.StatusServiceUnavailable, errors.New("key lookup unavailable")
		}
		key, err := lookup.GetByID(ctx, tenantID, keyID)
		if err != nil {
			return principal.Context{}, http.StatusServiceUnavailable, errors.New("key lookup unavailable")
		}
		if key == nil || key.ID != keyID || key.TenantID != tenantID || !key.IsValid() {
			return principal.Context{}, http.StatusUnprocessableEntity, errors.New("invalid key")
		}
		if applicationID != "" && applicationID != key.ProjectID {
			return principal.Context{}, http.StatusUnprocessableEntity, errors.New("key application mismatch")
		}
		applicationID = key.ProjectID
		previewPrincipal.KeyID = key.ID
		previewPrincipal.KeyOwnerUserID = key.UserID
		previewPrincipal.IdentitySource = principal.SourceAPIKey
		previewPrincipal.TrustLevel = principal.TrustKeyBound
	}
	if applicationID != "" {
		if h.deps == nil || h.deps.ProjectRepo == nil {
			return principal.Context{}, http.StatusServiceUnavailable, errors.New("application lookup unavailable")
		}
		project, err := h.deps.ProjectRepo.GetByID(ctx, tenantID, applicationID)
		if err != nil {
			return principal.Context{}, http.StatusServiceUnavailable, errors.New("application lookup unavailable")
		}
		if project == nil || project.ID != applicationID || project.TenantID != tenantID {
			return principal.Context{}, http.StatusUnprocessableEntity, errors.New("invalid application")
		}
		previewPrincipal.ProjectID = project.ID
		previewPrincipal.ApplicationID = project.ID
		previewPrincipal.ApplicationDepartmentID = project.TeamID
	}
	normalized, err := principal.Normalize(previewPrincipal)
	if err != nil {
		return principal.Context{}, http.StatusUnprocessableEntity, errors.New("invalid preview identity")
	}
	identityJSON, _ := json.Marshal(normalized)
	digest := sha256.Sum256(identityJSON)
	normalized.IdentityVersion = "preview-v1:" + hex.EncodeToString(digest[:8])
	normalized, err = principal.Normalize(normalized)
	if err != nil {
		return principal.Context{}, http.StatusUnprocessableEntity, errors.New("invalid preview identity")
	}
	return normalized, 0, nil
}

func (h *securityPolicyPreviewHandler) preview(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found")
		return
	}
	var request securityPolicyPreviewRequest
	if err := decodeSecurityPolicyPreviewRequest(w, r, &request); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "request_too_large", "policy preview request is too large")
			return
		}
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body does not match the policy preview contract")
		return
	}
	previewContext, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	previewPrincipal, status, err := h.buildPrincipal(previewContext, user.TenantID, request)
	if err != nil {
		if status == http.StatusServiceUnavailable {
			writeErrorWithStatus(w, status, "policy_preview_unavailable", "policy preview is temporarily unavailable")
		} else {
			writeErrorWithStatus(w, status, "invalid_preview_subject", "the selected preview subject is invalid")
		}
		return
	}
	if h.engine == nil || h.desiredProvider == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "policy_preview_unavailable", "policy preview is temporarily unavailable")
		return
	}
	pack, convergence, err := h.desiredProvider(previewContext, user.TenantID)
	if err != nil || pack == nil || pack.TenantID != user.TenantID {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "policy_preview_unavailable", "policy preview is temporarily unavailable")
		return
	}
	engineResponse, err := h.engine.PreviewPolicies(previewContext, securityPolicyPreviewEngineRequest{
		TenantID:  user.TenantID,
		Stage:     strings.ToLower(strings.TrimSpace(request.Stage)),
		Principal: previewPrincipal,
	})
	if err != nil || engineResponse == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "policy_preview_unavailable", "policy preview is temporarily unavailable")
		return
	}
	publishedSet := activeSecurityPolicyIDs(pack)
	publishedPolicyIDs := make([]string, 0, len(publishedSet))
	for policyID := range publishedSet {
		publishedPolicyIDs = append(publishedPolicyIDs, policyID)
	}
	sort.Strings(publishedPolicyIDs)
	runtimeStatus := ruleRuntimeStatusFromPack(pack, convergence)
	writeJSON(w, securityPolicyPreviewResponse{
		Stage:                 engineResponse.Stage,
		IdentityVersion:       engineResponse.IdentityVersion,
		DesiredVersion:        pack.Version,
		EngineRulePackVersion: engineResponse.RulePackVersion,
		ContentEvaluated:      engineResponse.ContentEvaluated,
		PublishedPolicyIDs:    publishedPolicyIDs,
		Nodes: securityPolicyPreviewNodeSummary{
			Status:              runtimeStatus.Status,
			NodeCount:           convergence.NodeCount,
			FreshCount:          convergence.FreshCount,
			ConvergedCount:      convergence.ConvergedCount,
			FreshConvergedCount: convergence.FreshConvergedCount,
			StaleCount:          convergence.StaleCount,
			AllConverged:        convergence.AllConverged,
		},
		Policies: engineResponse.Policies,
	})
}

func (c *securityEngineClient) PreviewPolicies(ctx context.Context, request securityPolicyPreviewEngineRequest) (*securityPolicyPreviewEngineResponse, error) {
	if c == nil || c.baseURL == "" || c.internalToken == "" || c.client == nil || ctx == nil {
		return nil, errors.New("security engine policy preview is unavailable")
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > maxSecurityPolicyPreviewRequestBytes {
		return nil, errors.New("security engine policy preview request is invalid")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/v1/internal/policies/preview/", bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("security engine policy preview request is invalid")
	}
	c.setRequestHeaders(httpRequest)
	response, err := c.client.Do(httpRequest)
	if err != nil {
		return nil, errors.New("security engine policy preview is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, errors.New("security engine policy preview is unavailable")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("security engine policy preview returned an invalid response")
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxSecurityPolicyPreviewResponseBytes+1))
	if err != nil || len(responseBody) > maxSecurityPolicyPreviewResponseBytes {
		return nil, errors.New("security engine policy preview returned an invalid response")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var parsed securityPolicyPreviewEngineResponse
	if err := decoder.Decode(&parsed); err != nil {
		return nil, errors.New("security engine policy preview returned an invalid response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("security engine policy preview returned an invalid response")
	}
	if parsed.TenantID != request.TenantID || parsed.Stage != request.Stage ||
		parsed.IdentityVersion != request.Principal.IdentityVersion || parsed.ContentEvaluated {
		return nil, errors.New("security engine policy preview returned an invalid response")
	}
	if parsed.Policies == nil {
		parsed.Policies = []securityPolicyPreviewEngineItem{}
	}
	return &parsed, nil
}

func PreviewSecurityPolicies(deps *Dependencies) http.HandlerFunc {
	return securityPolicyPreviewHandlerFromDependencies(deps).preview
}
