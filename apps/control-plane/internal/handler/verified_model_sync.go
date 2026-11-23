package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/google/uuid"
)

const (
	modelSyncRequestMaxBytes      = 256 << 10
	modelSyncMaxItems             = 50
	modelSyncFieldMaxRunes        = 255
	modelSyncVerifyWorkers        = 4
	modelSyncProofTTL             = 10 * time.Minute
	modelSyncGateMaxActive        = 1024
	modelSyncPreviewMaxCandidates = 2000
	// modelSyncMaxCatalogSelection caps one catalog selection. Every selected model
	// costs a real upstream protocol probe, so the cap keeps the worst case inside
	// modelSyncControlPlaneRequestTimeout.
	modelSyncMaxCatalogSelection = 200
)

// ModelSyncVerifyGate is process-local. Multi-replica deployments require a
// distributed lock to enforce the same tenant/provider exclusion globally.
// Entries are removed when a batch finishes, so the map cannot grow with history.
type modelSyncGateAcquireResult uint8

const (
	modelSyncGateAcquired modelSyncGateAcquireResult = iota
	modelSyncGateBusy
	modelSyncGateCapacity
)

type ModelSyncVerifyGate struct {
	mu     sync.Mutex
	active map[string]struct{}
}

func NewModelSyncVerifyGate() *ModelSyncVerifyGate {
	return &ModelSyncVerifyGate{active: make(map[string]struct{})}
}

func (g *ModelSyncVerifyGate) acquire(tenantID, providerID string) (func(), modelSyncGateAcquireResult) {
	key := tenantID + "\x00" + providerID
	g.mu.Lock()
	if g.active == nil {
		g.active = make(map[string]struct{})
	}
	if _, exists := g.active[key]; exists {
		g.mu.Unlock()
		return nil, modelSyncGateBusy
	}
	if len(g.active) >= modelSyncGateMaxActive {
		g.mu.Unlock()
		return nil, modelSyncGateCapacity
	}
	g.active[key] = struct{}{}
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		delete(g.active, key)
		g.mu.Unlock()
	}, modelSyncGateAcquired
}

type azureSyncProvider struct {
	provider   *repository.Provider
	credential *repository.ProviderCredential
	apiKey     string
}

func authorizeVerifiedModelSync(w http.ResponseWriter, r *http.Request, deps *Dependencies) (*repository.User, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "authentication required")
		return nil, false
	}
	if deps == nil || deps.PermissionChecker == nil {
		writeErrorWithStatus(w, http.StatusForbidden, "permission_check_failed", "permission check failed")
		return nil, false
	}
	allowed, err := deps.PermissionChecker.HasPermission(
		r.Context(),
		user.ID,
		user.TenantID,
		"tenant",
		user.TenantID,
		"models",
		"write",
	)
	if err != nil {
		writeErrorWithStatus(w, http.StatusForbidden, "permission_check_failed", "permission check failed")
		return nil, false
	}
	if !allowed {
		writeErrorWithStatus(w, http.StatusForbidden, "permission_denied", "permission denied")
		return nil, false
	}
	return user, true
}

func loadAzureSyncProviderBase(w http.ResponseWriter, r *http.Request, providerID string, deps *Dependencies) (*repository.User, *repository.Provider, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "authentication required")
		return nil, nil, false
	}
	if deps == nil || deps.ProviderRepo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "model verification is unavailable")
		return nil, nil, false
	}
	provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, providerID)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "provider_unavailable", "failed to load provider")
		return nil, nil, false
	}
	if provider == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "provider not found")
		return nil, nil, false
	}
	if provider.ProviderType != "azure" || provider.Status != "active" {
		writeErrorWithStatus(w, http.StatusConflict, "provider_not_eligible", "provider must be an active Azure provider")
		return nil, nil, false
	}
	return user, provider, true
}

func loadAzureSyncProbeProvider(w http.ResponseWriter, r *http.Request, providerID string, deps *Dependencies) (*repository.User, *azureSyncProvider, bool) {
	user, provider, ok := loadAzureSyncProviderBase(w, r, providerID, deps)
	if !ok {
		return nil, nil, false
	}
	credential, err := deps.ProviderRepo.GetCredential(r.Context(), provider.ID)
	if err != nil || credential == nil || credential.Status != "active" || credential.ProviderID != provider.ID {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "provider verification is unavailable")
		return nil, nil, false
	}
	apiKey, err := secrets.DecryptProviderSecret(credential.SecretCiphertext)
	if err != nil || strings.TrimSpace(apiKey) == "" {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "provider verification is unavailable")
		return nil, nil, false
	}
	return user, &azureSyncProvider{provider: provider, credential: credential, apiKey: apiKey}, true
}

func PreviewVerifiedModelSync(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, authorized := authorizeVerifiedModelSync(w, r, deps); !authorized {
			return
		}

		var req ModelSyncPreviewRequest
		if !decodeModelSyncJSON(w, r, &req) {
			return
		}
		if !validModelSyncProviderID(req.ProviderID) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "provider_id is required")
			return
		}
		req.ProviderID = strings.TrimSpace(req.ProviderID)
		_, loaded, ok := loadAzureSyncProbeProvider(w, r, req.ProviderID, deps)
		if !ok {
			return
		}
		response := ModelSyncPreviewResponse{ProviderID: loaded.provider.ID, Candidates: []ModelSyncCandidate{}}
		if deps.ModelRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load current models")
			return
		}
		models, err := deps.ModelRepo.List(r.Context(), loaded.provider.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load current models")
			return
		}
		existing, currentActive := indexExistingModels(models, loaded.provider.ID)
		response.CurrentActive = currentActive
		if deps.CatalogFactory == nil {
			response.CatalogUnavailable = true
			writeModelSyncJSON(w, response)
			return
		}
		client, err := deps.CatalogFactory.GetClient(loaded.provider.ProviderType)
		if err != nil || client == nil {
			response.CatalogUnavailable = true
			writeModelSyncJSON(w, response)
			return
		}
		proxyURL, err := loadConfiguredOutboundProxyURL(r.Context(), deps)
		if err != nil {
			response.CatalogUnavailable = true
			writeModelSyncJSON(w, response)
			return
		}
		modelsFromCatalog, err := client.FetchModels(catalog.WithOutboundProxy(r.Context(), proxyURL), loaded.provider.BaseURL, loaded.apiKey)
		if err != nil {
			response.CatalogUnavailable = true
			writeModelSyncJSON(w, response)
			return
		}
		response.Candidates, response.CatalogTruncated = buildModelSyncCandidates(modelsFromCatalog, existing)
		writeModelSyncJSON(w, response)
	}
}

// providerSupportsCatalogSync reports whether one provider can be synced from an
// upstream model catalog. Gemini and Bedrock credentials expose no model listing,
// and complete-chat relays are validated against a single model at onboarding.
func providerSupportsCatalogSync(provider *repository.Provider) bool {
	if provider == nil || provider.Status != "active" {
		return false
	}
	if provider.AuthMode == "authorization_raw" {
		return false
	}
	switch provider.ProviderType {
	case "gemini", "vertex", "bedrock":
		return false
	default:
		return true
	}
}

// ListModelSyncCandidates returns the upstream catalog merged with the models
// already stored for one provider, so an administrator can choose which entries to
// sync. It performs no writes: selection is applied later by SyncModels.
func ListModelSyncCandidates(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req ModelSyncCandidateRequest
		if !decodeModelSyncJSON(w, r, &req) {
			return
		}
		req.ProviderID = strings.TrimSpace(req.ProviderID)
		if !validModelSyncProviderID(req.ProviderID) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "provider_id is required")
			return
		}
		if deps == nil || deps.ProviderRepo == nil || deps.ModelRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "catalog_unavailable", "model catalog is unavailable")
			return
		}

		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, req.ProviderID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get provider")
			return
		}
		if provider == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "provider_not_found", "provider not found or not owned by your tenant")
			return
		}
		if !providerSupportsCatalogSync(provider) {
			writeErrorWithStatus(w, http.StatusConflict, "provider_not_eligible", "provider does not support model catalog sync")
			return
		}

		response := ModelSyncCandidateListResponse{
			ProviderID:   provider.ID,
			Candidates:   []ModelSyncCandidate{},
			MaxSelection: modelSyncMaxCatalogSelection,
		}
		models, err := deps.ModelRepo.List(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load current models")
			return
		}
		existing, currentActive := indexExistingModels(models, provider.ID)
		response.CurrentActive = currentActive

		credential, err := deps.ProviderRepo.GetCredential(r.Context(), provider.ID)
		if err != nil || credential == nil || credential.Status != "active" || credential.ProviderID != provider.ID {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "provider_not_configured", "provider credentials not configured")
			return
		}
		apiKey, err := secrets.DecryptProviderSecret(credential.SecretCiphertext)
		if err != nil || strings.TrimSpace(apiKey) == "" {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "provider_not_configured", "provider credentials not configured")
			return
		}

		if deps.CatalogFactory == nil {
			response.CatalogUnavailable = true
			writeModelSyncJSON(w, response)
			return
		}
		client, err := deps.CatalogFactory.GetClient(provider.ProviderType)
		if err != nil || client == nil {
			response.CatalogUnavailable = true
			writeModelSyncJSON(w, response)
			return
		}
		proxyURL, err := loadConfiguredOutboundProxyURL(r.Context(), deps)
		if err != nil {
			response.CatalogUnavailable = true
			writeModelSyncJSON(w, response)
			return
		}
		catalogModels, err := client.FetchModels(catalog.WithOutboundProxy(r.Context(), proxyURL), provider.BaseURL, apiKey)
		if err != nil {
			// A missing catalog is an operator-readable state, not a server fault:
			// the console tells the administrator to sync without a selection.
			response.CatalogUnavailable = true
			writeModelSyncJSON(w, response)
			return
		}
		response.Candidates, response.CatalogTruncated = buildModelSyncCandidates(catalogModels, existing)
		writeModelSyncJSON(w, response)
	}
}

// indexExistingModels maps the provider's stored models by upstream name and counts
// how many are currently managed (active).
func indexExistingModels(models []*repository.Model, providerID string) (map[string]*repository.Model, int) {
	existing := make(map[string]*repository.Model)
	active := 0
	for _, model := range models {
		if model == nil || model.ProviderID != providerID {
			continue
		}
		if model.Status == "active" {
			active++
		}
		if _, seen := existing[model.ModelName]; !seen {
			existing[model.ModelName] = model
		}
	}
	return existing, active
}

// buildModelSyncCandidates merges the upstream catalog with the models already stored
// for the provider. The Azure deployment preview and the generic catalog preview both
// use it so an administrator sees identical candidate facts on either path.
func buildModelSyncCandidates(catalogModels []types.ProviderCatalogModel, existing map[string]*repository.Model) ([]ModelSyncCandidate, bool) {
	byID := make(map[string]ModelSyncCandidate, len(catalogModels))
	for _, item := range catalogModels {
		if item.Object != "" && item.Object != "model" {
			continue
		}
		id, valid := canonicalModelSyncCatalogID(item.ID)
		if !valid {
			continue
		}
		if _, duplicate := byID[id]; duplicate {
			continue
		}
		candidate := ModelSyncCandidate{CatalogModelID: id, DisplayName: safeCatalogDisplayName(item.Name, id), DeploymentName: id}
		if current := existing[id]; current != nil {
			candidate.CurrentStatus = current.Status
			if validStoredModelSyncDeploymentName(current.UpstreamModelID) {
				candidate.DeploymentName = current.UpstreamModelID
			}
		}
		byID[id] = candidate
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	truncated := false
	if len(ids) > modelSyncPreviewMaxCandidates {
		ids = ids[:modelSyncPreviewMaxCandidates]
		truncated = true
	}
	candidates := make([]ModelSyncCandidate, 0, len(ids))
	for _, id := range ids {
		candidates = append(candidates, byID[id])
	}
	return candidates, truncated
}

// canonicalCatalogSelection normalises an administrator's catalog selection: trimmed,
// deduplicated and sorted. An empty selection means "sync the whole catalog".
func canonicalCatalogSelection(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(raw))
	selection := make([]string, 0, len(raw))
	for _, value := range raw {
		id, valid := canonicalModelSyncCatalogID(value)
		if !valid {
			return nil, errors.New("invalid catalog model id")
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		selection = append(selection, id)
	}
	if len(selection) > modelSyncMaxCatalogSelection {
		return nil, errors.New("catalog selection exceeds the per-request cap")
	}
	sort.Strings(selection)
	return selection, nil
}

func VerifyModelSyncCandidates(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, authorized := authorizeVerifiedModelSync(w, r, deps); !authorized {
			return
		}

		var req ModelSyncVerifyRequest
		if !decodeModelSyncJSON(w, r, &req) {
			return
		}
		providerID := strings.TrimSpace(req.ProviderID)
		items, err := canonicalVerifyItems(req.Items)
		if !validModelSyncProviderID(providerID) || err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid verification request")
			return
		}
		if deps == nil || strings.TrimSpace(deps.ModelSyncProofSecret) == "" || deps.ModelProber == nil || deps.ModelSyncVerifyGate == nil || deps.ModelRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "model verification is unavailable")
			return
		}
		user, loaded, ok := loadAzureSyncProbeProvider(w, r, providerID, deps)
		if !ok {
			return
		}
		release, gateResult := deps.ModelSyncVerifyGate.acquire(user.TenantID, loaded.provider.ID)
		switch gateResult {
		case modelSyncGateBusy:
			writeErrorWithStatus(w, http.StatusConflict, "verification_in_progress", "verification is already in progress")
			return
		case modelSyncGateCapacity:
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_capacity_exceeded", "verification capacity is exhausted")
			return
		case modelSyncGateAcquired:
		default:
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "model verification is unavailable")
			return
		}
		defer release()

		models, err := deps.ModelRepo.List(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "model verification is unavailable")
			return
		}
		providerConfigDigest := repository.VerifiedModelSyncProviderConfigDigest(loaded.provider.ProviderType, loaded.provider.BaseURL, loaded.provider.AuthMode)
		activeSetDigest := repository.VerifiedModelSyncActiveSetDigest(models, loaded.provider.ID)
		verificationBatchID := uuid.NewString()

		results := make([]ModelSyncVerificationResult, len(items))
		stopAfterChunk := false
		for start := 0; start < len(items); start += modelSyncVerifyWorkers {
			if stopAfterChunk || r.Context().Err() != nil {
				for i := start; i < len(items); i++ {
					results[i] = skippedVerificationResult(items[i])
				}
				break
			}
			end := start + modelSyncVerifyWorkers
			if end > len(items) {
				end = len(items)
			}
			var wg sync.WaitGroup
			for i := start; i < end; i++ {
				i := i
				wg.Add(1)
				go func() {
					defer wg.Done()
					item := items[i]
					protocols, protocolErr := verifiedModelProtocols(item.Protocols)
					result := ModelSyncVerificationResult{CatalogModelID: item.CatalogModelID, DeploymentName: item.DeploymentName, Protocols: protocols}
					probeOK := protocolErr == nil
					var probe catalog.ModelProbeResult
					for _, protocol := range protocols {
						if !probeOK {
							break
						}
						probeProtocol := protocol
						if probeProtocol == "responses_native" {
							probeProtocol = "responses"
						}
						probe = probeModelSafely(r.Context(), deps.ModelProber, catalog.ModelProbeRequest{BaseURL: loaded.provider.BaseURL, APIKey: loaded.apiKey, AuthMode: loaded.provider.AuthMode, DeploymentName: item.DeploymentName, Protocol: probeProtocol})
						probeOK = probe.OK
					}
					if probeOK {
						result.Status = "success"
						result.Message = "deployment verified"
					} else {
						result.Status = "failed"
						if protocolErr != nil {
							result.ErrorKind = "invalid_request"
						} else {
							result.ErrorKind = safeProbeErrorKind(probe.ErrorKind)
						}
						result.Message = safeProbeMessage(result.ErrorKind)
					}
					results[i] = result
				}()
			}
			wg.Wait()
			for i := start; i < end; i++ {
				if results[i].ErrorKind == catalog.ModelProbeErrorUnauthorized {
					stopAfterChunk = true
				}
			}
		}

		now := time.Now()
		expiresAt := now.Add(modelSyncProofTTL)
		for i := range results {
			if results[i].Status != "success" {
				continue
			}
			token, err := sealModelSyncClaim(deps.ModelSyncProofSecret, modelSyncClaim{
				Version:              2,
				TenantID:             user.TenantID,
				ProviderID:           loaded.provider.ID,
				CredentialID:         loaded.credential.ID,
				ProviderConfigDigest: providerConfigDigest,
				ActiveSetDigest:      activeSetDigest,
				VerificationBatchID:  verificationBatchID,
				CatalogID:            results[i].CatalogModelID,
				DeploymentName:       results[i].DeploymentName,
				EndpointType:         verifiedModelEndpointType(results[i].Protocols),
				Protocols:            results[i].Protocols,
				ExpiresAt:            expiresAt.Unix(),
			})
			if err != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "model verification is unavailable")
				return
			}
			results[i].ProofToken = token
			results[i].ExpiresAt = &expiresAt
		}
		writeModelSyncJSON(w, ModelSyncVerifyResponse{ProviderID: loaded.provider.ID, Results: results})
	}
}

func CommitVerifiedModelSync(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, authorized := authorizeVerifiedModelSync(w, r, deps); !authorized {
			return
		}

		var req ModelSyncCommitRequest
		if !decodeModelSyncJSON(w, r, &req) {
			return
		}
		providerID := strings.TrimSpace(req.ProviderID)
		if !validModelSyncProviderID(providerID) || len(req.ProofTokens) == 0 || len(req.ProofTokens) > modelSyncMaxItems {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid commit request")
			return
		}
		if deps == nil || strings.TrimSpace(deps.ModelSyncProofSecret) == "" {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "model verification is unavailable")
			return
		}
		for _, token := range req.ProofTokens {
			if token == "" || len(token) > modelSyncTokenMaxLength || strings.TrimSpace(token) != token {
				writeInvalidVerification(w)
				return
			}
		}
		user, provider, ok := loadAzureSyncProviderBase(w, r, providerID, deps)
		if !ok {
			return
		}
		now := time.Now()
		claims := make(map[string]modelSyncClaim, len(req.ProofTokens))
		expectedCredentialID := ""
		expectedProviderConfigDigest := ""
		// Proofs may come from several verify rounds (the console verifies large
		// selections in chunks). Commit is additive, so only the credential and
		// connection config the proofs were minted against must still match.
		for _, token := range req.ProofTokens {
			claim, err := openModelSyncClaim(deps.ModelSyncProofSecret, token, now)
			if err != nil || claim.TenantID != user.TenantID || claim.ProviderID != provider.ID || (claim.EndpointType != "chat" && claim.EndpointType != "responses") {
				writeInvalidVerification(w)
				return
			}
			if expectedCredentialID == "" {
				expectedCredentialID = claim.CredentialID
				expectedProviderConfigDigest = claim.ProviderConfigDigest
			} else {
				if claim.CredentialID != expectedCredentialID ||
					claim.ProviderConfigDigest != expectedProviderConfigDigest {
					writeErrorWithStatus(w, http.StatusConflict, "sync_conflict", "verified model set changed; verify again")
					return
				}
			}
			if current, exists := claims[claim.CatalogID]; exists {
				if current.DeploymentName != claim.DeploymentName || strings.Join(current.Protocols, "\x00") != strings.Join(claim.Protocols, "\x00") {
					writeInvalidVerification(w)
					return
				}
				continue
			}
			claims[claim.CatalogID] = claim
		}
		currentProviderConfigDigest := repository.VerifiedModelSyncProviderConfigDigest(provider.ProviderType, provider.BaseURL, provider.AuthMode)
		if currentProviderConfigDigest != expectedProviderConfigDigest {
			writeErrorWithStatus(w, http.StatusConflict, "sync_conflict", "verified model set changed; verify again")
			return
		}
		ids := make([]string, 0, len(claims))
		for id := range claims {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		desired := make([]repository.VerifiedProviderModel, 0, len(ids))
		for _, id := range ids {
			claim := claims[id]
			protocols, err := verifiedModelProtocols(claim.Protocols)
			if err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_verification", "verification protocol is invalid")
				return
			}
			capabilities := classifyModelModality(claim.CatalogID)
			capabilities["endpoint_type"] = verifiedModelEndpointType(protocols)
			protocolCapabilities := make(map[string]interface{}, len(protocols))
			for _, protocol := range protocols {
				protocolCapabilities[protocol] = true
			}
			protocolCapabilities["metadata"] = map[string]interface{}{
				"verified": true,
				"source":   "verified_sync",
				"version":  claim.VerificationBatchID,
			}
			capabilities["protocols"] = protocolCapabilities
			if modality, ok := capabilities["modality"].(map[string]interface{}); ok {
				modality["source"] = "verified_chat"
			}
			desired = append(desired, repository.VerifiedProviderModel{
				CatalogID:      claim.CatalogID,
				DeploymentName: claim.DeploymentName,
				ModelLabel:     claim.CatalogID,
				Capabilities:   capabilities,
				Protocols:      protocols,
				SourceVersion:  claim.VerificationBatchID,
				VerifiedAt:     time.Unix(claim.ExpiresAt, 0).Add(-modelSyncProofTTL),
				ExpiresAt:      time.Unix(claim.ExpiresAt, 0).Add(30 * 24 * time.Hour),
			})
		}
		if deps.ModelRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "verification_unavailable", "model verification is unavailable")
			return
		}
		result, err := deps.ModelRepo.MergeVerifiedProviderModels(r.Context(), user.TenantID, provider.ID, expectedCredentialID, expectedProviderConfigDigest, desired)
		if err != nil {
			if errors.Is(err, repository.ErrVerifiedModelSyncConflict) {
				writeErrorWithStatus(w, http.StatusConflict, "sync_conflict", "verified model set changed; verify again")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to commit verified models")
			return
		}
		detail := map[string]interface{}{"created": result.Created, "updated": result.Updated, "reactivated": result.Reactivated, "deactivated": result.Deactivated}
		logAudit(r, deps, "sync_verified_models", detail, "provider", provider.ID)
		writeModelSyncJSON(w, ModelSyncCommitResponse{ProviderID: provider.ID, Created: result.Created, Updated: result.Updated, Reactivated: result.Reactivated, Deactivated: result.Deactivated})
	}
}

func canonicalVerifyItems(items []ModelSyncVerifyItem) ([]ModelSyncVerifyItem, error) {
	if len(items) == 0 || len(items) > modelSyncMaxItems {
		return nil, errors.New("invalid item count")
	}
	canonical := make([]ModelSyncVerifyItem, 0, len(items))
	seen := make(map[string]ModelSyncVerifyItem, len(items))
	for _, item := range items {
		catalogID, validCatalogID := canonicalModelSyncCatalogID(item.CatalogModelID)
		if containsUnicodeControl(item.DeploymentName) {
			return nil, errors.New("invalid item")
		}
		item.CatalogModelID = catalogID
		item.DeploymentName = strings.TrimSpace(item.DeploymentName)
		if !validCatalogID || !validModelSyncField(item.DeploymentName) {
			return nil, errors.New("invalid item")
		}
		protocols, protocolErr := verifiedModelProtocols(item.Protocols)
		if protocolErr != nil {
			return nil, protocolErr
		}
		item.Protocols = protocols
		if existing, exists := seen[item.CatalogModelID]; exists {
			if existing.DeploymentName != item.DeploymentName || strings.Join(existing.Protocols, "\x00") != strings.Join(item.Protocols, "\x00") {
				return nil, errors.New("conflicting duplicate")
			}
			continue
		}
		seen[item.CatalogModelID] = item
		canonical = append(canonical, item)
	}
	return canonical, nil
}

func verifiedModelProtocols(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return []string{"chat_completions"}, nil
	}
	for _, value := range raw {
		if strings.EqualFold(strings.TrimSpace(value), "auto") && len(raw) != 1 {
			return nil, errors.New("auto verification protocol cannot be combined")
		}
	}
	seen := make(map[string]struct{}, len(raw))
	protocols := make([]string, 0, len(raw))
	for _, value := range raw {
		protocol := strings.ToLower(strings.TrimSpace(value))
		switch protocol {
		case "auto", "chat", "chat_completions":
			protocol = "chat_completions"
		case "responses", "responses_native":
			protocol = "responses_native"
		default:
			return nil, errors.New("unsupported verification protocol")
		}
		if _, exists := seen[protocol]; exists {
			continue
		}
		seen[protocol] = struct{}{}
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	return protocols, nil
}

func verifiedModelEndpointType(protocols []string) string {
	for _, protocol := range protocols {
		if protocol == "chat_completions" {
			return "chat"
		}
	}
	return "responses"
}

func canonicalModelSyncCatalogID(value string) (string, bool) {
	if containsUnicodeControl(value) || !utf8.ValidString(value) {
		return "", false
	}
	value = strings.TrimSpace(value)
	if !validModelSyncField(value) || containsUnicodeSpace(value) {
		return "", false
	}
	return value, true
}

func validStoredModelSyncDeploymentName(value string) bool {
	return validModelSyncField(value)
}

func safeCatalogDisplayName(value, fallback string) string {
	if containsUnicodeControl(value) || !utf8.ValidString(value) {
		return fallback
	}
	value = strings.TrimSpace(value)
	if value == "" || utf8.RuneCountInString(value) > modelSyncFieldMaxRunes {
		return fallback
	}
	return value
}

func validModelSyncProviderID(value string) bool {
	return validModelSyncField(strings.TrimSpace(value))
}

func validModelSyncField(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) || utf8.RuneCountInString(value) > modelSyncFieldMaxRunes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func containsUnicodeControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func containsUnicodeSpace(value string) bool {
	for _, r := range value {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func skippedVerificationResult(item ModelSyncVerifyItem) ModelSyncVerificationResult {
	return ModelSyncVerificationResult{CatalogModelID: item.CatalogModelID, DeploymentName: item.DeploymentName, Status: "skipped", ErrorKind: "skipped_after_unauthorized", Message: "skipped after authentication failure"}
}

func probeModelSafely(ctx context.Context, prober catalog.ModelProber, request catalog.ModelProbeRequest) (result catalog.ModelProbeResult) {
	defer func() {
		if recover() != nil {
			result = catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorUpstream}
		}
	}()
	return prober.Probe(ctx, request)
}

func safeProbeErrorKind(kind string) string {
	switch kind {
	case catalog.ModelProbeErrorUnauthorized,
		catalog.ModelProbeErrorNotDeployed,
		catalog.ModelProbeErrorRateLimited,
		catalog.ModelProbeErrorTimeout,
		catalog.ModelProbeErrorCancelled,
		catalog.ModelProbeErrorInvalidRequest,
		catalog.ModelProbeErrorUpstream:
		return kind
	default:
		return catalog.ModelProbeErrorUpstream
	}
}

func safeProbeMessage(kind string) string {
	switch kind {
	case catalog.ModelProbeErrorUnauthorized:
		return "upstream authentication failed"
	case catalog.ModelProbeErrorNotDeployed:
		return "deployment not found"
	case catalog.ModelProbeErrorRateLimited:
		return "upstream rate limited"
	case catalog.ModelProbeErrorTimeout:
		return "upstream probe timed out"
	case catalog.ModelProbeErrorCancelled:
		return "probe cancelled"
	case catalog.ModelProbeErrorInvalidRequest:
		return "probe configuration invalid"
	default:
		return "upstream probe failed"
	}
}

func decodeModelSyncJSON(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeErrorWithStatus(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, modelSyncRequestMaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		} else {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON request")
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON request")
		return false
	}
	return true
}

func writeInvalidVerification(w http.ResponseWriter) {
	writeErrorWithStatus(w, http.StatusBadRequest, "invalid_verification", "verification proof is invalid or expired")
}

func writeModelSyncJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
