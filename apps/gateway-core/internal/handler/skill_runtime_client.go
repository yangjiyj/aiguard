package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"golang.org/x/sync/singleflight"
)

const (
	skillDefinitionPath = "/admin/v1/internal/security/skills/definitions"
	skillAdmissionPath  = "/admin/v1/internal/security/skills/admission"
	skillInvocationPath = "/admin/v1/internal/security/skills/invocations"
	skillResultPath     = "/admin/v1/internal/security/skills/results"
	maxSkillAPIBytes    = 64 << 10
)

var ErrSkillInvocationNotFound = errors.New("skill invocation not found")

type skillAdmissionResolution struct {
	AssetID   string `json:"asset_id,omitempty"`
	VersionID string `json:"version_id,omitempty"`
	Status    string `json:"status"`
	Decision  string `json:"decision,omitempty"`
	RiskLevel string `json:"risk_level,omitempty"`
}

type skillAdmissionCacheEntry struct {
	resolution skillAdmissionResolution
	expiresAt  time.Time
}

type skillAdmissionCache struct {
	mu      sync.RWMutex
	entries map[string]skillAdmissionCacheEntry
	ttl     time.Duration
	group   singleflight.Group
}

func newSkillAdmissionCache() *skillAdmissionCache {
	return &skillAdmissionCache{
		entries: make(map[string]skillAdmissionCacheEntry),
		ttl:     30 * time.Second,
	}
}

func (c *skillAdmissionCache) get(key string, now time.Time) (skillAdmissionResolution, bool) {
	if c == nil {
		return skillAdmissionResolution{}, false
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || !now.Before(entry.expiresAt) {
		if ok {
			c.mu.Lock()
			delete(c.entries, key)
			c.mu.Unlock()
		}
		return skillAdmissionResolution{}, false
	}
	return entry.resolution, true
}

func (c *skillAdmissionCache) set(key string, resolution skillAdmissionResolution, now time.Time) {
	if c == nil {
		return
	}
	// Approved is deliberately never cached: revocation/quarantine must be
	// observed on the very next invocation. Failures then degrade to unknown
	// and require confirmation instead of reusing stale approval.
	if resolution.Status == string(agentguard.SkillAdmissionApproved) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return
	}
	c.mu.Lock()
	if len(c.entries) >= 4096 {
		for candidate, entry := range c.entries {
			if !now.Before(entry.expiresAt) {
				delete(c.entries, candidate)
			}
		}
		if len(c.entries) >= 4096 {
			for candidate := range c.entries {
				delete(c.entries, candidate)
				break
			}
		}
	}
	ttl := c.ttl
	if resolution.Status == string(agentguard.SkillAdmissionUnknown) ||
		resolution.Status == string(agentguard.SkillAdmissionUnverified) {
		ttl = 5 * time.Second
	}
	c.entries[key] = skillAdmissionCacheEntry{resolution: resolution, expiresAt: now.Add(ttl)}
	c.mu.Unlock()
}

func skillAdmissionCacheKey(tenantID string, identity agentguard.SkillIdentity) string {
	return strings.Join([]string{
		strings.TrimSpace(tenantID), identity.CanonicalName,
		identity.Version, strings.ToLower(identity.BundleHash),
	}, "\x1f")
}

func (c *ToolRiskClient) ResolveSkillAdmission(ctx context.Context, tenantID string, identity agentguard.SkillIdentity) (skillAdmissionResolution, error) {
	if c == nil || c.skillAdmissionCache == nil {
		return skillAdmissionResolution{Status: string(agentguard.SkillAdmissionUnknown)}, fmt.Errorf("skill admission client is unavailable")
	}
	if !identity.Complete() {
		return skillAdmissionResolution{Status: string(agentguard.SkillAdmissionUnverified)}, nil
	}
	key := skillAdmissionCacheKey(tenantID, identity)
	if cached, ok := c.skillAdmissionCache.get(key, time.Now()); ok {
		return cached, nil
	}
	value, err, _ := c.skillAdmissionCache.group.Do(key, func() (any, error) {
		if cached, ok := c.skillAdmissionCache.get(key, time.Now()); ok {
			return cached, nil
		}
		query := url.Values{}
		query.Set("canonical_name", identity.CanonicalName)
		query.Set("version", identity.Version)
		query.Set("bundle_hash", identity.BundleHash)
		var response skillAdmissionResolution
		if err := c.doSkillJSON(ctx, http.MethodGet, skillAdmissionPath+"?"+query.Encode(), tenantID, nil, &response); err != nil {
			return skillAdmissionResolution{}, err
		}
		response.Status = normalizeSkillAdmissionStatus(response.Status)
		c.skillAdmissionCache.set(key, response, time.Now())
		return response, nil
	})
	if err != nil {
		return skillAdmissionResolution{Status: string(agentguard.SkillAdmissionUnknown)}, err
	}
	return value.(skillAdmissionResolution), nil
}

func normalizeSkillAdmissionStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(agentguard.SkillAdmissionApproved):
		return string(agentguard.SkillAdmissionApproved)
	case string(agentguard.SkillAdmissionQuarantined):
		return string(agentguard.SkillAdmissionQuarantined)
	case string(agentguard.SkillAdmissionRevoked):
		return string(agentguard.SkillAdmissionRevoked)
	case string(agentguard.SkillAdmissionUnverified):
		return string(agentguard.SkillAdmissionUnverified)
	default:
		return string(agentguard.SkillAdmissionUnknown)
	}
}

func agentguardSkillAdmission(value string) agentguard.SkillAdmissionStatus {
	return agentguard.SkillAdmissionStatus(normalizeSkillAdmissionStatus(value))
}

func (c *ToolRiskClient) ObserveSkillDefinition(ctx context.Context, envelope *modelrouter.RequestEnvelope, tool ToolDef) error {
	if c == nil || envelope == nil || agentguard.ClassifyToolType(tool.Function.Name) != agentguard.ToolTypeSkill {
		return nil
	}
	definitionHash := toolDefinitionHash(tool)
	body := map[string]any{
		"canonical_name":   agentguard.CanonicalSkillName(tool.Function.Name),
		"display_name":     strings.TrimSpace(tool.Function.Name),
		"declared_version": "definition-" + definitionHash[:12],
		"definition_hash":  definitionHash,
	}
	var response map[string]any
	return c.doSkillJSON(ctx, http.MethodPost, skillDefinitionPath, envelope.TenantID, body, &response)
}

func canonicalToolSchema(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return []byte("{}")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return []byte("{}")
	}
	return canonical
}

func digestSkillBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

type skillInvocationRecord struct {
	AssetID               string
	AssetVersionID        string
	CanonicalName         string
	DeclaredVersion       string
	SourceURI             string
	Status                string
	RawDecision           string
	EffectiveDecision     string
	ParametersDigest      string
	RedactedPreview       map[string]any
	AttributionMode       string
	AttributionConfidence float64
}

func (c *ToolRiskClient) RecordSkillInvocation(ctx context.Context, envelope *modelrouter.RequestEnvelope, toolCallID string, record skillInvocationRecord) (string, error) {
	if c == nil || envelope == nil {
		return "", fmt.Errorf("skill invocation client is unavailable")
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	attributionMode := strings.ToLower(strings.TrimSpace(record.AttributionMode))
	attributionConfidence := record.AttributionConfidence
	if strings.TrimSpace(envelope.SessionID) == "" {
		attributionMode = "none"
		attributionConfidence = 0
	}
	body := map[string]any{
		"asset_id":               record.AssetID,
		"version_id":             record.AssetVersionID,
		"request_id":             envelope.RequestID,
		"session_id":             envelope.SessionID,
		"tool_call_id":           toolCallID,
		"canonical_name":         record.CanonicalName,
		"declared_version":       record.DeclaredVersion,
		"source_uri":             record.SourceURI,
		"status":                 record.Status,
		"raw_decision":           record.RawDecision,
		"effective_decision":     record.EffectiveDecision,
		"parameters_digest":      record.ParametersDigest,
		"redacted_preview":       record.RedactedPreview,
		"attribution_mode":       attributionMode,
		"attribution_confidence": attributionConfidence,
	}
	// 请求归属：用于控制面给 skill_invocation_risk 告警做用户 / 项目归属。
	// 未知时省略，兼容尚未升级的控制面（严格解码，新字段只在有值时发送）。
	if userID := strings.TrimSpace(envelope.UserID); userID != "" {
		body["user_id"] = userID
	}
	if projectID := strings.TrimSpace(envelope.ProjectID); projectID != "" {
		body["project_id"] = projectID
	}
	if keyID := strings.TrimSpace(envelope.ClientID); keyID != "" {
		body["api_key_id"] = keyID
	}
	var response struct {
		InvocationID string `json:"invocation_id"`
		ID           string `json:"id"`
		Invocation   struct {
			ID string `json:"id"`
		} `json:"invocation"`
	}
	if err := c.doSkillJSON(ctx, http.MethodPost, skillInvocationPath, envelope.TenantID, body, &response); err != nil {
		return "", err
	}
	if response.InvocationID != "" {
		return response.InvocationID, nil
	}
	if response.ID != "" {
		return response.ID, nil
	}
	return response.Invocation.ID, nil
}

func (c *ToolRiskClient) LinkSkillResult(ctx context.Context, envelope *modelrouter.RequestEnvelope, toolCallID string, findings []map[string]any) error {
	if c == nil || envelope == nil || strings.TrimSpace(envelope.SessionID) == "" ||
		strings.TrimSpace(toolCallID) == "" {
		return nil
	}
	body := map[string]any{
		"session_id":    envelope.SessionID,
		"tool_call_id":  toolCallID,
		"result_status": "result_observed",
		"findings":      findings,
	}
	var response map[string]any
	err := c.doSkillJSON(ctx, http.MethodPost, skillResultPath, envelope.TenantID, body, &response)
	var statusErr *skillHTTPStatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
		return ErrSkillInvocationNotFound
	}
	return err
}

type skillHTTPStatusError struct {
	StatusCode int
}

func (e *skillHTTPStatusError) Error() string {
	return fmt.Sprintf("skill control-plane returned status %d", e.StatusCode)
}

func (c *ToolRiskClient) doSkillJSON(ctx context.Context, method, path, tenantID string, requestBody any, responseBody any) error {
	if c == nil || c.httpClient == nil || strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("skill control-plane client is unavailable")
	}
	var body io.Reader
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode skill request: %w", err)
		}
		if len(payload) > maxSkillAPIBytes {
			return fmt.Errorf("skill request exceeds limit")
		}
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(
		ctx, method, strings.TrimRight(c.controlPlaneURL, "/")+path, body,
	)
	if err != nil {
		return fmt.Errorf("create skill request: %w", err)
	}
	request.Header.Set("X-Tenant-ID", tenantID)
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.internalAPISecret != "" {
		request.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call skill control-plane: %w", err)
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxSkillAPIBytes+1))
	if readErr != nil {
		return fmt.Errorf("read skill response: %w", readErr)
	}
	if len(payload) > maxSkillAPIBytes {
		return fmt.Errorf("skill response exceeds limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &skillHTTPStatusError{StatusCode: response.StatusCode}
	}
	if responseBody == nil || len(bytes.TrimSpace(payload)) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, responseBody); err != nil {
		return fmt.Errorf("decode skill response: %w", err)
	}
	return nil
}
