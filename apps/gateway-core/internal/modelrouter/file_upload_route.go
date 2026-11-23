package modelrouter

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNoFileUploadRoute means the authenticated tenant has no configured
	// OpenAI-compatible file-upload provider. Callers must not guess a default.
	ErrNoFileUploadRoute = errors.New("no eligible file upload route")
	// ErrAmbiguousFileUploadRoute means more than one provider explicitly
	// advertises files support. The tenant must select a single provider.
	ErrAmbiguousFileUploadRoute = errors.New("ambiguous file upload route")
)

// ResolveFileUploadRoute resolves the only provider eligible to receive a
// standard OpenAI-compatible /v1/files upload for this tenant. Unlike model
// requests, files does not contain a model selector, so ambiguity is an error
// instead of an invitation to pick a default provider.
func (m *ModelRouter) ResolveFileUploadRoute(ctx context.Context, tenantID string) (*ModelRecord, error) {
	if m == nil || m.db == nil || strings.TrimSpace(tenantID) == "" {
		return nil, ErrNoFileUploadRoute
	}

	const query = `
		SELECT DISTINCT ON (p.id)
			m.id, p.id, p.name, p.provider_type,
			COALESCE(p.base_url, ''), COALESCE(p.auth_mode, ''),
			COALESCE(m.capabilities_json, '{}'::jsonb), m.created_at
		FROM models m
		JOIN providers p ON p.id = m.provider_id
		WHERE p.tenant_id = $1
			AND p.status = 'active'
			AND m.status = 'active'
			AND m.capabilities_json->'protocols'->>'files' = 'true'
			AND EXISTS (
				SELECT 1
				FROM provider_credentials pc
				WHERE pc.provider_id = p.id
					AND pc.status = 'active'
					AND COALESCE(pc.secret_ciphertext, '') <> ''
			)
		ORDER BY p.id, m.created_at DESC, m.id`

	rows, err := m.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list file upload routes: %w", err)
	}
	defer rows.Close()

	proxyURL, err := m.loadConfiguredOutboundProxyURL(ctx)
	if err != nil {
		return nil, err
	}

	routes := make([]ModelRecord, 0)
	for rows.Next() {
		var route ModelRecord
		var capabilitiesJSON []byte
		if err := rows.Scan(
			&route.ID,
			&route.ProviderID,
			&route.ProviderName,
			&route.ProviderType,
			&route.ProviderBaseURL,
			&route.ProviderAuthMode,
			&capabilitiesJSON,
			&route.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan file upload route: %w", err)
		}
		route.UpstreamProxyURL = proxyURL
		route.ProtocolCapabilities = ParseProtocolCapabilities(capabilitiesJSON)
		route.ResponsesNative = route.ProtocolCapabilities.ResponsesNative
		routes = append(routes, route)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list file upload route rows: %w", err)
	}
	return selectUniqueFileUploadRoute(routes)
}

func selectUniqueFileUploadRoute(routes []ModelRecord) (*ModelRecord, error) {
	byProvider := make(map[string]ModelRecord)
	for _, route := range routes {
		if route.ProviderID == "" || !route.SupportsConfiguredEndpoint("files") {
			continue
		}
		if _, exists := byProvider[route.ProviderID]; !exists {
			byProvider[route.ProviderID] = route
		}
	}
	if len(byProvider) == 0 {
		return nil, ErrNoFileUploadRoute
	}
	if len(byProvider) > 1 {
		return nil, ErrAmbiguousFileUploadRoute
	}
	for _, route := range byProvider {
		routeCopy := route
		return &routeCopy, nil
	}
	return nil, ErrNoFileUploadRoute
}
