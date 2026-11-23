package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/endpointpolicy"
)

const endpointPolicyResponseLimit = 4 << 20

// fetchEndpointPolicy uses the same authenticated endpoint route as hookd's
// policy download. The bearer exists only in the request headers and is never
// logged or persisted here.
func (g *AgentEndpointGateway) fetchEndpointPolicy(ctx context.Context, token string) (endpointpolicy.Bundle, error) {
	if g.client == nil || strings.TrimSpace(g.controlURL) == "" || strings.TrimSpace(token) == "" {
		return endpointpolicy.Bundle{}, fmt.Errorf("policy source unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.controlURL+"/admin/v1/internal/agent/policy-bundle", nil)
	if err != nil {
		return endpointpolicy.Bundle{}, fmt.Errorf("policy request unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-JJDGuard-Internal-Token", g.secret)
	req.Header.Set("Accept", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return endpointpolicy.Bundle{}, fmt.Errorf("policy source unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return endpointpolicy.Bundle{}, fmt.Errorf("policy source status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, endpointPolicyResponseLimit+1))
	if err != nil || len(data) > endpointPolicyResponseLimit {
		return endpointpolicy.Bundle{}, fmt.Errorf("policy response invalid")
	}
	if err := rejectDuplicateEndpointJSONKeys(data); err != nil {
		return endpointpolicy.Bundle{}, fmt.Errorf("policy response invalid")
	}
	bundle, err := endpointpolicy.DecodeAndValidate(data)
	if err != nil {
		return endpointpolicy.Bundle{}, fmt.Errorf("policy response invalid")
	}
	return bundle, nil
}
