package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const mcpConfirmationExecutionResponseLimit = 64 << 10

type gatewayMCPConfirmationExecutor struct {
	baseURL string
	secret  string
	client  *http.Client
}

func NewGatewayMCPConfirmationExecutor(baseURL, secret string) MCPConfirmationExecutor {
	return &gatewayMCPConfirmationExecutor{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		secret:  secret,
		client:  &http.Client{Timeout: 20 * time.Second},
	}
}

func (e *gatewayMCPConfirmationExecutor) ExecuteMCPConfirmation(ctx context.Context, tenantID, confirmationID, attemptID string) error {
	if e == nil || e.baseURL == "" || e.secret == "" {
		return fmt.Errorf("mcp confirmation gateway executor is not configured")
	}
	if tenantID == "" || confirmationID == "" || attemptID == "" {
		return fmt.Errorf("mcp confirmation execution identity is incomplete")
	}
	body, err := json.Marshal(map[string]string{"attempt_id": attemptID})
	if err != nil {
		return err
	}
	endpoint := e.baseURL + "/admin/v1/internal/mcp/confirmations/" + url.PathEscape(confirmationID) + "/execute"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set(InternalAPISecretHeader, e.secret)
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("execute mcp confirmation: %w", err)
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, mcpConfirmationExecutionResponseLimit+1))
	if readErr != nil {
		return fmt.Errorf("read mcp confirmation execution response: %w", readErr)
	}
	if len(responseBody) > mcpConfirmationExecutionResponseLimit {
		return fmt.Errorf("mcp confirmation execution response too large")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted &&
		resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("mcp confirmation execution status %d", resp.StatusCode)
	}
	var result struct {
		ExecutionStatus string `json:"execution_status"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return fmt.Errorf("decode mcp confirmation execution response: %w", err)
	}
	switch result.ExecutionStatus {
	case "pending", "executing", "executed", "failed", "unknown":
		return nil
	default:
		return fmt.Errorf("gateway returned invalid mcp execution status %q", result.ExecutionStatus)
	}
}
