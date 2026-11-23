package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

var proxyScopeHTTPClient = &http.Client{
	Timeout:       2 * time.Second,
	Transport:     &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func probeProxyInspectionScope(ctx context.Context, client *http.Client, token string) (inspectionscope.RuntimeStatus, error) {
	var status inspectionscope.RuntimeStatus
	if token == "" {
		return status, fmt.Errorf("proxy_scope_auth_unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://proxy-server:3128/internal/v1/inspection-scope/status", nil)
	if err != nil {
		return status, err
	}
	req.Header.Set(InternalAPISecretHeader, token)
	response, err := client.Do(req)
	if err != nil {
		return status, fmt.Errorf("proxy_scope_unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(body) > 32768 {
		return inspectionscope.RuntimeStatus{}, fmt.Errorf("proxy_scope_invalid_response")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&status) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return inspectionscope.RuntimeStatus{}, fmt.Errorf("proxy_scope_invalid_response")
	}
	if response.StatusCode != http.StatusOK {
		return status, fmt.Errorf("proxy_scope_not_ready")
	}
	if status.Component != "proxy-server" || status.ConfigComponent != "gateway-core" {
		return inspectionscope.RuntimeStatus{}, fmt.Errorf("proxy_scope_wrong_component")
	}
	return status, nil
}

func includeProxyInspectionScope(ctx context.Context, deps *Dependencies, runtime *semanticRuntimeStatus, revision string) {
	// Full/offline deployments include the forward proxy. A model-only deployment
	// can explicitly disable this requirement; absence of a live receipt cannot.
	if strings.EqualFold(strings.TrimSpace(os.Getenv("JJD_PROXY_INSPECTION_REQUIRED")), "false") {
		return
	}
	token := ""
	if deps != nil {
		token = deps.SecurityEngineInternalToken
	}
	status, err := probeProxyInspectionScope(ctx, proxyScopeHTTPClient, token)
	applyProxyInspectionStatus(runtime, revision, status, err, time.Now().UTC())
}

func applyProxyInspectionStatus(runtime *semanticRuntimeStatus, revision string, report inspectionscope.RuntimeStatus, probeErr error, now time.Time) {
	runtime.ProxyRequired = true
	lastSuccess, dateErr := time.Parse(time.RFC3339Nano, report.LastSuccessAt)
	fresh := report.Fresh && dateErr == nil && now.Sub(lastSuccess) >= -15*time.Second && now.Sub(lastSuccess) <= semanticRuntimeReportTTL
	verified := probeErr == nil && report.Component == "proxy-server" && report.ConfigComponent == "gateway-core" && report.Status == "applied" && report.ConfigLoaded && fresh && report.ErrorCode == "" && report.AppliedRevision == revision
	component := semanticRuntimeComponentStatus{Component: "proxy-server", NodeID: report.NodeID, DesiredRevision: revision,
		AppliedRevision: report.AppliedRevision, HeldRevision: report.HeldRevision, ConfigLoaded: report.ConfigLoaded,
		Fresh: fresh, ReportedAt: lastSuccess, Status: semanticRuntimeStatusDegraded, Nodes: []semanticRuntimeNodeStatus{}}
	if verified {
		component.Status = semanticRuntimeStatusApplied
		component.ActiveNodes = 1
		component.AppliedNodes = 1
	} else {
		component.LastError = "proxy_scope_not_verified"
		if report.ErrorCode != "" && semanticErrorCodePattern.MatchString(report.ErrorCode) {
			component.LastError = report.ErrorCode
		}
		runtime.RuntimeVerified = false
		if runtime.Status == semanticRuntimeStatusApplied {
			runtime.Status = semanticRuntimeStatusPartial
		}
	}
	runtime.Components = append(runtime.Components, component)
}
