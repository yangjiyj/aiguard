package handler

import (
	"net/http"
	"sort"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

type postureFailureMode struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
}

type postureControl struct {
	ID      string `json:"id"`
	Enabled *bool  `json:"enabled"`
	Wired   *bool  `json:"wired"`
}

type postureChannel struct {
	ID              string               `json:"id"`
	ConfiguredMode  string               `json:"configured_mode"`
	EffectiveMode   string               `json:"effective_mode"`
	RuntimeVerified bool                 `json:"runtime_verified"`
	ModeSources     []string             `json:"mode_sources"`
	FailModes       []postureFailureMode `json:"fail_modes"`
	Controls        []postureControl     `json:"controls"`
}

type postureMLLayer struct {
	ID                string `json:"id"`
	ConfiguredEnabled bool   `json:"configured_enabled"`
	RuntimeEnabled    *bool  `json:"runtime_enabled"`
	RuntimeVerified   bool   `json:"runtime_verified"`
}

type securityPosture struct {
	TenantID        string           `json:"tenant_id"`
	GeneratedAt     time.Time        `json:"generated_at"`
	RuntimeVerified bool             `json:"runtime_verified"`
	Channels        []postureChannel `json:"channels"`
	MLLayers        []postureMLLayer `json:"ml_layers"`
	Warnings        []string         `json:"warnings"`
}

func GetSecurityPosture(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		if !roles.CanManageSecurityPolicy(user.Role) || user.TenantID == "" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		configs, err := buildSemanticComponentConfigs(r.Context(), deps)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "security_posture_unavailable", "security configuration is unavailable")
			return
		}
		key, err := semanticGatewayRevisionKey(deps)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "security_posture_unavailable", "security runtime verification is unavailable")
			return
		}
		proxy, proxyErr := probeProxyInspectionScope(r.Context(), proxyScopeHTTPClient, deps.SecurityEngineInternalToken)
		now := time.Now().UTC()
		posture := buildSecurityPosture(user.TenantID, configs, key, activeSemanticRuntimeReports(now), proxy, proxyErr, now)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeAgentGuardJSON(w, posture)
	}
}

func postureMode(record bool) string {
	if record {
		return "record"
	}
	return "protect"
}

func postureFailure(closed bool) string {
	if closed {
		return "closed"
	}
	return "open"
}

func newPostureChannel(id, configured, mode string, failures []postureFailureMode, controls []postureControl) postureChannel {
	return postureChannel{ID: id, ConfiguredMode: configured, EffectiveMode: mode, RuntimeVerified: true, FailModes: failures, Controls: controls}
}

func postureSwitch(id string, enabled, wired *bool) postureControl {
	return postureControl{ID: id, Enabled: enabled, Wired: wired}
}

func gatewayPostureChannels(p *inspectionscope.GatewaySecurityPosture, configured string) []postureChannel {
	mode := postureMode(*p.SecurityAuditOnly)
	wired := inspectionscope.PostureBool(true)
	failures := []postureFailureMode{{"guardrail", postureFailure(*p.GuardrailFailClosed)}, {"capacity", postureFailure(*p.CapacityFailClosed)}}
	lock := postureSwitch("deployment_record_lock", p.DeploymentAuditOnly, wired)
	input := postureSwitch("input_inspection", p.InspectUserInput, wired)
	output := postureSwitch("output_inspection", p.InspectModelOutput, wired)
	file := postureSwitch("file_dlp", p.FileDLPEnabled, wired)
	agent := postureSwitch("agent_guard", wired, p.AgentGuardWired)
	forwardMode := mode
	if p.ForwardProxyMode == "tunnel_audit" {
		forwardMode = "record"
	}
	channels := []postureChannel{
		newPostureChannel("chat", configured, mode, failures, []postureControl{lock, agent, input, output, file,
			postureSwitch("tool_result_inspection", p.InspectToolResults, wired), postureSwitch("security_action_header", p.SecurityActionHeaderEnabled, wired)}),
		newPostureChannel("mcp", configured, mode, append([]postureFailureMode{{"policy", p.MCPPolicyFailMode}}, failures...), []postureControl{lock, agent,
			postureSwitch("gateway", p.MCPGatewayEnabled, wired), postureSwitch("tool_result_guard", p.MCPResultGuardEnabled, p.MCPResultCheckerWired),
			postureSwitch("cache_invalidator", wired, p.MCPCacheInvalidatorWired), postureSwitch("cache_invalidator_active", p.MCPCacheInvalidatorRunning, p.MCPCacheInvalidatorWired)}),
		newPostureChannel("skill", configured, mode, append([]postureFailureMode{{"admission", p.SkillAdmissionFailMode}}, failures...), []postureControl{lock, agent, postureSwitch("admission", wired, p.SkillAdmissionWired)}),
		newPostureChannel("forward_proxy", configured, forwardMode, []postureFailureMode{{"gateway_whitelist", p.WhitelistFailMode}}, []postureControl{
			postureSwitch("gateway_record_lock", p.DeploymentAuditOnly, wired), postureSwitch("gateway_whitelist", inspectionscope.PostureBool(p.ForwardProxyMode == "deny_unlisted"), wired),
			postureSwitch("gateway_blind_tunnel", wired, wired)}),
		newPostureChannel("reverse_proxy", configured, mode, failures, []postureControl{lock, input, output, file, postureSwitch("stream_guard", wired, p.ReverseStreamGuardWired)}),
	}
	for i := range channels {
		channels[i].ModeSources = []string{p.ExecutionModeSource}
	}
	return channels
}

func unknownGatewayPostureChannels(configured string) []postureChannel {
	// Only the shape comes from this template. Every runtime fact is cleared.
	b := inspectionscope.PostureBool(false)
	p := &inspectionscope.GatewaySecurityPosture{SecurityAuditOnly: b, DeploymentAuditOnly: b, GuardrailFailClosed: b, CapacityFailClosed: b,
		MCPPolicyFailMode: "open", SkillAdmissionFailMode: "open", ForwardProxyMode: "deny_unlisted", WhitelistFailMode: "closed",
		MCPGatewayEnabled: b, MCPResultGuardEnabled: b, MCPResultCheckerWired: b, MCPCacheInvalidatorWired: b, MCPCacheInvalidatorRunning: b,
		SecurityActionHeaderEnabled: b, FileDLPEnabled: b, InspectUserInput: b, InspectModelOutput: b, InspectToolResults: b,
		AgentGuardWired: b, SkillAdmissionWired: b, ReverseStreamGuardWired: b}
	channels := gatewayPostureChannels(p, configured)
	for i := range channels {
		channels[i].EffectiveMode, channels[i].RuntimeVerified = "unknown", false
		channels[i].ModeSources = []string{}
		for j := range channels[i].FailModes {
			channels[i].FailModes[j].Mode = "unknown"
		}
		for j := range channels[i].Controls {
			channels[i].Controls[j].Enabled, channels[i].Controls[j].Wired = nil, nil
		}
	}
	return channels
}

func postureReportFresh(reported, now time.Time) bool {
	age := now.Sub(reported)
	return !reported.IsZero() && age >= -15*time.Second && age <= semanticRuntimeReportTTL
}

func verifiedGatewayPostureReport(report semanticRuntimeReport, configs semanticComponentConfigs, key []byte, now time.Time) bool {
	if report.Component != semanticGatewayComponent || report.ConfigLoaded == nil || !*report.ConfigLoaded || report.ErrorCode != "" || !postureReportFresh(report.ReportedAt, now) || report.DesiredRevision != configs.GatewayRevision || report.Posture.Validate() != nil {
		return false
	}
	configuredRecord, _ := configs.Gateway["security_audit_only"].(bool)
	managed, _ := configs.Gateway["security_execution_mode_managed"].(bool)
	if managed && *report.Posture.SecurityAuditOnly != (configuredRecord || *report.Posture.DeploymentAuditOnly) {
		return false
	}
	if (report.Posture.ExecutionModeSource == "legacy" || report.Posture.ExecutionModeSource == "startup") && managed {
		return false
	}
	actual := make(map[string]any, len(configs.Gateway))
	for k, value := range configs.Gateway {
		actual[k] = value
	}
	actual["security_audit_only"] = *report.Posture.SecurityAuditOnly
	expected, err := semanticConfigRevision(semanticGatewayComponent, actual, key)
	if err != nil {
		return false
	}
	return report.AppliedRevision == expected
}

func agreePostureBool(first, other *bool) bool {
	return first != nil && other != nil && *first == *other
}

func mergeGatewayPostureChannels(snapshots [][]postureChannel) []postureChannel {
	merged := snapshots[0]
	for i := range merged {
		mode := merged[i].EffectiveMode
		for _, channels := range snapshots[1:] {
			other := channels[i]
			merged[i].ModeSources = append(merged[i].ModeSources, other.ModeSources...)
			if other.EffectiveMode != mode {
				merged[i].EffectiveMode, merged[i].RuntimeVerified = "mixed", false
			}
			for j := range merged[i].FailModes {
				if merged[i].FailModes[j].Mode != other.FailModes[j].Mode {
					merged[i].FailModes[j].Mode, merged[i].RuntimeVerified = "unknown", false
				}
			}
			for j := range merged[i].Controls {
				control := &merged[i].Controls[j]
				if !agreePostureBool(control.Enabled, other.Controls[j].Enabled) {
					control.Enabled, merged[i].RuntimeVerified = nil, false
				}
				if !agreePostureBool(control.Wired, other.Controls[j].Wired) {
					control.Wired, merged[i].RuntimeVerified = nil, false
				}
			}
		}
		merged[i].ModeSources = uniquePostureStrings(merged[i].ModeSources)
	}
	return merged
}

func verifiedProxyPostureReport(report inspectionscope.RuntimeStatus, desired string, probeErr error, now time.Time) bool {
	lastSuccess, err := time.Parse(time.RFC3339Nano, report.LastSuccessAt)
	return probeErr == nil && err == nil && report.Component == "proxy-server" && report.ConfigComponent == semanticGatewayComponent && report.Status == "applied" && report.ConfigLoaded && report.Fresh && report.ErrorCode == "" && report.AppliedRevision == desired && postureReportFresh(lastSuccess, now) && report.Posture.Validate() == nil && *report.Posture.ModeSourceVerified
}

func includeProxySecurityPosture(channel *postureChannel, report inspectionscope.RuntimeStatus, verified bool) {
	proxyFailures := []postureFailureMode{{"proxy_whitelist", "unknown"}, {"proxy_detection", "unknown"}, {"capacity", "unknown"}}
	proxyControls := []postureControl{{ID: "proxy_record_lock"}, {ID: "proxy_inspection_queue"}, {ID: "proxy_tls_inspection"}, {ID: "proxy_input_inspection"}, {ID: "proxy_output_inspection"}, {ID: "proxy_tool_result_inspection"}}
	if !verified {
		channel.EffectiveMode, channel.RuntimeVerified = "unknown", false
	} else {
		p := report.Posture
		source := "database"
		if *p.DeploymentAuditOnly {
			source = "deployment"
		}
		channel.ModeSources = uniquePostureStrings(append(channel.ModeSources, source))
		proxyMode := postureMode(*p.SecurityAuditOnly)
		if channel.EffectiveMode == "unknown" {
			channel.RuntimeVerified = false
		} else if channel.EffectiveMode != proxyMode {
			channel.EffectiveMode, channel.RuntimeVerified = "mixed", false
		}
		proxyFailures = []postureFailureMode{{"proxy_whitelist", p.WhitelistFailMode}, {"proxy_detection", p.DetectionFailMode}, {"capacity", postureFailure(*p.CapacityFailClosed)}}
		wired := inspectionscope.PostureBool(true)
		proxyControls = []postureControl{postureSwitch("proxy_record_lock", p.DeploymentAuditOnly, wired),
			postureSwitch("proxy_inspection_queue", wired, p.InspectionQueueWired), postureSwitch("proxy_tls_inspection", p.TLSInspectionCapable, p.TLSInspectionCapable),
			postureSwitch("proxy_input_inspection", p.InspectUserInput, wired), postureSwitch("proxy_output_inspection", p.InspectModelOutput, wired), postureSwitch("proxy_tool_result_inspection", p.InspectToolResults, wired)}
	}
	channel.FailModes = append(channel.FailModes, proxyFailures...)
	channel.Controls = append(channel.Controls, proxyControls...)
}

func verifiedEnginePostureReports(reports []semanticRuntimeReport, revision string, now time.Time) bool {
	if len(reports) == 0 {
		return false
	}
	for _, report := range reports {
		if report.Component != semanticEngineComponent || report.ConfigLoaded == nil || !*report.ConfigLoaded || report.AppliedRevision != revision || report.ErrorCode != "" || !postureReportFresh(report.ReportedAt, now) {
			return false
		}
	}
	return true
}

func buildSecurityPosture(tenantID string, configs semanticComponentConfigs, key []byte, reports map[string][]semanticRuntimeReport, proxy inspectionscope.RuntimeStatus, proxyErr error, now time.Time) securityPosture {
	configuredRecord, _ := configs.Gateway["security_audit_only"].(bool)
	configured := postureMode(configuredRecord)
	out := securityPosture{TenantID: tenantID, GeneratedAt: now, Channels: unknownGatewayPostureChannels(configured), MLLayers: []postureMLLayer{}, Warnings: []string{}}
	gatewayReports := reports[semanticGatewayComponent]
	allGatewayVerified := len(gatewayReports) > 0
	snapshots := make([][]postureChannel, 0, len(gatewayReports))
	for _, report := range gatewayReports {
		if !verifiedGatewayPostureReport(report, configs, key, now) {
			allGatewayVerified = false
			continue
		}
		snapshots = append(snapshots, gatewayPostureChannels(report.Posture, configured))
		if *report.Posture.MCPResultGuardEnabled && !*report.Posture.MCPResultCheckerWired {
			out.Warnings = append(out.Warnings, "mcp_tool_result_guard_unwired")
		}
		if !*report.Posture.MCPCacheInvalidatorRunning {
			out.Warnings = append(out.Warnings, "mcp_cache_invalidator_inactive")
		}
		if report.Posture.ExecutionModeSource == "startup" || report.Posture.ExecutionModeSource == "legacy" {
			out.Warnings = append(out.Warnings, "gateway_execution_mode_"+report.Posture.ExecutionModeSource)
		}
	}
	if allGatewayVerified {
		out.Channels = mergeGatewayPostureChannels(snapshots)
	} else {
		out.Warnings = append(out.Warnings, "gateway_runtime_unverified")
	}
	proxyVerified := verifiedProxyPostureReport(proxy, configs.GatewayRevision, proxyErr, now)
	if !proxyVerified {
		out.Warnings = append(out.Warnings, "proxy_runtime_unverified")
	}
	includeProxySecurityPosture(&out.Channels[3], proxy, proxyVerified)
	if allGatewayVerified {
		out.Warnings = append(out.Warnings, "gateway_forward_tunnel_uninspected")
	}
	engineVerified := verifiedEnginePostureReports(reports[semanticEngineComponent], configs.EngineRevision, now)
	if !engineVerified {
		out.Warnings = append(out.Warnings, "security_engine_runtime_unverified")
	}
	master, _ := configs.Engine["semantic_enabled"].(bool)
	for _, key := range []string{"semantic_enabled", "semantic_input_enabled", "semantic_agent_enabled", "semantic_output_enabled", "tier1_enabled", "fp_suppression_enabled", "source_aware_enabled", "confidence_gating_enabled", "coding_traffic_downgrade_enabled", "file_content_dlp_enabled"} {
		value, _ := configs.Engine[key].(bool)
		layer := postureMLLayer{ID: key, ConfiguredEnabled: value, RuntimeVerified: engineVerified}
		if engineVerified {
			active := value
			if key == "semantic_input_enabled" || key == "semantic_agent_enabled" || key == "semantic_output_enabled" {
				active = active && master
			}
			layer.RuntimeEnabled = inspectionscope.PostureBool(active)
		}
		out.MLLayers = append(out.MLLayers, layer)
	}
	out.RuntimeVerified = engineVerified
	for _, channel := range out.Channels {
		out.RuntimeVerified = out.RuntimeVerified && channel.RuntimeVerified
		if channel.EffectiveMode == "mixed" {
			out.Warnings = append(out.Warnings, channel.ID+"_runtime_mixed")
		}
	}
	out.Warnings = uniquePostureStrings(out.Warnings)
	return out
}

func uniquePostureStrings(values []string) []string {
	sort.Strings(values)
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}
