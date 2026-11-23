package handler

import (
	"context"

	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

type proxySecurityPostureReader struct {
	reader InspectionRuntimeStatusReader
	proxy  *ProxyHandler
}

func WithProxySecurityPosture(reader InspectionRuntimeStatusReader, proxy *ProxyHandler) InspectionRuntimeStatusReader {
	return &proxySecurityPostureReader{reader: reader, proxy: proxy}
}

func (r *proxySecurityPostureReader) RuntimeStatus() inspectionscope.RuntimeStatus {
	if r == nil || r.reader == nil {
		return inspectionscope.RuntimeStatus{}
	}
	status := r.reader.RuntimeStatus()
	if r.proxy == nil || r.proxy.securityClient == nil {
		return status
	}
	ctx := context.Background()
	client := r.proxy.securityClient
	auditOnly := client.securityAuditOnly(ctx)
	policy := client.inspectionPolicy(ctx)
	// 2.9.22（D7）：部署变量只在没有显式执行模式时作初值，此时才算“部署记录模式”。
	deploymentAuditOnly := (EnvSecurityAuditOnlySettingReader{}).Enabled(ctx)
	if reader, ok := client.auditOnlySettings.(interface {
		deploymentInitialValueActive(context.Context) bool
	}); ok {
		deploymentAuditOnly = reader.deploymentInitialValueActive(ctx)
	}
	modeVerified := deploymentAuditOnly
	if reader, ok := client.auditOnlySettings.(interface{ runtimeValueVerified() bool }); ok {
		modeVerified = modeVerified || reader.runtimeValueVerified()
	}
	status.Posture = &inspectionscope.ProxySecurityPosture{
		SchemaVersion:        inspectionscope.SecurityPostureSchemaVersion,
		SecurityAuditOnly:    inspectionscope.PostureBool(auditOnly),
		DeploymentAuditOnly:  inspectionscope.PostureBool(deploymentAuditOnly),
		CapacityFailClosed:   inspectionscope.PostureBool(client.detectionPolicy().FailClosedOnCapacity),
		DetectionFailMode:    proxyPostureFailureMode(client.detectionPolicy().FailClosedOnDetectionFailure),
		WhitelistFailMode:    r.proxy.whitelistChecker.runtimeFailureMode(ctx),
		InspectionQueueWired: inspectionscope.PostureBool(client.inspectionQueue != nil),
		InspectUserInput:     inspectionscope.PostureBool(policy.InspectUserInput),
		InspectModelOutput:   inspectionscope.PostureBool(policy.InspectModelOutput),
		InspectToolResults:   inspectionscope.PostureBool(policy.InspectToolResults),
		ModeSourceVerified:   inspectionscope.PostureBool(modeVerified),
		TLSInspectionCapable: inspectionscope.PostureBool(r.proxy.caManager != nil && client.inspectionScope != nil),
	}
	return status
}

func proxyPostureFailureMode(closed bool) string {
	if closed {
		return "closed"
	}
	return "open"
}
