package handler

// 本文件由 scripts/gen_officer_route_registry.py 根据 cmd/server/main.go 与 permission.sodRouteTable 生成，请勿手改。
// 收录 SoD 对安全员/审计员放行的全部已注册路由，以及它们在 main.go 里的注册表达式。
//   - officer_routes_role_gate_test.go 用它们真实调用 handler，断言不是 handler 层的角色拒绝；
//   - TestOfficerRouteRegistryMatchesSoDTable 反向核对注册表与 SoD 表一致：路由新增、改类别而这里没重新生成，测试失败。
// 重新生成：python3 scripts/gen_officer_route_registry.py（在仓库根目录执行），然后 gofmt。

import (
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/diagnostics"
)

type officerRouteEntry struct {
	class string // SoD 类别的取值（如 "security_write"），与 permission.SoDClass 一致
	expr  string // 与 main.go 注册处完全一致的表达式
	build func() http.Handler
}

func officerRouteRegistry() map[string]officerRouteEntry {
	// 桩依赖：repo 全部为 nil，只用于走到 handler 的角色判定；之后访问 nil 仓库 panic 视为「已通过角色判定」。
	deps := &Dependencies{}
	agentAdminAPI := NewAgentAdminAPI(nil, deps)
	agentUnifiedAssetAPI := NewAgentUnifiedAssetAPI(nil, deps)
	agentDestinationApprovalAPI := NewAgentDestinationApprovalAPI(nil, deps)
	nativeEventAPI := NewNativeEventAPI(nil)
	agentAuthorizationAPI := NewAgentAuthorizationAPI(nil, deps)
	agentAuthorizationApprovalAPI := NewAgentAuthorizationApprovalAPI(nil, deps)
	agentDelegationAPI := NewAgentDelegationAPI(nil, nil)
	agentDelegationInvestigationAPI := NewAgentDelegationInvestigationAPI(nil)
	agentEndpointAPI := NewAgentEndpointAPI(nil)
	kubernetesSnapshotAPI := NewAgentKubernetesSnapshotAPI(nil)
	var mcpRedlineSettingsStore mcpRedlineSettingsStore
	// 诊断引擎为 nil：handler 先做角色判定，之后返回 503，不算角色拒绝。
	var diagEngine *diagnostics.Engine
	_, _, _, _, _, _, _, _, _, _, _ = deps, agentAdminAPI, agentUnifiedAssetAPI, agentDestinationApprovalAPI, nativeEventAPI, agentAuthorizationAPI, agentAuthorizationApprovalAPI, agentDelegationAPI, agentDelegationInvestigationAPI, agentEndpointAPI, kubernetesSnapshotAPI
	_ = mcpRedlineSettingsStore
	_ = diagEngine
	// 训练语料扫描：store 为 nil，handler 先做角色判定，之后返回 503，不算角色拒绝。
	corpusScanHTTP := NewCorpusScanHandler(deps, nil, nil)
	return map[string]officerRouteEntry{
		"DELETE /admin/v1/agent/approval-exceptions/{id}":               {class: "security_write", expr: "agentAuthorizationApprovalAPI.RevokeException", build: func() http.Handler { return asHandler(agentAuthorizationApprovalAPI.RevokeException) }},
		"DELETE /admin/v1/agentguard/exceptions/{id}":                   {class: "security_write", expr: "handler.DeleteAgentGuardException(deps)", build: func() http.Handler { return asHandler(DeleteAgentGuardException(deps)) }},
		"DELETE /admin/v1/content-security/exceptions/{id}":             {class: "security_write", expr: "handler.DeleteContentAuditException(deps)", build: func() http.Handler { return asHandler(DeleteContentAuditException(deps)) }},
		"DELETE /admin/v1/mcp-policies/{id}":                            {class: "security_write", expr: "handler.DeleteMCPPolicy(deps)", build: func() http.Handler { return asHandler(DeleteMCPPolicy(deps)) }},
		"DELETE /admin/v1/mcp-servers/{id}/allowlist-template":          {class: "security_write", expr: "handler.RemoveMCPAllowlistTemplate(deps)", build: func() http.Handler { return asHandler(RemoveMCPAllowlistTemplate(deps)) }},
		"DELETE /admin/v1/rules/{id}":                                   {class: "security_write", expr: "handler.DeleteRule(deps)", build: func() http.Handler { return asHandler(DeleteRule(deps)) }},
		"DELETE /admin/v1/security/corpus-scans/{id}":                   {class: "security_write", expr: "corpusScanHTTP.Delete", build: func() http.Handler { return asHandler(corpusScanHTTP.Delete) }},
		"DELETE /admin/v1/security/policies/{id}":                       {class: "security_write", expr: "handler.DeleteSecurityPolicy(deps)", build: func() http.Handler { return asHandler(DeleteSecurityPolicy(deps)) }},
		"DELETE /admin/v1/tools/config/{id}":                            {class: "security_write", expr: "handler.DeleteToolRiskConfig(deps)", build: func() http.Handler { return asHandler(DeleteToolRiskConfig(deps)) }},
		"GET /admin/v1/agent-operation-events":                          {class: "security_record_read", expr: "handler.ListAgentOperationEvents(deps)", build: func() http.Handler { return asHandler(ListAgentOperationEvents(deps)) }},
		"GET /admin/v1/agent-operation-events/{public_event_id}":        {class: "security_record_read", expr: "handler.GetAgentOperationEvent(deps)", build: func() http.Handler { return asHandler(GetAgentOperationEvent(deps)) }},
		"GET /admin/v1/agent-operation-protection":                      {class: "security_config_read", expr: "handler.GetAgentOperationProtection(deps)", build: func() http.Handler { return asHandler(GetAgentOperationProtection(deps)) }},
		"GET /admin/v1/agent-sessions":                                  {class: "security_record_read", expr: "handler.ListAgentSessions(deps)", build: func() http.Handler { return asHandler(ListAgentSessions(deps)) }},
		"GET /admin/v1/agent-sessions/by-type":                          {class: "security_record_read", expr: "handler.ListAgentSessionsByType(deps)", build: func() http.Handler { return asHandler(ListAgentSessionsByType(deps)) }},
		"GET /admin/v1/agent-sessions/distribution":                     {class: "security_record_read", expr: "handler.GetAgentTypeDistribution(deps)", build: func() http.Handler { return asHandler(GetAgentTypeDistribution(deps)) }},
		"GET /admin/v1/agent-sessions/stats":                            {class: "security_record_read", expr: "handler.GetAgentStats(deps)", build: func() http.Handler { return asHandler(GetAgentStats(deps)) }},
		"GET /admin/v1/agent-sessions/{session_id}":                     {class: "security_record_read", expr: "handler.GetAgentSession(deps)", build: func() http.Handler { return asHandler(GetAgentSession(deps)) }},
		"GET /admin/v1/agent/approval-exceptions":                       {class: "security_config_read", expr: "agentAuthorizationApprovalAPI.ListExceptions", build: func() http.Handler { return asHandler(agentAuthorizationApprovalAPI.ListExceptions) }},
		"GET /admin/v1/agent/approval-rules":                            {class: "security_config_read", expr: "agentDestinationApprovalAPI.List", build: func() http.Handler { return asHandler(agentDestinationApprovalAPI.List) }},
		"GET /admin/v1/agent/approvals":                                 {class: "security_record_read", expr: "agentAuthorizationApprovalAPI.ListApprovals", build: func() http.Handler { return asHandler(agentAuthorizationApprovalAPI.ListApprovals) }},
		"GET /admin/v1/agent/assets":                                    {class: "security_record_read", expr: "agentAdminAPI.ListAssets", build: func() http.Handler { return asHandler(agentAdminAPI.ListAssets) }},
		"GET /admin/v1/agent/delegations/{id}/calls":                    {class: "common", expr: "agentDelegationAPI.ListCalls", build: func() http.Handler { return asHandler(agentDelegationAPI.ListCalls) }},
		"GET /admin/v1/agent/endpoints":                                 {class: "security_record_read", expr: "agentAdminAPI.ListEndpoints", build: func() http.Handler { return asHandler(agentAdminAPI.ListEndpoints) }},
		"GET /admin/v1/agent/endpoints/{id}":                            {class: "security_record_read", expr: "agentAdminAPI.GetEndpoint", build: func() http.Handler { return asHandler(agentAdminAPI.GetEndpoint) }},
		"GET /admin/v1/agent/events":                                    {class: "security_record_read", expr: "agentAdminAPI.ListEvents", build: func() http.Handler { return asHandler(agentAdminAPI.ListEvents) }},
		"GET /admin/v1/agent/kubernetes/clusters":                       {class: "security_record_read", expr: "kubernetesSnapshotAPI.ListClusters", build: func() http.Handler { return asHandler(kubernetesSnapshotAPI.ListClusters) }},
		"GET /admin/v1/agent/kubernetes/clusters/{cluster_id}/coverage": {class: "security_record_read", expr: "kubernetesSnapshotAPI.Coverage", build: func() http.Handler { return asHandler(kubernetesSnapshotAPI.Coverage) }},
		"GET /admin/v1/agent/native-events":                             {class: "security_record_read", expr: "nativeEventAPI.List", build: func() http.Handler { return asHandler(nativeEventAPI.List) }},
		"GET /admin/v1/agent/overview":                                  {class: "security_record_read", expr: "agentAdminAPI.Overview", build: func() http.Handler { return asHandler(agentAdminAPI.Overview) }},
		"GET /admin/v1/agent/policy-bundles":                            {class: "security_config_read", expr: "agentAdminAPI.ListPolicyBundles", build: func() http.Handler { return asHandler(agentAdminAPI.ListPolicyBundles) }},
		"GET /admin/v1/agent/policy-bundles/current":                    {class: "security_config_read", expr: "agentAdminAPI.CurrentPolicyBundle", build: func() http.Handler { return asHandler(agentAdminAPI.CurrentPolicyBundle) }},
		"GET /admin/v1/agent/principals":                                {class: "directory_read", expr: "agentAuthorizationAPI.ListPrincipals", build: func() http.Handler { return asHandler(agentAuthorizationAPI.ListPrincipals) }},
		"GET /admin/v1/agent/principals/{id}/delegation-tree":           {class: "security_record_read", expr: "agentDelegationInvestigationAPI.Tree", build: func() http.Handler { return asHandler(agentDelegationInvestigationAPI.Tree) }},
		"GET /admin/v1/agent/sessions":                                  {class: "security_record_read", expr: "agentAdminAPI.ListSessions", build: func() http.Handler { return asHandler(agentAdminAPI.ListSessions) }},
		"GET /admin/v1/agent/sessions/{id}":                             {class: "security_record_read", expr: "agentAdminAPI.GetSession", build: func() http.Handler { return asHandler(agentAdminAPI.GetSession) }},
		"GET /admin/v1/agent/unified-assets":                            {class: "security_record_read", expr: "agentUnifiedAssetAPI.List", build: func() http.Handler { return asHandler(agentUnifiedAssetAPI.List) }},
		"GET /admin/v1/agent/unified-assets/native-reference-link":      {class: "security_record_read", expr: "agentUnifiedAssetAPI.FindNativeReferenceAsset", build: func() http.Handler { return asHandler(agentUnifiedAssetAPI.FindNativeReferenceAsset) }},
		"GET /admin/v1/agent/unified-assets/{id}/history":               {class: "security_record_read", expr: "agentUnifiedAssetAPI.ListHistory", build: func() http.Handler { return asHandler(agentUnifiedAssetAPI.ListHistory) }},
		"GET /admin/v1/agentguard/behavior/baseline":                    {class: "security_config_read", expr: "handler.GetAgentGuardBehaviorBaseline(deps)", build: func() http.Handler { return asHandler(GetAgentGuardBehaviorBaseline(deps)) }},
		"GET /admin/v1/agentguard/confirmations":                        {class: "security_record_read", expr: "handler.ListAgentGuardConfirmations(deps)", build: func() http.Handler { return asHandler(ListAgentGuardConfirmations(deps)) }},
		"GET /admin/v1/agentguard/exceptions":                           {class: "security_config_read", expr: "handler.ListAgentGuardExceptions(deps)", build: func() http.Handler { return asHandler(ListAgentGuardExceptions(deps)) }},
		"GET /admin/v1/agentguard/governance/stats":                     {class: "security_record_read", expr: "handler.GetAgentGuardFalsePositiveStats(deps)", build: func() http.Handler { return asHandler(GetAgentGuardFalsePositiveStats(deps)) }},
		"GET /admin/v1/agentguard/policies":                             {class: "security_config_read", expr: "handler.ListAgentGuardPolicies(deps)", build: func() http.Handler { return asHandler(ListAgentGuardPolicies(deps)) }},
		"GET /admin/v1/agentguard/policies/{id}/versions":               {class: "security_config_read", expr: "handler.ListAgentGuardPolicyVersions(deps)", build: func() http.Handler { return asHandler(ListAgentGuardPolicyVersions(deps)) }},
		"GET /admin/v1/agentguard/risk-overview":                        {class: "security_record_read", expr: "handler.GetAgentRiskOverview(deps)", build: func() http.Handler { return asHandler(GetAgentRiskOverview(deps)) }},
		"GET /admin/v1/agentguard/rollouts":                             {class: "security_config_read", expr: "handler.ListAgentGuardRollouts(deps)", build: func() http.Handler { return asHandler(ListAgentGuardRollouts(deps)) }},
		"GET /admin/v1/agentguard/templates":                            {class: "security_config_read", expr: "handler.ListAgentGuardTemplates(deps)", build: func() http.Handler { return asHandler(ListAgentGuardTemplates(deps)) }},
		"GET /admin/v1/alert-groups":                                    {class: "security_record_read", expr: "handler.ListAlertGroups(deps)", build: func() http.Handler { return asHandler(ListAlertGroups(deps)) }},
		"GET /admin/v1/alert-groups/{id}":                               {class: "security_record_read", expr: "handler.GetAlertGroup(deps)", build: func() http.Handler { return asHandler(GetAlertGroup(deps)) }},
		"GET /admin/v1/alert-groups/{id}/events":                        {class: "security_record_read", expr: "handler.ListAlertGroupEvents(deps)", build: func() http.Handler { return asHandler(ListAlertGroupEvents(deps)) }},
		"GET /admin/v1/alerts/inbox":                                    {class: "common", expr: "handler.ListAlertInboxW8(deps)", build: func() http.Handler { return asHandler(ListAlertInboxW8(deps)) }},
		"GET /admin/v1/alerts/inbox/export":                             {class: "audit_export", expr: "handler.ExportAlertInbox(deps)", build: func() http.Handler { return asHandler(ExportAlertInbox(deps)) }},
		"GET /admin/v1/alerts/inbox/folded":                             {class: "common", expr: "handler.ListAlertInboxFolded(deps)", build: func() http.Handler { return asHandler(ListAlertInboxFolded(deps)) }},
		"GET /admin/v1/alerts/inbox/folded/items":                       {class: "common", expr: "handler.ListAlertInboxFoldedItems(deps)", build: func() http.Handler { return asHandler(ListAlertInboxFoldedItems(deps)) }},
		"GET /admin/v1/audit-chain/export":                              {class: "audit_export", expr: "handler.ExportAuditChain(deps)", build: func() http.Handler { return asHandler(ExportAuditChain(deps)) }},
		"GET /admin/v1/audit-chain/integrity":                           {class: "audit", expr: "handler.GetAuditChainIntegrity(deps)", build: func() http.Handler { return asHandler(GetAuditChainIntegrity(deps)) }},
		"GET /admin/v1/audit-chain/stats":                               {class: "audit", expr: "handler.GetAuditChainStats(deps)", build: func() http.Handler { return asHandler(GetAuditChainStats(deps)) }},
		"GET /admin/v1/audit/access-retention": {class: "evidence", expr: "handler.ListForwardProxyAccess(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(ListForwardProxyAccess(deps))))
		}},
		"GET /admin/v1/audit/access-retention/export": {class: "audit_export", expr: "handler.ExportForwardProxyAccess(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(ExportForwardProxyAccess(deps))))
		}},
		"GET /admin/v1/audit/access-retention/runs": {class: "evidence", expr: "handler.ListEvidenceRuns(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(ListEvidenceRuns(deps))))
		}},
		"GET /admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original": {class: "evidence", expr: "handler.GetAccessRetentionArtifact(false, deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetAccessRetentionArtifact(false, deps))))
		}},
		"GET /admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/preview": {class: "evidence", expr: "handler.GetAccessRetentionArtifact(true, deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetAccessRetentionArtifact(true, deps))))
		}},
		"GET /admin/v1/audit/access-retention/{request_id}/blob": {class: "evidence", expr: "handler.GetAccessRetentionBlob(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetAccessRetentionBlob(deps))))
		}},
		"GET /admin/v1/audit/access-retention/{request_id}/content": {class: "evidence", expr: "handler.GetAccessRetentionContent(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetAccessRetentionContent(deps))))
		}},
		"GET /admin/v1/audit/access-retention/{request_id}/image-proxy": {class: "evidence", expr: "handler.GetAccessRetentionImageProxy(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetAccessRetentionImageProxy(deps))))
		}},
		"GET /admin/v1/audit/access-retention/{request_id}/timeline": {class: "evidence", expr: "handler.GetEvidenceTimeline(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetEvidenceTimeline(deps))))
		}},
		"GET /admin/v1/audit/agents/sessions":           {class: "security_record_read", expr: "handler.ListAgentSessionsByType(deps)", build: func() http.Handler { return asHandler(ListAgentSessionsByType(deps)) }},
		"GET /admin/v1/audit/agents/user/{user_id}":     {class: "security_record_read", expr: "handler.GetUserAgentDetail(deps)", build: func() http.Handler { return asHandler(GetUserAgentDetail(deps)) }},
		"GET /admin/v1/audit/content":                   {class: "security_record_read", expr: "handler.ListContentAudit(deps)", build: func() http.Handler { return asHandler(ListContentAudit(deps)) }},
		"GET /admin/v1/audit/content/security-overview": {class: "security_record_read", expr: "handler.GetContentSecurityOverview(deps)", build: func() http.Handler { return asHandler(GetContentSecurityOverview(deps)) }},
		"GET /admin/v1/audit/content/users":             {class: "security_record_read", expr: "handler.ListContentAuditUsers(deps)", build: func() http.Handler { return asHandler(ListContentAuditUsers(deps)) }},
		"GET /admin/v1/audit/content/{session_id}": {class: "evidence", expr: "handler.GetSessionContent(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetSessionContent(deps))))
		}},
		"GET /admin/v1/audit/content/{session_id}/events": {class: "evidence", expr: "handler.GetSessionSecurityEvents(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetSessionSecurityEvents(deps))))
		}},
		"GET /admin/v1/audit/content/{session_id}/export": {class: "audit_export", expr: "handler.ExportSessionContent(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(ExportSessionContent(deps))))
		}},
		"GET /admin/v1/audit/dispositions": {class: "evidence", expr: "handler.ListAuditDispositions(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(ListAuditDispositions(deps))))
		}},
		"GET /admin/v1/audit/events":                {class: "security_record_read", expr: "handler.ListSecurityEvents(deps)", build: func() http.Handler { return asHandler(ListSecurityEvents(deps)) }},
		"GET /admin/v1/audit/export":                {class: "audit_export", expr: "handler.ExportAuditLogs(deps)", build: func() http.Handler { return asHandler(ExportAuditLogs(deps)) }},
		"GET /admin/v1/audit/login-history":         {class: "login_history", expr: "handler.ListLoginHistoryAudit(deps)", build: func() http.Handler { return asHandler(ListLoginHistoryAudit(deps)) }},
		"GET /admin/v1/audit/raw-evidence":          {class: "raw_evidence", expr: "handler.ListRawEvidence(deps)", build: func() http.Handler { return asHandler(ListRawEvidence(deps)) }},
		"GET /admin/v1/audit/raw-evidence/settings": {class: "raw_evidence", expr: "handler.GetRawEvidenceSettings(deps)", build: func() http.Handler { return asHandler(GetRawEvidenceSettings(deps)) }},
		"GET /admin/v1/audit/requests": {class: "evidence", expr: "handler.ListAuditRequests(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(ListAuditRequests(deps))))
		}},
		"GET /admin/v1/audit/requests/{request_id}": {class: "evidence", expr: "handler.GetAuditRequestDetail(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetAuditRequestDetail(deps))))
		}},
		"GET /admin/v1/audit/tools/high-risk":                      {class: "security_record_read", expr: "handler.ListHighRiskToolCalls(deps)", build: func() http.Handler { return asHandler(ListHighRiskToolCalls(deps)) }},
		"GET /admin/v1/audit/tools/session/{session_id}":           {class: "security_record_read", expr: "handler.ListSessionToolCalls(deps)", build: func() http.Handler { return asHandler(ListSessionToolCalls(deps)) }},
		"GET /admin/v1/audit/tools/stats":                          {class: "security_record_read", expr: "handler.GetToolCallStats(deps)", build: func() http.Handler { return asHandler(GetToolCallStats(deps)) }},
		"GET /admin/v1/audit/tools/trend":                          {class: "security_record_read", expr: "handler.GetRiskTrend(deps)", build: func() http.Handler { return asHandler(GetRiskTrend(deps)) }},
		"GET /admin/v1/audit/tools/user/{user_id}":                 {class: "security_record_read", expr: "handler.GetUserToolCalls(deps)", build: func() http.Handler { return asHandler(GetUserToolCalls(deps)) }},
		"GET /admin/v1/content-security/exceptions":                {class: "security_config_read", expr: "handler.ListContentAuditExceptions(deps)", build: func() http.Handler { return asHandler(ListContentAuditExceptions(deps)) }},
		"GET /admin/v1/content-security/file-policy":               {class: "security_config_read", expr: "handler.GetContentFilePolicy(deps)", build: func() http.Handler { return asHandler(GetContentFilePolicy(deps)) }},
		"GET /admin/v1/content-security/industry":                  {class: "security_config_read", expr: "handler.GetContentSecurityIndustry(deps)", build: func() http.Handler { return asHandler(GetContentSecurityIndustry(deps)) }},
		"GET /admin/v1/content-security/rules":                     {class: "security_config_read", expr: "handler.ListContentSecurityRules(deps)", build: func() http.Handler { return asHandler(ListContentSecurityRules(deps)) }},
		"GET /admin/v1/diagnostics/badge":                          {class: "common", expr: "handler.GetDiagnosticsBadge(diagEngine)", build: func() http.Handler { return asHandler(GetDiagnosticsBadge(diagEngine)) }},
		"GET /admin/v1/diagnostics/sessions":                       {class: "common", expr: "handler.ListDiagnosticsSessions(diagEngine)", build: func() http.Handler { return asHandler(ListDiagnosticsSessions(diagEngine)) }},
		"GET /admin/v1/diagnostics/sessions/{id}":                  {class: "common", expr: "handler.GetDiagnosticsSession(diagEngine)", build: func() http.Handler { return asHandler(GetDiagnosticsSession(diagEngine)) }},
		"GET /admin/v1/diagnostics/settings":                       {class: "common", expr: "handler.GetDiagnosticsSettings(diagEngine)", build: func() http.Handler { return asHandler(GetDiagnosticsSettings(diagEngine)) }},
		"GET /admin/v1/integration/agent-credentials":              {class: "directory_read", expr: "handler.ListAgentCredentials(deps)", build: func() http.Handler { return asHandler(ListAgentCredentials(deps)) }},
		"GET /admin/v1/integration/agent-credentials/{id}":         {class: "directory_read", expr: "handler.GetAgentCredential(deps)", build: func() http.Handler { return asHandler(GetAgentCredential(deps)) }},
		"GET /admin/v1/integration/agent-policies":                 {class: "security_config_read", expr: "handler.ListAgentPolicies(deps)", build: func() http.Handler { return asHandler(ListAgentPolicies(deps)) }},
		"GET /admin/v1/integration/audit-events":                   {class: "security_record_read", expr: "handler.ListIntegrationAuditEvents(deps)", build: func() http.Handler { return asHandler(ListIntegrationAuditEvents(deps)) }},
		"GET /admin/v1/integration/capabilities":                   {class: "security_record_read", expr: "handler.IntegrationCapabilities(deps)", build: func() http.Handler { return asHandler(IntegrationCapabilities(deps)) }},
		"GET /admin/v1/integration/credential-hits":                {class: "security_record_read", expr: "handler.ListIntegrationCredentialHits(deps)", build: func() http.Handler { return asHandler(ListIntegrationCredentialHits(deps)) }},
		"GET /admin/v1/integration/dlp-status":                     {class: "security_config_read", expr: "handler.GetIntegrationDLPStatus(deps)", build: func() http.Handler { return asHandler(GetIntegrationDLPStatus(deps)) }},
		"GET /admin/v1/integration/enforcement-status":             {class: "security_record_read", expr: "handler.GetIntegrationEnforcementStatus(deps)", build: func() http.Handler { return asHandler(GetIntegrationEnforcementStatus(deps)) }},
		"GET /admin/v1/integration/projects":                       {class: "directory_read", expr: "handler.ListIntegrationProjects(deps)", build: func() http.Handler { return asHandler(ListIntegrationProjects(deps)) }},
		"GET /admin/v1/integration/retention-status":               {class: "security_record_read", expr: "handler.GetIntegrationRetentionStatus(deps)", build: func() http.Handler { return asHandler(GetIntegrationRetentionStatus(deps)) }},
		"GET /admin/v1/integration/upstreams":                      {class: "directory_read", expr: "handler.ListIntegrationUpstreams(deps)", build: func() http.Handler { return asHandler(ListIntegrationUpstreams(deps)) }},
		"GET /admin/v1/keys":                                       {class: "directory_read", expr: "handler.ListKeys(deps)", build: func() http.Handler { return asHandler(ListKeys(deps)) }},
		"GET /admin/v1/llm-provider-catalog":                       {class: "common", expr: "handler.ListLLMProviderCatalog()", build: func() http.Handler { return asHandler(ListLLMProviderCatalog()) }},
		"GET /admin/v1/mcp-audit/export":                           {class: "audit_export", expr: "handler.ExportMCPAuditLogs(deps)", build: func() http.Handler { return asHandler(ExportMCPAuditLogs(deps)) }},
		"GET /admin/v1/mcp-policies":                               {class: "security_config_read", expr: "handler.ListMCPPolicies(deps)", build: func() http.Handler { return asHandler(ListMCPPolicies(deps)) }},
		"GET /admin/v1/mcp-policies/shadow-check":                  {class: "security_config_read", expr: "handler.MCPPolicyShadowCheck(deps)", build: func() http.Handler { return asHandler(MCPPolicyShadowCheck(deps)) }},
		"GET /admin/v1/mcp-redline-settings":                       {class: "security_config_read", expr: "handler.GetMCPRedlineSettings(deps, mcpRedlineSettingsStore)", build: func() http.Handler { return asHandler(GetMCPRedlineSettings(deps, mcpRedlineSettingsStore)) }},
		"GET /admin/v1/mcp-servers":                                {class: "security_config_read", expr: "handler.ListMCPServers(deps)", build: func() http.Handler { return asHandler(ListMCPServers(deps)) }},
		"GET /admin/v1/mcp-servers/{id}/allowlist-template":        {class: "security_config_read", expr: "handler.GetMCPAllowlistTemplate(deps)", build: func() http.Handler { return asHandler(GetMCPAllowlistTemplate(deps)) }},
		"GET /admin/v1/mcp-servers/{id}/tools":                     {class: "security_config_read", expr: "handler.ListMCPServerTools(deps)", build: func() http.Handler { return asHandler(ListMCPServerTools(deps)) }},
		"GET /admin/v1/mcp-tools/shadow-check":                     {class: "security_config_read", expr: "handler.MCPToolShadowCheck(deps)", build: func() http.Handler { return asHandler(MCPToolShadowCheck(deps)) }},
		"GET /admin/v1/me":                                         {class: "common", expr: "handler.GetCurrentUser(deps)", build: func() http.Handler { return asHandler(GetCurrentUser(deps)) }},
		"GET /admin/v1/me/permissions":                             {class: "common", expr: "handler.GetMyPermissions(deps)", build: func() http.Handler { return asHandler(GetMyPermissions(deps)) }},
		"GET /admin/v1/me/totp":                                    {class: "common", expr: "handler.GetMyTOTPStatus(deps)", build: func() http.Handler { return asHandler(GetMyTOTPStatus(deps)) }},
		"GET /admin/v1/models":                                     {class: "directory_read", expr: "handler.ListModels(deps)", build: func() http.Handler { return asHandler(ListModels(deps)) }},
		"GET /admin/v1/models/sync/state":                          {class: "directory_read", expr: "handler.CatalogSyncSettings(deps)", build: func() http.Handler { return asHandler(CatalogSyncSettings(deps)) }},
		"GET /admin/v1/permissions/actions":                        {class: "common", expr: "handler.ListPermissionActions(deps)", build: func() http.Handler { return asHandler(ListPermissionActions(deps)) }},
		"GET /admin/v1/permissions/resources":                      {class: "common", expr: "handler.ListPermissionResources(deps)", build: func() http.Handler { return asHandler(ListPermissionResources(deps)) }},
		"GET /admin/v1/policy-center/agent-behaviors":              {class: "security_config_read", expr: "handler.GetPolicyCenterAgentBehaviors(deps)", build: func() http.Handler { return asHandler(GetPolicyCenterAgentBehaviors(deps)) }},
		"GET /admin/v1/policy-suggestions":                         {class: "security_config_read", expr: "handler.ListPolicySuggestions(deps)", build: func() http.Handler { return asHandler(ListPolicySuggestions(deps)) }},
		"GET /admin/v1/portal-integration/employee-key":            {class: "common", expr: "handler.EmployeeKeyEndpoint(deps, \"metadata\")", build: func() http.Handler { return asHandler(EmployeeKeyEndpoint(deps, "metadata")) }},
		"GET /admin/v1/portal-integration/employee-key/credential": {class: "common", expr: "handler.EmployeeKeyEndpoint(deps, \"credential\")", build: func() http.Handler { return asHandler(EmployeeKeyEndpoint(deps, "credential")) }},
		"GET /admin/v1/projects":                                   {class: "directory_read", expr: "handler.ListProjects(deps)", build: func() http.Handler { return asHandler(ListProjects(deps)) }},
		"GET /admin/v1/protection-settings":                        {class: "security_config_read", expr: "handler.GetProtectionSettings(deps)", build: func() http.Handler { return asHandler(GetProtectionSettings(deps)) }},
		"GET /admin/v1/proxy/forward-access": {class: "evidence", expr: "handler.ListForwardProxyAccess(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(ListForwardProxyAccess(deps))))
		}},
		"GET /admin/v1/roles":                                          {class: "common", expr: "handler.ListRoles(deps)", build: func() http.Handler { return asHandler(ListRoles(deps)) }},
		"GET /admin/v1/roles/{name}/permissions":                       {class: "common", expr: "handler.GetRolePermissions(deps)", build: func() http.Handler { return asHandler(GetRolePermissions(deps)) }},
		"GET /admin/v1/rule-sets":                                      {class: "security_config_read", expr: "handler.ListRuleSets(deps)", build: func() http.Handler { return asHandler(ListRuleSets(deps)) }},
		"GET /admin/v1/rules":                                          {class: "security_config_read", expr: "handler.ListRules(deps)", build: func() http.Handler { return asHandler(ListRules(deps)) }},
		"GET /admin/v1/rules/pull-status":                              {class: "security_config_read", expr: "handler.GetRulePackPullStatus(deps)", build: func() http.Handler { return asHandler(GetRulePackPullStatus(deps)) }},
		"GET /admin/v1/security/alert-occurrences":                     {class: "security_record_read", expr: "handler.ListAlertOccurrences(deps)", build: func() http.Handler { return asHandler(ListAlertOccurrences(deps)) }},
		"GET /admin/v1/security/alert-occurrences/operational":         {class: "security_record_read", expr: "handler.ListAlertOperationalEvents(deps)", build: func() http.Handler { return asHandler(ListAlertOperationalEvents(deps)) }},
		"GET /admin/v1/security/alert-occurrences/operational/summary": {class: "security_record_read", expr: "handler.SummarizeAlertOperationalEvents(deps)", build: func() http.Handler { return asHandler(SummarizeAlertOperationalEvents(deps)) }},
		"GET /admin/v1/security/alert-occurrences/summary":             {class: "security_record_read", expr: "handler.SummarizeAlertCases(deps)", build: func() http.Handler { return asHandler(SummarizeAlertCases(deps)) }},
		"GET /admin/v1/security/block-records":                         {class: "security_record_read", expr: "handler.ListSecurityBlockRecords(deps)", build: func() http.Handler { return asHandler(ListSecurityBlockRecords(deps)) }},
		"GET /admin/v1/security/block-records/export":                  {class: "audit_export", expr: "handler.ExportSecurityBlockRecords(deps)", build: func() http.Handler { return asHandler(ExportSecurityBlockRecords(deps)) }},
		"GET /admin/v1/security/block-records/{block_id}":              {class: "security_record_read", expr: "handler.GetSecurityBlockRecord(deps)", build: func() http.Handler { return asHandler(GetSecurityBlockRecord(deps)) }},
		"GET /admin/v1/security/block-records/{block_id}/trace":        {class: "security_record_read", expr: "handler.GetSecurityBlockTrace(deps)", build: func() http.Handler { return asHandler(GetSecurityBlockTrace(deps)) }},
		"GET /admin/v1/security/corpus-scans":                          {class: "security_record_read", expr: "corpusScanHTTP.List", build: func() http.Handler { return asHandler(corpusScanHTTP.List) }},
		"GET /admin/v1/security/corpus-scans/{id}":                     {class: "security_record_read", expr: "corpusScanHTTP.Get", build: func() http.Handler { return asHandler(corpusScanHTTP.Get) }},
		"GET /admin/v1/security/corpus-scans/{id}/masked":              {class: "security_write", expr: "corpusScanHTTP.DownloadMasked", build: func() http.Handler { return asHandler(corpusScanHTTP.DownloadMasked) }},
		"GET /admin/v1/security/corpus-scans/{id}/report":              {class: "security_record_read", expr: "corpusScanHTTP.DownloadReport", build: func() http.Handler { return asHandler(corpusScanHTTP.DownloadReport) }},
		"GET /admin/v1/security/policies":                              {class: "security_config_read", expr: "handler.ListSecurityPolicies(deps)", build: func() http.Handler { return asHandler(ListSecurityPolicies(deps)) }},
		"GET /admin/v1/security/policies/capabilities":                 {class: "security_config_read", expr: "handler.ListSecurityPolicyCapabilities(deps)", build: func() http.Handler { return asHandler(ListSecurityPolicyCapabilities(deps)) }},
		"GET /admin/v1/security/policy-assets":                         {class: "security_config_read", expr: "handler.ListPolicyAssets(deps)", build: func() http.Handler { return asHandler(ListPolicyAssets(deps)) }},
		"GET /admin/v1/security/posture":                               {class: "security_config_read", expr: "handler.GetSecurityPosture(deps)", build: func() http.Handler { return asHandler(GetSecurityPosture(deps)) }},
		"GET /admin/v1/security/reply-policy":                          {class: "security_config_read", expr: "handler.GetSecurityReplyPolicy(deps)", build: func() http.Handler { return asHandler(GetSecurityReplyPolicy(deps)) }},
		"GET /admin/v1/security/semantic/runtime-status":               {class: "security_config_read", expr: "handler.GetSemanticRuntimeStatus(deps)", build: func() http.Handler { return asHandler(GetSemanticRuntimeStatus(deps)) }},
		"GET /admin/v1/security/semantic/settings":                     {class: "security_config_read", expr: "handler.GetSemanticSettings(deps)", build: func() http.Handler { return asHandler(GetSemanticSettings(deps)) }},
		"GET /admin/v1/security/smart-detection/overview":              {class: "security_record_read", expr: "handler.GetSmartDetectionOverview(deps)", build: func() http.Handler { return asHandler(GetSmartDetectionOverview(deps)) }},
		"GET /admin/v1/settings/org-labels":                            {class: "common", expr: "handler.GetOrgLabels(deps)", build: func() http.Handler { return asHandler(GetOrgLabels(deps)) }},
		"GET /admin/v1/skills/assets":                                  {class: "security_config_read", expr: "handler.ListSkillAssets(deps)", build: func() http.Handler { return asHandler(ListSkillAssets(deps)) }},
		"GET /admin/v1/skills/assets/{id}/versions":                    {class: "security_config_read", expr: "handler.ListSkillAssetVersions(deps)", build: func() http.Handler { return asHandler(ListSkillAssetVersions(deps)) }},
		"GET /admin/v1/skills/invocations":                             {class: "security_record_read", expr: "handler.ListSkillInvocations(deps)", build: func() http.Handler { return asHandler(ListSkillInvocations(deps)) }},
		"GET /admin/v1/system/audit-operations":                        {class: "audit", expr: "handler.ListAuditOperationsW8(deps)", build: func() http.Handler { return asHandler(ListAuditOperationsW8(deps)) }},
		"GET /admin/v1/system/audit-operations/export":                 {class: "audit_export", expr: "handler.ExportAuditOperations(deps)", build: func() http.Handler { return asHandler(ExportAuditOperations(deps)) }},
		"GET /admin/v1/system/initialization":                          {class: "common", expr: "handler.GetFirstAdminInitializationStatus(deps)", build: func() http.Handler { return asHandler(GetFirstAdminInitializationStatus(deps)) }},
		"GET /admin/v1/system/license":                                 {class: "common", expr: "handler.GetLicenseStatus(deps)", build: func() http.Handler { return asHandler(GetLicenseStatus(deps)) }},
		"GET /admin/v1/system/product":                                 {class: "common", expr: "handler.GetProductInfo(deps)", build: func() http.Handler { return asHandler(GetProductInfo(deps)) }},
		"GET /admin/v1/system/settings":                                {class: "common", expr: "handler.GetSystemSettings(deps)", build: func() http.Handler { return asHandler(GetSystemSettings(deps)) }},
		"GET /admin/v1/system/version":                                 {class: "common", expr: "handler.GetVersionInfo(deps)", build: func() http.Handler { return asHandler(GetVersionInfo(deps)) }},
		"GET /admin/v1/teams":                                          {class: "directory_read", expr: "handler.ListTeams(deps)", build: func() http.Handler { return asHandler(ListTeams(deps)) }},
		"GET /admin/v1/tools/config":                                   {class: "security_config_read", expr: "handler.GetToolRiskConfigs(deps)", build: func() http.Handler { return asHandler(GetToolRiskConfigs(deps)) }},
		"GET /admin/v1/users/{id}/login-history":                       {class: "login_history", expr: "handler.GetUserLoginHistory(deps)", build: func() http.Handler { return asHandler(GetUserLoginHistory(deps)) }},
		"GET /api/security/posture":                                    {class: "security_config_read", expr: "handler.GetSecurityPosture(deps)", build: func() http.Handler { return asHandler(GetSecurityPosture(deps)) }},
		"PATCH /admin/v1/alert-groups/{id}":                            {class: "alert_handle", expr: "handler.UpdateAlertGroupStatus(deps)", build: func() http.Handler { return asHandler(UpdateAlertGroupStatus(deps)) }},
		"PATCH /admin/v1/rules/{id}":                                   {class: "security_write", expr: "handler.UpdateRule(deps)", build: func() http.Handler { return asHandler(UpdateRule(deps)) }},
		"PATCH /admin/v1/security/policies/{id}":                       {class: "security_write", expr: "handler.UpdateSecurityPolicy(deps)", build: func() http.Handler { return asHandler(UpdateSecurityPolicy(deps)) }},
		"POST /admin/v1/agent/approval-exceptions":                     {class: "security_write", expr: "agentAuthorizationApprovalAPI.CreateException", build: func() http.Handler { return asHandler(agentAuthorizationApprovalAPI.CreateException) }},
		"POST /admin/v1/agent/approval-rules":                          {class: "security_write", expr: "agentDestinationApprovalAPI.Create", build: func() http.Handler { return asHandler(agentDestinationApprovalAPI.Create) }},
		"POST /admin/v1/agent/approval-rules/{id}/deactivate":          {class: "security_write", expr: "agentDestinationApprovalAPI.Deactivate", build: func() http.Handler { return asHandler(agentDestinationApprovalAPI.Deactivate) }},
		"POST /admin/v1/agent/approvals/{id}/resolve":                  {class: "security_write", expr: "agentAuthorizationApprovalAPI.ResolveApproval", build: func() http.Handler { return asHandler(agentAuthorizationApprovalAPI.ResolveApproval) }},
		"POST /admin/v1/agent/approvals/{id}/revoke":                   {class: "security_write", expr: "agentAuthorizationApprovalAPI.RevokeApproval", build: func() http.Handler { return asHandler(agentAuthorizationApprovalAPI.RevokeApproval) }},
		"POST /admin/v1/agentguard/confirmations/{id}/resolve":         {class: "security_write", expr: "handler.ResolveAgentGuardConfirmation(deps)", build: func() http.Handler { return asHandler(ResolveAgentGuardConfirmation(deps)) }},
		"POST /admin/v1/agentguard/exceptions":                         {class: "security_write", expr: "handler.CreateAgentGuardException(deps)", build: func() http.Handler { return asHandler(CreateAgentGuardException(deps)) }},
		"POST /admin/v1/agentguard/exceptions/suggest":                 {class: "security_config_read", expr: "handler.SuggestAgentGuardException(deps)", build: func() http.Handler { return asHandler(SuggestAgentGuardException(deps)) }},
		"POST /admin/v1/agentguard/policies":                           {class: "security_write", expr: "handler.CreateAgentGuardPolicy(deps)", build: func() http.Handler { return asHandler(CreateAgentGuardPolicy(deps)) }},
		"POST /admin/v1/agentguard/policies/simulate":                  {class: "security_config_read", expr: "handler.SimulateAgentGuardPolicy(deps)", build: func() http.Handler { return asHandler(SimulateAgentGuardPolicy(deps)) }},
		"POST /admin/v1/agentguard/policies/{id}/rollback":             {class: "security_write", expr: "handler.RollbackAgentGuardPolicy(deps)", build: func() http.Handler { return asHandler(RollbackAgentGuardPolicy(deps)) }},
		"POST /admin/v1/agentguard/rollouts":                           {class: "security_write", expr: "handler.CreateAgentGuardRollout(deps)", build: func() http.Handler { return asHandler(CreateAgentGuardRollout(deps)) }},
		"POST /admin/v1/alert-groups/batch-status":                     {class: "alert_handle", expr: "handler.BatchUpdateAlertGroupStatus(deps)", build: func() http.Handler { return asHandler(BatchUpdateAlertGroupStatus(deps)) }},
		"POST /admin/v1/alerts/{id}/read":                              {class: "common", expr: "handler.MarkAlertRead(deps)", build: func() http.Handler { return asHandler(MarkAlertRead(deps)) }},
		"POST /admin/v1/audit-chain/verify":                            {class: "audit", expr: "handler.VerifyAuditChain(deps)", build: func() http.Handler { return asHandler(VerifyAuditChain(deps)) }},
		"POST /admin/v1/audit/access-retention/{request_id}/content": {class: "evidence", expr: "handler.GetAccessRetentionContent(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetAccessRetentionContent(deps))))
		}},
		"POST /admin/v1/audit/access-retention/{request_id}/timeline": {class: "evidence", expr: "handler.GetEvidenceTimeline(deps)", build: func() http.Handler {
			return asHandler(RequireFullTenantContentEvidence(asHandler(GetEvidenceTimeline(deps))))
		}},
		"POST /admin/v1/audit/leak-trace":                        {class: "evidence", expr: "handler.LeakTrace(deps)", build: func() http.Handler { return asHandler(RequireFullTenantContentEvidence(asHandler(LeakTrace(deps)))) }},
		"POST /admin/v1/audit/raw-evidence/{id}/reveal":          {class: "raw_evidence", expr: "handler.RevealRawEvidence(deps)", build: func() http.Handler { return asHandler(RevealRawEvidence(deps)) }},
		"POST /admin/v1/content-security/exceptions":             {class: "security_write", expr: "handler.CreateContentAuditException(deps)", build: func() http.Handler { return asHandler(CreateContentAuditException(deps)) }},
		"POST /admin/v1/content-security/rules":                  {class: "security_write", expr: "handler.CreateContentSensitiveRule(deps)", build: func() http.Handler { return asHandler(CreateContentSensitiveRule(deps)) }},
		"POST /admin/v1/detectors/batch-update":                  {class: "security_write", expr: "handler.BatchUpdateDetector(deps)", build: func() http.Handler { return asHandler(BatchUpdateDetector(deps)) }},
		"POST /admin/v1/detectors/init":                          {class: "security_write", expr: "handler.InitDetectors(deps)", build: func() http.Handler { return asHandler(InitDetectors(deps)) }},
		"POST /admin/v1/diagnostics/sessions":                    {class: "common", expr: "handler.CreateDiagnosticsSession(diagEngine)", build: func() http.Handler { return asHandler(CreateDiagnosticsSession(diagEngine)) }},
		"POST /admin/v1/diagnostics/sessions/{id}/messages":      {class: "common", expr: "handler.AddDiagnosticsMessage(diagEngine)", build: func() http.Handler { return asHandler(AddDiagnosticsMessage(diagEngine)) }},
		"POST /admin/v1/employee-login":                          {class: "common", expr: "handler.EmployeeLogin(deps)", build: func() http.Handler { return asHandler(EmployeeLogin(deps)) }},
		"POST /admin/v1/integration/agent-policies":              {class: "security_write", expr: "handler.WriteAgentPolicy(deps)", build: func() http.Handler { return asHandler(WriteAgentPolicy(deps)) }},
		"POST /admin/v1/internal/agent/events":                   {class: "common", expr: "agentEndpointAPI.Events", build: func() http.Handler { return asHandler(agentEndpointAPI.Events) }},
		"POST /admin/v1/internal/agent/identity-events":          {class: "common", expr: "nativeEventAPI.Ingest", build: func() http.Handler { return asHandler(nativeEventAPI.Ingest) }},
		"POST /admin/v1/internal/agent/kubernetes/snapshot-runs": {class: "common", expr: "kubernetesSnapshotAPI.BeginSnapshotRun", build: func() http.Handler { return asHandler(kubernetesSnapshotAPI.BeginSnapshotRun) }},
		"POST /admin/v1/internal/agent/kubernetes/snapshots":     {class: "common", expr: "kubernetesSnapshotAPI.IngestSnapshot", build: func() http.Handler { return asHandler(kubernetesSnapshotAPI.IngestSnapshot) }},
		"POST /admin/v1/internal/agent/probe-reports":            {class: "common", expr: "agentEndpointAPI.ProbeReports", build: func() http.Handler { return asHandler(agentEndpointAPI.ProbeReports) }},
		"POST /admin/v1/logout":                                  {class: "common", expr: "handler.Logout(deps)", build: func() http.Handler { return asHandler(Logout(deps)) }},
		"POST /admin/v1/mcp-policies":                            {class: "security_write", expr: "handler.CreateMCPPolicy(deps)", build: func() http.Handler { return asHandler(CreateMCPPolicy(deps)) }},
		"POST /admin/v1/mcp-policies/shadow-check":               {class: "security_config_read", expr: "handler.MCPPolicyShadowCheck(deps)", build: func() http.Handler { return asHandler(MCPPolicyShadowCheck(deps)) }},
		"POST /admin/v1/mcp-policies/simulate":                   {class: "security_config_read", expr: "handler.SimulateMCPPolicy(deps)", build: func() http.Handler { return asHandler(SimulateMCPPolicy(deps)) }},
		"POST /admin/v1/mcp-servers/{id}/admission":              {class: "security_write", expr: "handler.SetMCPServerAdmission(deps)", build: func() http.Handler { return asHandler(SetMCPServerAdmission(deps)) }},
		"POST /admin/v1/mcp-servers/{id}/allowlist-template":     {class: "security_write", expr: "handler.ApplyMCPAllowlistTemplate(deps)", build: func() http.Handler { return asHandler(ApplyMCPAllowlistTemplate(deps)) }},
		"POST /admin/v1/mcp-tools/{id}/admission":                {class: "security_write", expr: "handler.SetMCPToolAdmission(deps)", build: func() http.Handler { return asHandler(SetMCPToolAdmission(deps)) }},
		"POST /admin/v1/me/change-password":                      {class: "common", expr: "handler.ChangeCurrentPassword(deps)", build: func() http.Handler { return asHandler(ChangeCurrentPassword(deps)) }},
		"POST /admin/v1/me/totp/enable":                          {class: "common", expr: "handler.EnableMyTOTP(deps)", build: func() http.Handler { return asHandler(EnableMyTOTP(deps)) }},
		"POST /admin/v1/me/totp/setup":                           {class: "common", expr: "handler.SetupMyTOTP(deps)", build: func() http.Handler { return asHandler(SetupMyTOTP(deps)) }},
		"POST /admin/v1/policy-suggestions/{id}/approve":         {class: "security_write", expr: "handler.ReviewPolicySuggestion(deps, true)", build: func() http.Handler { return asHandler(ReviewPolicySuggestion(deps, true)) }},
		"POST /admin/v1/policy-suggestions/{id}/reject":          {class: "security_write", expr: "handler.ReviewPolicySuggestion(deps, false)", build: func() http.Handler { return asHandler(ReviewPolicySuggestion(deps, false)) }},
		"POST /admin/v1/portal-integration/employee-key/claim":   {class: "common", expr: "handler.EmployeeKeyEndpoint(deps, \"claim\")", build: func() http.Handler { return asHandler(EmployeeKeyEndpoint(deps, "claim")) }},
		"POST /admin/v1/portal-integration/employee-key/ensure":  {class: "common", expr: "handler.EmployeeKeyEndpoint(deps, \"ensure\")", build: func() http.Handler { return asHandler(EmployeeKeyEndpoint(deps, "ensure")) }},
		"POST /admin/v1/portal-integration/employee-key/reset":   {class: "common", expr: "handler.EmployeeKeyEndpoint(deps, \"reset\")", build: func() http.Handler { return asHandler(EmployeeKeyEndpoint(deps, "reset")) }},
		"POST /admin/v1/rule-sets":                               {class: "security_write", expr: "handler.CreateRuleSet(deps)", build: func() http.Handler { return asHandler(CreateRuleSet(deps)) }},
		"POST /admin/v1/rule-sets/{id}/publish":                  {class: "security_write", expr: "handler.PublishRuleSet(deps)", build: func() http.Handler { return asHandler(PublishRuleSet(deps)) }},
		"POST /admin/v1/rules":                                   {class: "security_write", expr: "handler.CreateRule(deps)", build: func() http.Handler { return asHandler(CreateRule(deps)) }},
		"POST /admin/v1/rules/{id}/toggle":                       {class: "security_write", expr: "handler.ToggleRule(deps)", build: func() http.Handler { return asHandler(ToggleRule(deps)) }},
		"POST /admin/v1/security/corpus-scans":                   {class: "security_write", expr: "corpusScanHTTP.Create", build: func() http.Handler { return asHandler(corpusScanHTTP.Create) }},
		"POST /admin/v1/security/corpus-scans/{id}/cancel":       {class: "security_write", expr: "corpusScanHTTP.Cancel", build: func() http.Handler { return asHandler(corpusScanHTTP.Cancel) }},
		"POST /admin/v1/security/corpus-scans/{id}/start":        {class: "security_write", expr: "corpusScanHTTP.Start", build: func() http.Handler { return asHandler(corpusScanHTTP.Start) }},
		"POST /admin/v1/security/policies":                       {class: "security_write", expr: "handler.CreateSecurityPolicy(deps)", build: func() http.Handler { return asHandler(CreateSecurityPolicy(deps)) }},
		"POST /admin/v1/security/policies/batch":                 {class: "security_write", expr: "handler.BatchUpdateSecurityPolicies(deps)", build: func() http.Handler { return asHandler(BatchUpdateSecurityPolicies(deps)) }},
		"POST /admin/v1/security/policies/preview":               {class: "security_config_read", expr: "handler.PreviewSecurityPolicies(deps)", build: func() http.Handler { return asHandler(PreviewSecurityPolicies(deps)) }},
		"POST /admin/v1/security/policies/quick-create/generate": {class: "security_write", expr: "handler.GenerateQuickSecurityPolicy(deps)", build: func() http.Handler { return asHandler(GenerateQuickSecurityPolicy(deps)) }},
		"POST /admin/v1/security/policies/quick-create/preview":  {class: "security_config_read", expr: "handler.PreviewQuickSecurityPolicy(deps)", build: func() http.Handler { return asHandler(PreviewQuickSecurityPolicy(deps)) }},
		"POST /admin/v1/security/semantic/test-judge":            {class: "security_write", expr: "handler.TestSemanticJudge(deps)", build: func() http.Handler { return asHandler(TestSemanticJudge(deps)) }},
		"POST /admin/v1/security/test":                           {class: "security_write", expr: "handler.TestSecurity(deps)", build: func() http.Handler { return asHandler(TestSecurity(deps)) }},
		"POST /admin/v1/skills/scan":                             {class: "security_write", expr: "handler.ScanSkillArchive(deps)", build: func() http.Handler { return asHandler(ScanSkillArchive(deps)) }},
		"POST /admin/v1/skills/versions/{id}/admission":          {class: "security_write", expr: "handler.SetSkillVersionAdmission(deps)", build: func() http.Handler { return asHandler(SetSkillVersionAdmission(deps)) }},
		"POST /admin/v1/tools/config":                            {class: "security_write", expr: "handler.CreateToolRiskConfig(deps)", build: func() http.Handler { return asHandler(CreateToolRiskConfig(deps)) }},
		"POST /admin/v1/tools/config/batch":                      {class: "security_write", expr: "handler.BatchUpsertToolRiskConfigs(deps)", build: func() http.Handler { return asHandler(BatchUpsertToolRiskConfigs(deps)) }},
		"PUT /admin/v1/agent-operation-protection":               {class: "security_write", expr: "handler.PutAgentOperationProtection(deps)", build: func() http.Handler { return asHandler(PutAgentOperationProtection(deps)) }},
		"PUT /admin/v1/agent/endpoints/{id}/mode":                {class: "security_write", expr: "agentAdminAPI.UpdateEndpointMode", build: func() http.Handler { return asHandler(agentAdminAPI.UpdateEndpointMode) }},
		"PUT /admin/v1/agent/unified-assets/{id}/catalog":        {class: "security_write", expr: "agentUnifiedAssetAPI.UpdateCatalog", build: func() http.Handler { return asHandler(agentUnifiedAssetAPI.UpdateCatalog) }},
		"PUT /admin/v1/agentguard/policies/{id}":                 {class: "security_write", expr: "handler.UpdateAgentGuardPolicy(deps)", build: func() http.Handler { return asHandler(UpdateAgentGuardPolicy(deps)) }},
		"PUT /admin/v1/audit/dispositions":                       {class: "alert_handle", expr: "handler.UpsertAuditDisposition(deps)", build: func() http.Handler { return asHandler(UpsertAuditDisposition(deps)) }},
		"PUT /admin/v1/audit/raw-evidence/settings":              {class: "raw_evidence", expr: "handler.UpdateRawEvidenceSettings(deps)", build: func() http.Handler { return asHandler(UpdateRawEvidenceSettings(deps)) }},
		"PUT /admin/v1/content-security/file-policy":             {class: "security_write", expr: "handler.UpdateContentFilePolicy(deps)", build: func() http.Handler { return asHandler(UpdateContentFilePolicy(deps)) }},
		"PUT /admin/v1/content-security/industry":                {class: "security_write", expr: "handler.UpdateContentSecurityIndustry(deps)", build: func() http.Handler { return asHandler(UpdateContentSecurityIndustry(deps)) }},
		"PUT /admin/v1/integration/agent-policies/{id}":          {class: "security_write", expr: "handler.WriteAgentPolicy(deps)", build: func() http.Handler { return asHandler(WriteAgentPolicy(deps)) }},
		"PUT /admin/v1/mcp-policies/{id}":                        {class: "security_write", expr: "handler.UpdateMCPPolicy(deps)", build: func() http.Handler { return asHandler(UpdateMCPPolicy(deps)) }},
		"PUT /admin/v1/mcp-redline-settings":                     {class: "security_write", expr: "handler.UpdateMCPRedlineSettings(deps, mcpRedlineSettingsStore)", build: func() http.Handler { return asHandler(UpdateMCPRedlineSettings(deps, mcpRedlineSettingsStore)) }},
		"PUT /admin/v1/policy-center/agent-behaviors/{key}":      {class: "security_write", expr: "handler.PutPolicyCenterAgentBehavior(deps)", build: func() http.Handler { return asHandler(PutPolicyCenterAgentBehavior(deps)) }},
		"PUT /admin/v1/protection-settings":                      {class: "security_write", expr: "handler.UpdateProtectionSettings(deps)", build: func() http.Handler { return asHandler(UpdateProtectionSettings(deps)) }},
		"PUT /admin/v1/security/corpus-scans/{id}/chunks/{n}":    {class: "security_write", expr: "corpusScanHTTP.UploadChunk", build: func() http.Handler { return asHandler(corpusScanHTTP.UploadChunk) }},
		"PUT /admin/v1/security/policy-assets/{id}":              {class: "security_write", expr: "handler.UpdatePolicyAsset(deps)", build: func() http.Handler { return asHandler(UpdatePolicyAsset(deps)) }},
		"PUT /admin/v1/security/reply-policy":                    {class: "security_write", expr: "handler.PutSecurityReplyPolicy(deps)", build: func() http.Handler { return asHandler(PutSecurityReplyPolicy(deps)) }},
		"PUT /admin/v1/security/semantic/settings":               {class: "security_write", expr: "handler.UpdateSemanticSettings(deps)", build: func() http.Handler { return asHandler(UpdateSemanticSettings(deps)) }},
		"PUT /admin/v1/security/smart-detection/config":          {class: "security_write", expr: "handler.UpdateSmartDetectionConfig(deps)", build: func() http.Handler { return asHandler(UpdateSmartDetectionConfig(deps)) }},
		"PUT /admin/v1/security/system-settings":                 {class: "security_write", expr: "handler.UpdateSecuritySystemSettings(deps)", build: func() http.Handler { return asHandler(UpdateSecuritySystemSettings(deps)) }},
		"PUT /admin/v1/tools/config/{id}":                        {class: "security_write", expr: "handler.UpdateToolRiskConfig(deps)", build: func() http.Handler { return asHandler(UpdateToolRiskConfig(deps)) }},
	}
}

func asHandler(v any) http.Handler {
	switch h := v.(type) {
	case http.Handler:
		return h
	case func(http.ResponseWriter, *http.Request):
		return http.HandlerFunc(h)
	}
	panic("unsupported handler type")
}
