import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from "react-router-dom"
import { useEffect, useState } from "react"
import { Alert, Button } from "antd"
import { useCurrencyStore } from "./stores/currency"
import { billingEmployeeApi, licenseApi } from "./services/api"
import { useAuthStore } from "./stores/auth"
import Layout from "./components/Layout"
import RequireRole from "./components/RequireRole"
import { roleHome } from "./utils/access"
import { isConsoleRole, CONSOLE_LOGIN_COPY } from "./utils/consoleAccess"
import LoginHistoryAudit from "./pages/LoginHistoryAudit"
import Login from "./pages/Login"
import Dashboard from "./pages/Dashboard"
import Users from "./pages/Users"
import Apps from "./pages/Apps"
import Providers from "./pages/Providers"
import ModelManagement from "./pages/ModelManagement"
import ModelOperations from "./pages/ModelOperations"
import Keys from "./pages/Keys"
import CostRecords from "./pages/cost/CostRecords"
import ContentAudit from "./pages/ContentAudit"
import SecurityOperationsOverview from "./pages/SecurityOperationsOverview"
import ToolAudit from "./pages/ToolAudit"
import SecurityPolicyCenter from "./pages/SecurityPolicyCenter"
import ToolRiskConfig from "./pages/ToolRiskConfig"
import SystemSettings from "./pages/SystemSettings"
import RetentionStorage from "./pages/RetentionStorage"
import OperationAudit from "./pages/OperationAudit"
import ServiceHealth from "./pages/ServiceHealth"
import ProxySettings from "./pages/ProxySettings"
import ReverseProxy from "./pages/ReverseProxy"
import AccessRetention from "./pages/AccessRetention"
import ChangePassword from "./pages/ChangePassword"
import Organizations from "./pages/Organizations"
import AlertInbox from "./pages/AlertInbox"
import BillingOverview from "./pages/billing/Overview"
import BillingBudgets from "./pages/billing/Budgets"
import BillingPricing from "./pages/billing/Pricing"
import BillingStatements from "./pages/billing/Statements"
import ModelRouting from "./pages/ModelRouting"
import NotifyChannels from "./pages/NotifyChannels"
import SkillSecurity from "./pages/SkillSecurity"
import CorpusScan from "./pages/CorpusScan"
import License from "./pages/License"
import McpServers from "./pages/McpServers"
import McpPolicies from "./pages/McpPolicies"
import McpAudit from "./pages/McpAudit"
import McpApprovals from "./pages/McpApprovals"
import IdentitySources from "./pages/IdentitySources"
import IdentityLoginSource from "./pages/IdentityLoginSource"
import IdentityDirectorySource from "./pages/IdentityDirectorySource"
import AgentGuard from "./pages/AgentGuard"
import AgentBehaviorControl from "./pages/AgentBehaviorControl"
import BlockRecords from "./pages/BlockRecords"
import GatewayAgentSessions from "./pages/GatewayAgentSessions"
import AgentSessionDetail from "./pages/agent/AgentSessionDetail"
import { canReadAgent } from "./pages/agent/dict"

function AgentLicenseRoute({ children, feature = 'agent_security' }: { children: JSX.Element; feature?: 'agent_audit' | 'agent_security' }) {
  const { user } = useAuthStore()
  const [attempt, setAttempt] = useState(0)
  const requestKey = `${user?.id ?? ''}:${user?.tenant_id ?? ''}:${user?.role ?? ''}:${feature}:${attempt}`
  const [result, setResult] = useState<{ key: string; status: 'licensed' | 'unlicensed' | 'invalid' | 'error' } | null>(null)
  const gatewayAudit = feature === 'agent_audit'
  const capability = gatewayAudit ? 'AI Agent 审计' : '端侧智能体安全'
  useEffect(() => {
    let active = true
    licenseApi.status().then(({ data }) => {
      if (active) setResult({ key: requestKey, status: !data.valid ? 'invalid' : data.features?.includes(feature) ? 'licensed' : 'unlicensed' })
    }).catch(() => { if (active) setResult({ key: requestKey, status: 'error' }) })
    return () => { active = false }
  }, [feature, requestKey])
  if (result?.key !== requestKey) return <div role="status">正在核实{capability}授权…</div>
  if (result.status === 'error') return <Alert type="error" showIcon message="授权状态读取失败" description="请重试以确认当前授权状态。" action={<Button aria-label="重试" onClick={() => setAttempt(value => value + 1)}>重试</Button>} />
  if (result.status !== 'licensed') return <Alert type="info" showIcon message={gatewayAudit ? '智能体会话审计暂不可用' : '端侧智能体功能暂不可用'} description={<>
    {result.status === 'invalid' ? '当前许可证无效或已到期。' : `当前许可证未包含“${capability}”。`}
    {!gatewayAudit ? '端侧智能体安全与 AI Agent 审计分别授权。' : null}
    请在 <Link to="/system/license">授权管理</Link> 查看该能力状态。
  </>} />
  return children
}

// 旧路径跳到新路径并保留查询参数，深链（如按部门打开额度）继续可用。
function LegacyRedirect({ to }: { to: string }) {
  const location = useLocation()
  return <Navigate to={to + location.search} replace />
}

function SecurityPoliciesRoute() {
  const requestedSection = new URLSearchParams(window.location.search).get("section")
  if (requestedSection === "agent-behavior") {
    return <Navigate to="/security/agents" replace />
  }
  return <RequireRole path="/security/policies"><SecurityPolicyCenter /></RequireRole>
}

function LegacyAgentSecurityRoute() {
  const tab = new URLSearchParams(window.location.search).get('tab')
  return <RequireRole path="/security/agentguard"><Navigate to={tab === 'confirmations' ? '/security/agents/advanced?tab=confirmations' : '/security/agents'} replace /></RequireRole>
}

export function ConsoleAccessDenied() {
  return <main className="login-page"><section className="login-shell">
    <Alert type="warning" showIcon message={CONSOLE_LOGIN_COPY.deniedHeading} description={CONSOLE_LOGIN_COPY.employeeHint}
      action={<>
        <Button href="/chat/login">{CONSOLE_LOGIN_COPY.openChat}</Button>
        <Button onClick={() => { useAuthStore.getState().logout(); window.location.replace('/login') }}>{CONSOLE_LOGIN_COPY.returnToConsole}</Button>
      </>} />
  </section></main>
}

function App() {
  const { isAuthenticated, user } = useAuthStore()
  useEffect(() => {
    if (!isAuthenticated) return
    let active = true
    void billingEmployeeApi.settings(user?.tenant_id || '').then(response => {
      if (active) useCurrencyStore.getState().setTenantCurrency(response.data?.data?.currency)
    }).catch(() => { /* 保持当前币种，设置页可重试加载。 */ })
    return () => { active = false }
  }, [isAuthenticated, user?.tenant_id])

  if (!isAuthenticated) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    )
  }

  if (!isConsoleRole(user?.role)) return <ConsoleAccessDenied />

  if (user?.password_change_required) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/change-password" element={<ChangePassword />} />
          <Route path="*" element={<Navigate to="/change-password" replace />} />
        </Routes>
      </BrowserRouter>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to={roleHome(user?.role || "")} replace />} />
          <Route path="dashboard" element={<RequireRole path="/dashboard"><Dashboard /></RequireRole>} />
          <Route path="change-password" element={<ChangePassword />} />

          <Route path="usage" element={<RequireRole path="/usage"><BillingOverview /></RequireRole>} />
          <Route path="cost/records" element={<RequireRole path="/cost/records"><CostRecords /></RequireRole>} />
          <Route path="cost/snapshot" element={<Navigate to="/cost/records" replace />} />
          <Route path="cost/savings" element={<Navigate to="/cost/records" replace />} />
          <Route path="cost/anomalies" element={<Navigate to="/cost/statements" replace />} />
          <Route path="cost/forecast" element={<Navigate to="/cost/records" replace />} />
          <Route path="cost/prices-fx" element={<Navigate to="/cost/pricing" replace />} />
          <Route path="cost/budgets" element={<RequireRole path="/cost/budgets"><BillingBudgets /></RequireRole>} />
          <Route path="cost/pricing" element={<RequireRole path="/cost/pricing"><BillingPricing /></RequireRole>} />
          <Route path="cost/statements" element={<RequireRole path="/cost/statements"><BillingStatements /></RequireRole>} />
          {/* P1：旧路由保留跳转，带上原查询参数（如 scope_type/scope_id），不出现 404 */}
          <Route path="cost/customer-billing" element={<RequireRole path="/cost/customer-billing"><LegacyRedirect to="/cost/statements" /></RequireRole>} />
          <Route path="cost/quota-policies" element={<RequireRole path="/cost/quota-policies"><LegacyRedirect to="/cost/budgets" /></RequireRole>} />
          <Route path="cost/alerts" element={<RequireRole path="/cost/alerts"><AlertInbox /></RequireRole>} />

          <Route path="agent/native-events" element={<div style={{ padding: 24 }}>此管理功能已迁入独立智能体安全平台。请使用平台登录入口。</div>} />
          <Route path="agent/assets" element={<div style={{ padding: 24 }}>此管理功能已迁入独立智能体安全平台。请使用平台登录入口。</div>} />
          <Route path="agent/endpoints" element={<div style={{ padding: 24 }}>此管理功能已迁入独立智能体安全平台。请使用平台登录入口。</div>} />
          <Route path="agent/enrollment" element={<div style={{ padding: 24 }}>此管理功能已迁入独立智能体安全平台。请使用平台登录入口。</div>} />
          <Route path="agent/sessions" element={canReadAgent(user?.role) ? <AgentLicenseRoute feature="agent_audit"><GatewayAgentSessions /></AgentLicenseRoute> : <Navigate to={roleHome(user?.role || "")} replace />} />
          <Route path="agent/sessions/:id" element={canReadAgent(user?.role) ? <AgentLicenseRoute><AgentSessionDetail /></AgentLicenseRoute> : <Navigate to={roleHome(user?.role || "")} replace />} />
          <Route path="security/overview" element={<Navigate to="/security/policies" replace />} />
          <Route path="compliance/overview" element={<RequireRole path="/compliance/overview"><SecurityOperationsOverview /></RequireRole>} />
          <Route path="security/alerts" element={<RequireRole path="/security/alerts"><ContentAudit /></RequireRole>} />
          <Route path="security/blocks" element={<RequireRole path="/security/blocks"><BlockRecords /></RequireRole>} />
          <Route path="security/agent-tools" element={<RequireRole path="/security/agent-tools"><ToolAudit /></RequireRole>} />
          <Route path="security/agents" element={<RequireRole path="/security/agents"><AgentBehaviorControl /></RequireRole>} />
          <Route path="security/agents/advanced" element={<RequireRole path="/security/agents/advanced"><AgentGuard /></RequireRole>} />
          <Route path="security/agentguard" element={<LegacyAgentSecurityRoute />} />
          <Route path="security/agent-operation-protection/advanced" element={<RequireRole path="/security/agent-operation-protection/advanced"><Navigate to="/security/agents?tab=advanced" replace /></RequireRole>} />
          <Route path="security/agent-operation-protection" element={<Navigate to="/security/agents?behavior=destructive_operation" replace />} />
          <Route path="security/events" element={<RequireRole path="/security/events"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="security/tools" element={<RequireRole path="/security/tools"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="security/detections" element={<RequireRole path="/security/detections"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="security/instruction-alerts" element={<RequireRole path="/security/instruction-alerts"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="security/content-data" element={<RequireRole path="/security/content-data"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="security/semantic" element={<RequireRole path="/security/semantic"><Navigate to="/security/policies?tab=detection" replace /></RequireRole>} />
          <Route path="security/skills" element={<RequireRole path="/security/skills"><SkillSecurity /></RequireRole>} />
          <Route path="security/corpus-scan" element={<RequireRole path="/security/corpus-scan"><CorpusScan /></RequireRole>} />
          {/* 智能检测控制台已从 UI 下线（后端能力保留），旧路径重定向到策略中心检测配置 */}
          <Route path="security/smart-detection" element={<Navigate to="/security/policies?tab=detection" replace />} />
          <Route path="security/content" element={<RequireRole path="/security/content"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="security/data" element={<RequireRole path="/security/data"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="security/policies" element={<SecurityPoliciesRoute />} />
          <Route path="security/tool-config" element={<RequireRole path="/security/tool-config"><ToolRiskConfig /></RequireRole>} />
          <Route path="security" element={<RequireRole path="/security"><SecurityPolicyCenter /></RequireRole>} />
          <Route path="security/*" element={<RequireRole path="/security"><SecurityPolicyCenter /></RequireRole>} />

          <Route path="mcp-gateway/servers" element={<RequireRole path="/mcp-gateway/servers"><McpServers /></RequireRole>} />
          <Route path="mcp-gateway/policies" element={<RequireRole path="/mcp-gateway/policies"><McpPolicies /></RequireRole>} />
          <Route path="mcp-gateway/approvals" element={<RequireRole path="/mcp-gateway/approvals"><McpApprovals /></RequireRole>} />
          <Route path="mcp-gateway/audit" element={<RequireRole path="/mcp-gateway/audit"><McpAudit /></RequireRole>} />
          {/* D7：控制台页面原挂在 /mcp/* 下，与网关数据面 /mcp/{serverID} 冲突（边缘代理整段转给网关，刷新即 404）。
              页面已迁到 /mcp-gateway/*；下面的旧路径只为已有书签/外链保留，经 SPA 回落后重定向，query 保留。 */}
          <Route path="mcp/servers" element={<RequireRole path="/mcp-gateway/servers"><LegacyRedirect to="/mcp-gateway/servers" /></RequireRole>} />
          <Route path="mcp/policies" element={<RequireRole path="/mcp-gateway/policies"><LegacyRedirect to="/mcp-gateway/policies" /></RequireRole>} />
          <Route path="mcp/approvals" element={<RequireRole path="/mcp-gateway/approvals"><LegacyRedirect to="/mcp-gateway/approvals" /></RequireRole>} />
          <Route path="mcp/audit" element={<RequireRole path="/mcp-gateway/audit"><LegacyRedirect to="/mcp-gateway/audit" /></RequireRole>} />
          <Route path="mcp/overview" element={<Navigate to="/mcp-gateway/audit" replace />} />

          <Route path="audit/content" element={<RequireRole path="/audit/content"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="audit/tools" element={<RequireRole path="/audit/tools"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="audit/agents" element={<RequireRole path="/audit/agents"><Navigate to="/security/alerts" replace /></RequireRole>} />
          <Route path="audit/access-retention" element={<RequireRole path="/audit/access-retention"><AccessRetention /></RequireRole>} />
          <Route path="audit/login-history" element={<RequireRole path="/audit/login-history"><LoginHistoryAudit /></RequireRole>} />
          <Route path="system/audit-operations" element={<RequireRole path="/system/audit-operations"><OperationAudit /></RequireRole>} />
          <Route path="system/service-health" element={<RequireRole path="/system/service-health"><ServiceHealth /></RequireRole>} />

          <Route path="connect/channels" element={<RequireRole path="/connect/channels"><ReverseProxy /></RequireRole>} />
          <Route path="connect/models" element={<Navigate to="/models" replace />} />
          <Route path="connect/apps" element={<Navigate to="/apps" replace />} />
          <Route path="connect/network" element={<RequireRole path="/connect/network"><ProxySettings /></RequireRole>} />
          <Route path="connect/forward-access" element={<RequireRole path="/connect/forward-access"><Navigate to="/audit/access-retention" replace /></RequireRole>} />
          <Route path="proxy/settings" element={<Navigate to="/connect/network" replace />} />
          <Route path="proxy/reverse" element={<Navigate to="/connect/channels" replace />} />

          <Route path="organizations" element={<RequireRole path="/organizations"><Organizations /></RequireRole>} />
          <Route path="apps" element={<RequireRole path="/apps"><Apps /></RequireRole>} />
          <Route path="users" element={<RequireRole path="/users"><Users /></RequireRole>} />
          <Route path="employee-ai-permissions" element={<Navigate to="/organizations" replace />} />
          <Route path="group-mapping-rules" element={<Navigate to="/organizations" replace />} />
          <Route path="identity-sources" element={<RequireRole path="/identity-sources"><IdentitySources /></RequireRole>} />
          <Route path="identity-sources/login" element={<RequireRole path="/identity-sources/login"><IdentityLoginSource /></RequireRole>} />
          <Route path="identity-sources/directory" element={<RequireRole path="/identity-sources/directory"><IdentityDirectorySource /></RequireRole>} />
          {/* 任务8：合并身份源入口，旧路径重定向到企业身份源子页 */}
          <Route path="sso-config" element={<Navigate to="/identity-sources/login" replace />} />
          <Route path="directory-sync" element={<Navigate to="/identity-sources/directory" replace />} />
          <Route path="keys" element={<RequireRole path="/keys"><Keys /></RequireRole>} />
          <Route path="providers" element={<RequireRole path="/providers"><Providers /></RequireRole>} />
          <Route path="models" element={<RequireRole path="/models"><ModelManagement /></RequireRole>} />
          <Route path="model-operations" element={<RequireRole path="/model-operations"><ModelOperations /></RequireRole>} />
          <Route path="model-routing" element={<RequireRole path="/model-routing"><ModelRouting /></RequireRole>} />
          <Route path="routing-policies" element={<Navigate to="/model-routing" replace />} />
          <Route path="routing-decisions" element={<Navigate to="/model-routing" replace />} />
          <Route path="mcp-servers" element={<RequireRole path="/mcp-servers"><Navigate to="/mcp-gateway/servers" replace /></RequireRole>} />
          <Route path="provider-price-snapshots" element={<RequireRole path="/provider-price-snapshots"><Navigate to="/models" replace /></RequireRole>} />
          <Route path="system/notify-channels" element={<RequireRole path="/system/notify-channels"><NotifyChannels /></RequireRole>} />
          <Route path="system/settings" element={<RequireRole path="/system/settings"><SystemSettings /></RequireRole>} />
          <Route path="system/retention-storage" element={<RequireRole path="/system/retention-storage"><RetentionStorage /></RequireRole>} />
          <Route path="system/license" element={<RequireRole path="/system/license"><License /></RequireRole>} />
          <Route path="*" element={<Navigate to={roleHome(user?.role || "")} replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
