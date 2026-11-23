import { CONSOLE_LOGIN_COPY as copy } from '../utils/consoleAccess'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from '../App'
import { licenseApi } from '../services/api'

const { mockAuth } = vi.hoisted(() => ({
  mockAuth: {
    isAuthenticated: true,
    user: { role: 'platform_admin', password_change_required: false },
    logout: vi.fn(),
  },
}))

vi.mock('../stores/auth', () => ({ useAuthStore: () => mockAuth }))

vi.mock('../pages/cost/CostRecords', () => ({ default: () => <div>计费概览路由</div> }))
vi.mock('../pages/SecurityPolicyCenter', () => ({ default: () => <div>策略中心路由</div> }))
vi.mock('../pages/SavingsBoard', () => ({ default: () => <div>节省看板旧页面</div> }))
vi.mock('../pages/ModelManagement', () => ({ default: () => <div>模型管理路由</div> }))
vi.mock('../pages/McpServers', () => ({ default: () => <div>MCP 服务管理路由</div> }))
vi.mock('../pages/McpAudit', () => ({ default: () => <div>MCP 调用审计路由</div> }))
vi.mock('../pages/McpPolicies', () => ({ default: () => <div>MCP 调用策略路由</div> }))
vi.mock('../pages/McpApprovals', () => ({ default: () => <div>MCP 审批与例外路由</div> }))
vi.mock('../pages/SemanticConsole', () => ({ default: () => <div>语义检测控制台页</div> }))
vi.mock('../pages/AgentSecurity', () => ({ default: () => <div>智能体安全路由</div> }))
vi.mock('../pages/AgentGuard', () => ({ default: () => <div>工程治理界面</div> }))
vi.mock('../pages/AgentBehaviorControl', () => ({ default: () => <div>智能体行为管控路由</div> }))
vi.mock('../pages/Organizations', () => ({ default: () => <div>组织管理页面</div> }))
vi.mock('../pages/ContentAudit', () => ({ default: () => <div>误报处理安全告警页面</div> }))
vi.mock('../pages/ToolAudit', () => ({ default: () => <div>行为审计旧页面</div> }))
vi.mock('../pages/SkillSecurity', () => ({ default: () => <div>资产与准入旧页面</div> }))
vi.mock('../pages/Dashboard', () => ({ default: () => <div>态势总览页面</div> }))
vi.mock('../pages/OperationAudit', () => ({ default: () => <div>operation-audit-route</div> }))
vi.mock('../pages/AccessRetention', () => ({ default: () => <div>access-retention-route</div> }))
vi.mock('../pages/SecurityOperationsOverview', () => ({ default: () => <div>compliance-overview-route</div> }))
vi.mock('../pages/LoginHistoryAudit', () => ({ default: () => <div>login-history-route</div> }))
vi.mock('../pages/ProxySettings', () => ({ default: () => <div>proxy-settings-route</div> }))
vi.mock('../pages/ReverseProxy', () => ({ default: () => <div>reverse-proxy-route</div> }))
vi.mock('../pages/Apps', () => ({ default: () => <div>apps-route</div> }))
vi.mock('../pages/agent/AgentNativeTimeline', () => ({ default: () => <div>原生运行调查页面</div> }))
vi.mock('../pages/agent/AgentAssetCoverage', () => ({ default: () => <div>资产覆盖页面</div> }))
vi.mock('../pages/agent/AgentEndpoints', () => ({ default: () => <div>端点数据页面</div> }))
vi.mock('../pages/agent/AgentSessions', () => ({ default: () => <div>会话数据页面</div> }))
vi.mock('../pages/GatewayAgentSessions', () => ({ default: () => <div>网关会话审计页面</div> }))
vi.mock('../pages/agent/AgentSessionDetail', () => ({ default: () => <div>会话详情页面</div> }))
vi.mock('../pages/agent/AgentEnrollment', () => ({ default: () => <div>注册令牌页面</div> }))

describe('App legacy customer-facing routes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState({}, '', '/')
    mockAuth.user = { role: 'platform_admin', password_change_required: false }
    vi.spyOn(licenseApi, 'status').mockResolvedValue({ data: { valid: false, features: [] } } as any)
  })

  it.each([
    ['/agent/assets', '资产覆盖页面'],
    ['/agent/native-events', '原生运行调查页面'],
    ['/agent/endpoints', '端点数据页面'],
    ['/agent/sessions', '网关会话审计页面'],
    ['/agent/sessions/test-session', '会话详情页面'],
    ['/agent/enrollment', '注册令牌页面'],
  ])('无授权直达 %s 显示占位而不请求受保护页面', async (path, original) => {
    window.history.pushState({}, '', path)
    render(<App />)
    expect(await screen.findByText(path === '/agent/sessions' ? '智能体会话审计暂不可用' : path.includes('/sessions') ? '端侧智能体功能暂不可用' : '此管理功能已迁入独立智能体安全平台。请使用平台登录入口。')).toBeInTheDocument()
    expect(screen.queryByText(original)).not.toBeInTheDocument()
    expect(window.location.pathname).toBe(path)
  })

  it('五项有效授权可打开网关会话审计，不要求端侧授权', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: {
      valid: true,
      features: ['web_ai', 'agent_audit', 'ide_proxy', 'content_retention', 'sensitive_data_guard'],
    } } as any)
    window.history.pushState({}, '', '/agent/sessions')
    render(<App />)
    expect(await screen.findByText('网关会话审计页面')).toBeInTheDocument()
    expect(screen.queryByText('端侧智能体功能暂不可用')).not.toBeInTheDocument()
    expect(screen.queryByText('会话数据页面')).not.toBeInTheDocument()
  })

  it('网关审计授权不能打开端侧会话详情', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: { valid: true, features: ['agent_audit'] } } as any)
    window.history.pushState({}, '', '/agent/sessions/native-session')
    render(<App />)
    expect(await screen.findByText('端侧智能体功能暂不可用')).toBeInTheDocument()
    expect(screen.queryByText('会话详情页面')).not.toBeInTheDocument()
  })

  it('端侧授权不会自动授予网关会话审计', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: { valid: true, features: ['agent_security'] } } as any)
    window.history.pushState({}, '', '/agent/sessions')
    render(<App />)
    expect(await screen.findByText('智能体会话审计暂不可用')).toBeInTheDocument()
    expect(screen.queryByText('网关会话审计页面')).not.toBeInTheDocument()
  })

  it('读取授权失败时显示可重试错误，不宣称缺少授权', async () => {
    vi.mocked(licenseApi.status).mockRejectedValue(new Error('network unavailable'))
    window.history.pushState({}, '', '/agent/sessions')
    render(<App />)
    expect(await screen.findByText('授权状态读取失败')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
    expect(screen.queryByText('网关会话审计页面')).not.toBeInTheDocument()
  })

  it('授权查询重试成功后恢复会话审计', async () => {
    vi.mocked(licenseApi.status).mockRejectedValueOnce(new Error('temporary outage'))
      .mockResolvedValue({ data: { valid: true, features: ['agent_audit'] } } as any)
    window.history.pushState({}, '', '/agent/sessions')
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: '重试' }))
    expect(await screen.findByText('网关会话审计页面')).toBeInTheDocument()
  })

  it('账号切换后重新核实授权，不复用上一账号的页面许可', async () => {
    vi.mocked(licenseApi.status).mockResolvedValueOnce({ data: { valid: true, features: ['agent_audit'] } } as any)
      .mockResolvedValue({ data: { valid: true, features: [] } } as any)
    window.history.pushState({}, '', '/agent/sessions')
    const view = render(<App />)
    expect(await screen.findByText('网关会话审计页面')).toBeInTheDocument()
    mockAuth.user = { id: 'other-admin', tenant_id: 'tenant-2', role: 'tenant_admin', password_change_required: false } as any
    view.rerender(<App />)
    expect(screen.queryByText('网关会话审计页面')).not.toBeInTheDocument()
    expect(await screen.findByText('智能体会话审计暂不可用')).toBeInTheDocument()
    await waitFor(() => expect(licenseApi.status).toHaveBeenCalledTimes(2))
  })

  it('过期许可证即使包含审计能力也不能打开会话页面', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: { valid: false, features: ['agent_audit'] } } as any)
    window.history.pushState({}, '', '/agent/sessions')
    render(<App />)
    expect(await screen.findByText('智能体会话审计暂不可用')).toBeInTheDocument()
    expect(screen.getByText(/当前许可证无效或已到期/)).toBeInTheDocument()
    expect(screen.queryByText('网关会话审计页面')).not.toBeInTheDocument()
  })

  it.each(['tenant_admin'])('原生管理路由将有许可的 %s 引导到独立平台', async role => {
    mockAuth.user = { role, password_change_required: false }
    vi.mocked(licenseApi.status).mockResolvedValue({ data: { valid: true, features: ['agent_security'] } } as Awaited<ReturnType<typeof licenseApi.status>>)
    window.history.pushState({}, '', '/agent/native-events')
    render(<App />)
    expect(await screen.findByText('此管理功能已迁入独立智能体安全平台。请使用平台登录入口。')).toBeInTheDocument()
    expect(screen.queryByText('原生运行调查页面')).not.toBeInTheDocument()
  })
  it('blocks developer before its legacy management routes', async () => {
    mockAuth.user = { role: 'developer', password_change_required: false }
    for (const path of ['/agent/native-events']) {
      window.history.pushState({}, '', path)
      const view = render(<App />)
      expect(screen.getByText(copy.deniedHeading)).toBeInTheDocument()
      view.unmount()
    }
  })

  it('有 agent_security 授权也不能从网关打开独立平台端点管理', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: { valid: true, features: ['agent_security'] } } as any)
    window.history.pushState({}, '', '/agent/endpoints')
    render(<App />)
    expect(await screen.findByText('此管理功能已迁入独立智能体安全平台。请使用平台登录入口。')).toBeInTheDocument()
    expect(screen.queryByText('端点数据页面')).not.toBeInTheDocument()
  })

  it.each([
    ['/security/alerts', '误报处理安全告警页面'],
    ['/security/agent-tools', '行为审计旧页面'],
    ['/security/skills', '资产与准入旧页面'],
    ['/security/policies', '策略中心路由'],
  ])('平台一级菜单 %s 复用真实旧路由', async (path, content) => {
    window.history.pushState({}, '', path)
    render(<App />)
    expect(await screen.findByText(content)).toBeInTheDocument()
  })

  it('redirects removed savings board route to cost overview', async () => {
    window.history.pushState({}, '', '/cost/savings')

    render(<App />)

    expect(await screen.findByText('计费概览路由')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/cost/records')
    expect(screen.queryByText('节省看板旧页面')).not.toBeInTheDocument()
  })

  it('keeps security alerts on the false-positive handling page', async () => {
    window.history.pushState({}, '', '/security/alerts')

    render(<App />)

    expect(await screen.findByText('误报处理安全告警页面')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/alerts')
  })

  it.each(['tenant_owner', 'tenant_admin'])('allows %s to open scoped security alerts', async (role) => {
    mockAuth.user = { role, password_change_required: false }
    window.history.pushState({}, '', '/security/alerts')

    render(<App />)

    expect(await screen.findByText('误报处理安全告警页面')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/alerts')
  })

  it.each(['developer', 'project_owner'])('keeps %s out of scoped security alerts', async (role) => {
    mockAuth.user = { role, password_change_required: false }
    window.history.pushState({}, '', '/security/alerts')

    render(<App />)

    expect(screen.getByText(copy.deniedHeading)).toBeInTheDocument()
    expect(screen.queryByText('误报处理安全告警页面')).not.toBeInTheDocument()
  })

  it('redirects removed security overview route to policy center', async () => {
    window.history.pushState({}, '', '/security/overview')

    render(<App />)

    expect(await screen.findByText('策略中心路由')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/policies')
    expect(screen.queryByText('安全总览旧页面')).not.toBeInTheDocument()
  })

  it('redirects the legacy agent protection route to the new behavior control page', async () => {
    window.history.pushState({}, '', '/security/agent-operation-protection')

    render(<App />)

    expect(await screen.findByText('智能体行为管控路由')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/agents')
    expect(window.location.search).toBe('?behavior=destructive_operation')
  })
  it('routes the behavior control page separately from AgentGuard advanced settings', async () => {
    window.history.pushState({}, '', '/security/agents')
    render(<App />)
    expect(await screen.findByText('智能体行为管控路由')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/agents')
  })
  it('keeps the AgentGuard advanced settings route reachable', async () => {
    window.history.pushState({}, '', '/security/agents/advanced')
    render(<App />)
    expect(await screen.findByText('工程治理界面')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/agents/advanced')
  })

  it('redirects legacy MCP server route to the new MCP gateway servers page', async () => {
    window.history.pushState({}, '', '/mcp-servers')

    render(<App />)

    expect(await screen.findByText('MCP 服务管理路由')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/mcp-gateway/servers')
    expect(screen.queryByText('模型管理路由')).not.toBeInTheDocument()
  })

  // D7：控制台页面原先挂在 /mcp/* 下，与网关数据面 /mcp/{serverID} 冲突（边缘代理把整个 /mcp/ 前缀转给网关，
  // 刷新即 404）。页面迁到 /mcp-gateway/*；旧书签经边缘回落到 SPA 后在前端重定向，query 保留。
  it.each([
    ['/mcp/servers', '/mcp-gateway/servers', 'MCP 服务管理路由'],
    ['/mcp/policies', '/mcp-gateway/policies', 'MCP 调用策略路由'],
    ['/mcp/approvals', '/mcp-gateway/approvals', 'MCP 审批与例外路由'],
    ['/mcp/audit?request_id=req-1', '/mcp-gateway/audit', 'MCP 调用审计路由'],
  ])('redirects the old console bookmark %s to %s', async (from, to, label) => {
    window.history.pushState({}, '', from)
    render(<App />)
    expect(await screen.findByText(label)).toBeInTheDocument()
    expect(window.location.pathname).toBe(to)
    if (from.includes('?')) expect(window.location.search).toBe('?request_id=req-1')
  })

  it.each([
    ['/mcp-gateway/servers', 'MCP 服务管理路由'],
    ['/mcp-gateway/policies', 'MCP 调用策略路由'],
    ['/mcp-gateway/approvals', 'MCP 审批与例外路由'],
    ['/mcp-gateway/audit', 'MCP 调用审计路由'],
  ])('serves console page %s directly', async (path, label) => {
    window.history.pushState({}, '', path)
    render(<App />)
    expect(await screen.findByText(label)).toBeInTheDocument()
    expect(window.location.pathname).toBe(path)
  })

  it('redirects the removed MCP overview bookmark to call audit', async () => {
    window.history.pushState({}, '', '/mcp/overview')

    render(<App />)

    expect(await screen.findByText('MCP 调用审计路由')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/mcp-gateway/audit')
  })

  it.each(['/employee-ai-permissions', '/group-mapping-rules'])(
    'redirects removed identity route %s to organizations',
    async (path) => {
      window.history.pushState({}, '', path)

      render(<App />)

      expect(await screen.findByText('组织管理页面')).toBeInTheDocument()
      expect(window.location.pathname).toBe('/organizations')
    },
  )

  it('旧智能检测路由重定向到策略中心的检测配置', async () => {
    window.history.pushState({}, '', '/security/smart-detection')

    render(<App />)

    expect(await screen.findByText('策略中心路由')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/policies')
    expect(window.location.search).toBe('?tab=detection')
  })

  it('returns the legacy intelligent-agent risk route to behavior policies', async () => {
    window.history.pushState({}, '', '/security/agentguard')

    render(<App />)

    expect(await screen.findByText('智能体行为管控路由')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/agents')
    expect(window.location.search).toBe('')
    expect(screen.queryByText('智能体安全路由')).not.toBeInTheDocument()
    expect(screen.queryByText('策略中心路由')).not.toBeInTheDocument()
    expect(screen.queryByText('工程治理界面')).not.toBeInTheDocument()
  })

  it('routes legacy behavior section to standalone behavior page', async () => {
    window.history.pushState({}, '', '/security/policies?section=agent-behavior')

    render(<App />)

    expect(await screen.findByText('\u667a\u80fd\u4f53\u884c\u4e3a\u7ba1\u63a7\u8def\u7531')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/agents')
  })

  // W4 4.7: one canonical entry per page, the duplicate redirects.
  it.each([
    ['/connect/models', '/models'],
    ['/connect/apps', '/apps'],
    ['/proxy/settings', '/connect/network'],
    ['/proxy/reverse', '/connect/channels'],
  ])('redirects duplicate entry %s to %s', async (from, to) => {
    window.history.pushState({}, '', from)
    render(<App />)
    await vi.waitFor(() => expect(window.location.pathname).toBe(to))
  })

  // The established system-administrator contract includes audit visibility.
  it.each(['platform_admin', 'admin'])('preserves existing %s access to audit pages', async (role) => {
    mockAuth.user = { role, password_change_required: false }
    for (const path of ['/system/audit-operations', '/audit/login-history', '/audit/access-retention', '/compliance/overview']) {
      window.history.pushState({}, '', path)
      const { unmount } = render(<App />)
      await vi.waitFor(() => expect(window.location.pathname).toBe(path))
      unmount()
    }
  })

  // W4 4.2: the auditor reads audit pages and lands on operation audit.
  // 三员分立：auditor、security_officer 是控制台角色（SoD 项），不再被 App 的控制台闸门整体挡下；
  // 它们访问自己无权的页面时由 RequireRole 重定向回各自的落地页，且不渲染该页面内容。
  it('auditor is redirected away from pages outside its duty, to its own landing page', async () => {
    mockAuth.user = { role: 'auditor', password_change_required: false }
    for (const path of ['/', '/audit/login-history']) {
      window.history.pushState({}, '', path)
      const view = render(<App />)
      expect(screen.queryByText(copy.deniedHeading)).not.toBeInTheDocument()
      view.unmount()
    }
    window.history.pushState({}, '', '/security/policies')
    render(<App />)
    expect(screen.queryByText('策略中心路由')).not.toBeInTheDocument()
    expect(window.location.pathname).toBe('/system/audit-operations')
  })

  it.each([
    ['auditor', '/system/audit-operations'],
    ['security_officer', '/security/alerts'],
  ])('sends %s away from the business dashboard to its own landing page', async (role, home) => {
    mockAuth.user = { role, password_change_required: false }
    window.history.pushState({}, '', '/dashboard')
    render(<App />)
    expect(screen.queryByText('态势总览页面')).not.toBeInTheDocument()
    expect(window.location.pathname).toBe(home)
  })

  it('security_officer is redirected away from audit pages outside its duty, but opens its own', async () => {
    mockAuth.user = { role: 'security_officer', password_change_required: false }
    window.history.pushState({}, '', '/system/audit-operations')
    const view = render(<App />)
    expect(screen.queryByText('operation-audit-route')).not.toBeInTheDocument()
    expect(window.location.pathname).toBe('/security/alerts')
    view.unmount()
    window.history.pushState({}, '', '/security/alerts')
    render(<App />)
    expect(await screen.findByText('误报处理安全告警页面')).toBeInTheDocument()
  })

  it.each(['dept_manager'])('blocks persisted %s identities before scoped security pages', role => {
    mockAuth.user = { role, password_change_required: false }
    window.history.pushState({}, '', '/security/alerts')
    render(<App />)
    expect(screen.getByText(copy.deniedHeading)).toBeInTheDocument()
  })

})
