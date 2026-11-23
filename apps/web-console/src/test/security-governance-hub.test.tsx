import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import AgentBehaviorControl from '../pages/AgentBehaviorControl'
import { securityPoliciesApi } from '../services/securityPoliciesApi'
import { useAuthStore } from '../stores/auth'
import { canAccessPath } from '../utils/access'

vi.mock('../pages/agentguard/AgentRiskOverview', () => ({ default: () => <div>真实风险视图入口</div> }))
vi.mock('../pages/AgentOperationProtection', () => ({ default: () => <div>高级破坏规则入口</div> }))
vi.mock('../pages/agentguard/SequenceRuleSettings', () => ({ default: () => null }))
vi.mock('../hooks/useSecurityExecutionMode', () => ({ useSecurityExecutionMode: () => ({ mode: { effective_mode: 'protect' }, isError: false, isLoading: false }) }))
const page = (path = '/security/agents') => render(<MemoryRouter initialEntries={[path]}><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><AgentBehaviorControl /></QueryClientProvider></MemoryRouter>)

describe('Unified agent governance', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.setState({ user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' }, token: 'fixture', isAuthenticated: true })
    vi.spyOn(securityPoliciesApi, 'agentBehaviors').mockResolvedValue({ data: { items: [{ key: 'external_tool', label: 'MCP', description: '', configured_action: 'alert_allow', current_action: 'alert_allow', health: 'ok', allowed_actions: ['record', 'alert_allow', 'block'], has_advanced_overrides: false, configured: true, version: 'v1', match_scope: 'mcp_gateway', evaluation_stage: 'invocation_proposed' }] } } as never)
  })
  it('has only behavior and advanced policy tabs and leaves approvals separate', async () => {
    page()
    expect(await screen.findByRole('tab', { name: '行为策略' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: '人工确认' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: '风险态势' })).not.toBeInTheDocument()
    expect(screen.queryByText('真实风险视图入口')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: '高级规则' }))
    expect(await screen.findByText('高级破坏规则入口')).toBeInTheDocument()
  })
  it('does not expose higher privileged advanced rules to a tenant administrator', async () => {
    useAuthStore.setState({ user: { id: 'owner', username: 'owner', role: 'tenant_owner', tenant_id: 'tenant-a' } })
    page('/security/agents?tab=advanced')
    // 2.9.22 起安全员也能保存（canManageSecurityPolicy），无权角色只显示“只读”。
    expect(await screen.findByText('只读')).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: '高级规则' })).not.toBeInTheDocument()
    expect(screen.queryByText('高级破坏规则入口')).not.toBeInTheDocument()
  })
  it('removes obsolete overview query state and shows behavior policies', async () => {
    page('/security/agents?tab=overview')
    expect(await screen.findByRole('tab', { name: '行为策略' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByRole('tab', { name: '风险态势' })).not.toBeInTheDocument()
    expect(screen.queryByText('真实风险视图入口')).not.toBeInTheDocument()
  })
  it('shows MCP as admission allow/disable and never promises a managed-risk notification', async () => {
    page()
    const group = await screen.findByRole('radiogroup', { name: '调用外部工具处理方式' })
    expect(within(group).getByRole('radio', { name: '允许' })).toBeInTheDocument()
    expect(within(group).getByRole('radio', { name: '禁用' })).toBeInTheDocument()
    expect(within(group).queryByRole('radio', { name: '风险告警并放行' })).not.toBeInTheDocument()
    expect(screen.getByText('MCP 基础准入')).toBeInTheDocument()
    expect(screen.queryByText('策略与执行分开看')).not.toBeInTheDocument()
  })
  // 2.9.22 起安全员要在 Skill 页改 Skill 调用防护（后端 Skill 接口是 SoDSecurityConfigRead / SoDSecurityWrite，安全员可用）。
  it('aligns Skill routes with the actual backend administrator roles', () => {
    for (const role of ['platform_admin', 'admin', 'tenant_owner', 'tenant_admin', 'security_officer']) expect(canAccessPath(role, '/security/skills')).toBe(true)
    for (const role of ['auditor', 'viewer']) expect(canAccessPath(role, '/security/skills')).toBe(false)
  })
})
