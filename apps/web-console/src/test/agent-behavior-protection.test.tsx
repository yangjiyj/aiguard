import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AgentBehaviorControl from '../pages/AgentBehaviorControl'
import api, { agentGuardApi } from '../services/api'
import { securityPoliciesApi, type PolicyCenterAgentBehavior } from '../services/securityPoliciesApi'
import { useAuthStore } from '../stores/auth'
import { canManageSecurityPolicy } from '../utils/access'
import { chooseOption, PROTECTION_ITEMS } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }
})

const BEHAVIOR_KEYS = ['destructive_operation', 'system_command', 'sensitive_resource', 'network_egress', 'database_change', 'external_tool']

function behaviors(): PolicyCenterAgentBehavior[] {
  return BEHAVIOR_KEYS.map((key) => ({
    key,
    label: key,
    description: key,
    configured_action: 'alert_allow',
    current_action: 'alert_allow',
    health: 'ok',
    allowed_actions: ['record', 'alert_allow', 'block'],
    has_advanced_overrides: false,
    configured: true,
    version: 'v1',
    ...(key === 'sensitive_resource' ? { restricted_file_patterns: ['*.pdf'], restricted_file_action: 'block' as const } : {}),
  })) as PolicyCenterAgentBehavior[]
}

function setRole(role: string) {
  useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role, tenant_id: 'tenant-a' }, isAuthenticated: true })
}

function renderPage(entry = '/security/agents') {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        <AgentBehaviorControl />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('智能体行为页：防护项卡片', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    setRole('platform_admin')
    vi.spyOn(api, 'get').mockImplementation(async (url: string) => {
      if (url === '/protection-settings') return { data: { items: PROTECTION_ITEMS } } as never
      if (url === '/agentguard/exceptions') return { data: { data: [{ id: 'e1', rule_id: 'agent.ssh_private_key', enabled: true }, { id: 'e2', rule_id: 'agent.ssh_private_key', enabled: false }] } } as never
      return { data: { security_execution_mode: { configured_mode: 'protect', effective_mode: 'protect', locked: false, source: 'admin_settings', runtime_verified: true, runtime_status: 'verified' } } } as never
    })
    vi.spyOn(api, 'put').mockImplementation(async () => ({ data: { items: PROTECTION_ITEMS } } as never))
    vi.spyOn(securityPoliciesApi, 'agentBehaviors').mockImplementation(async () => ({ data: { items: behaviors() } } as never))
    vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockResolvedValue({ data: {} } as never)
  })

  it('平台管理员与安全员能改安全设置，审计员与租户管理员不能', () => {
    expect(canManageSecurityPolicy('platform_admin')).toBe(true)
    expect(canManageSecurityPolicy('security_officer')).toBe(true)
    expect(canManageSecurityPolicy('auditor')).toBe(false)
    expect(canManageSecurityPolicy('tenant_admin')).toBe(false)
    expect(canManageSecurityPolicy(undefined)).toBe(false)
  })

  it('三张卡片按分组显示，改动作即调用防护项接口', async () => {
    renderPage()
    expect(await screen.findByRole('table', { name: '敏感目标' })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: '兜底判定' })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: '端侧内置规则' })).toBeInTheDocument()
    expect(screen.getByText('和上面的分类卡片取严')).toBeInTheDocument()
    // Skill、MCP 组不放在这个页面。
    expect(screen.queryByText('Skill 身份异常')).not.toBeInTheDocument()

    const sshRow = (await screen.findByText('SSH 私钥')).closest('tr') as HTMLElement
    expect(within(sshRow).getByText('1 条')).toBeInTheDocument()
    await chooseOption(within(sshRow).getByRole('combobox', { name: 'SSH 私钥动作' }), '阻断')
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', {
      items: { 'agent.ssh_private_key': { action: 'block', params: {} } },
    }))
  })

  it('改参数在离开输入框时保存，带上该项全部参数', async () => {
    const user = userEvent.setup()
    renderPage()
    const input = await screen.findByRole('spinbutton', { name: '工具连续失败窗口（秒）' })
    await user.clear(input)
    await user.type(input, '300')
    fireEvent.blur(input)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', {
      items: { 'agent.tool_failure_loop': { action: 'alert_allow', params: { window_seconds: 300, threshold: 5 } } },
    }))
  })

  it('安全员可以改', async () => {
    setRole('security_officer')
    renderPage()
    const select = await screen.findByRole('combobox', { name: 'SSH 私钥动作' })
    await waitFor(() => expect(select).toBeEnabled())
    expect(screen.queryByText('只读')).not.toBeInTheDocument()
  })

  it('租户管理员只读：动作、参数、加例外都不可用', async () => {
    setRole('tenant_admin')
    renderPage()
    const select = await screen.findByRole('combobox', { name: 'SSH 私钥动作' })
    expect(select).toBeDisabled()
    expect(screen.getByRole('spinbutton', { name: '工具连续失败窗口（秒）' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'SSH 私钥加例外' })).toBeDisabled()
    expect(screen.getByText('只读')).toBeInTheDocument()
    expect(api.put).not.toHaveBeenCalled()
  })

  it('从拦截记录跳来：高亮该行，加例外预填原因码和目标，可选长期', async () => {
    const user = userEvent.setup()
    const create = vi.spyOn(agentGuardApi, 'createException').mockResolvedValue({ data: {} } as never)
    renderPage('/security/agents?protection=agent.high_risk_without_rule&rule=blocked_destructive_sql&target=db.query')
    const label = await screen.findByText('未配置规则的高风险调用')
    const row = label.closest('tr') as HTMLElement
    expect(row).toHaveClass('is-focused')
    expect(row).toHaveAttribute('id', 'protection-item-agent.high_risk_without_rule')

    await user.click(within(row).getByRole('button', { name: '未配置规则的高风险调用加例外' }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('blocked_destructive_sql')
    expect(screen.getByLabelText('目标匹配')).toHaveValue('db.query')
    await user.click(screen.getByRole('checkbox', { name: '长期' }))
    await user.type(screen.getByLabelText('审批原因'), '业务必需')
    await user.click(screen.getByRole('button', { name: '创建例外' }))
    await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
      scope_type: 'tenant',
      rule_id: 'blocked_destructive_sql',
      target_pattern: 'db.query',
      expires_at: '9999-12-31T00:00:00Z',
    })))
  })

  it('文件类防护项加例外：关联规则预填防护项键，目标写法有说明', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: 'SSH 私钥加例外' }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('agent.ssh_private_key')
    expect(screen.getByText(/不含 \/ 只比文件名/)).toBeInTheDocument()
  })

  it('?protection_group 定位到敏感目标卡片', async () => {
    renderPage('/security/agents?protection_group=agent_target')
    await screen.findByRole('table', { name: '敏感目标' })
    expect(document.getElementById('protection-group-agent_target')).toHaveClass('is-focused')
  })

  it('?protection=agent.restricted_file 展开受限文件区块；作用范围默认三项，可改并保存', async () => {
    const user = userEvent.setup()
    renderPage('/security/agents?protection=agent.restricted_file')
    const section = await screen.findByTestId('restricted-file-section')
    await waitFor(() => expect(section).toHaveClass('is-focused'))
    const proxyOutput = await within(section).findByRole('checkbox', { name: '代理输出' })
    expect(within(section).getByRole('checkbox', { name: '工具调用' })).toBeChecked()
    expect(within(section).getByRole('checkbox', { name: '用户输入' })).toBeChecked()
    await waitFor(() => expect(proxyOutput).toBeEnabled())
    await user.click(proxyOutput)
    await user.click(within(section).getByRole('button', { name: '保存受限文件配置' }))
    await waitFor(() => expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledWith('sensitive_resource', expect.objectContaining({
      restricted_file_scopes: ['tool_call', 'user_mention'],
    })))
    expect(within(section).getByRole('button', { name: '加例外' })).toBeInTheDocument()
  })
})
