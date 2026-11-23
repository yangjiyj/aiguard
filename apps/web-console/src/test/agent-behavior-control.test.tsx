import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AgentBehaviorControl from '../pages/AgentBehaviorControl'
import api from '../services/api'
import { securityPoliciesApi, type PolicyCenterAgentBehaviorAction } from '../services/securityPoliciesApi'
import { useAuthStore } from '../stores/auth'

const KEYS = [
  'destructive_operation',
  'system_command',
  'sensitive_resource',
  'network_egress',
  'database_change',
  'external_tool',
]

const LABELS: Record<string, string> = {
  destructive_operation: '删除与破坏',
  system_command: '系统命令',
  sensitive_resource: '敏感资源访问',
  network_egress: '网络外联',
  database_change: '数据库变更',
  external_tool: '外部工具（MCP）',
}

function makeItems(actions: Record<string, PolicyCenterAgentBehaviorAction>, version: string) {
  return KEYS.map((key) => ({
    key,
    label: LABELS[key],
    description: `${LABELS[key]}的处理动作`,
    configured_action: actions[key],
    current_action: actions[key],
    health: 'ok' as const,
    allowed_actions: ['record', 'alert_allow', 'block'] as PolicyCenterAgentBehaviorAction[],
    has_advanced_overrides: key === 'external_tool',
    configured: true,
    version,
  }))
}

describe('AgentBehaviorControl', () => {
  let actions: Record<string, PolicyCenterAgentBehaviorAction>
  let version: number

  beforeEach(() => {
    vi.restoreAllMocks()
    actions = Object.fromEntries(KEYS.map((key) => [key, 'record'])) as Record<string, PolicyCenterAgentBehaviorAction>
    version = 1
    useAuthStore.setState({
      token: 'test-token',
      user: { id: 'admin-1', username: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' },
      isAuthenticated: true,
    })
    vi.spyOn(api, 'get').mockResolvedValue({ data: { security_execution_mode: { configured_mode: 'protect', effective_mode: 'protect', locked: false, source: 'admin_settings', runtime_verified: true, runtime_status: 'verified' } } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(securityPoliciesApi, 'agentBehaviors').mockImplementation(async () => ({
      data: { items: makeItems(actions, `v${version}`) },
    } as never))
    vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockImplementation(async (key, input) => {
      actions[key] = input.action
      version += 1
      return { data: {} } as never
    })
  })

  const renderPage = () => render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        <AgentBehaviorControl />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('管理员手工调整后按最新版本保存，不出现推荐入口也不改全局模式', async () => {
    const user = userEvent.setup()
    renderPage()

    const systemGroup = await screen.findByRole('radiogroup', { name: '系统命令处理方式' })
    const blockAction = within(systemGroup).getByRole('radio', { name: '阻断' })
    expect(screen.queryByRole('button', { name: '采用推荐方案' })).not.toBeInTheDocument()
    await waitFor(() => expect(blockAction).toBeEnabled())
    fireEvent.click(blockAction)
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: '保存全部调整' }))
    await user.click(screen.getByRole('button', { name: '确认保存' }))

    await waitFor(() => expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledWith(
      'system_command',
      { action: 'block', version: 'v1' },
    ))
    expect(api.put).not.toHaveBeenCalled()
  })

  it('管理员手工调整后按最新版本保存，不出现推荐入口也不改全局模式' + ': refresh failure is not success', async () => {
    const user = userEvent.setup()
    let readsAfterWrite = 0
    vi.mocked(securityPoliciesApi.agentBehaviors).mockImplementation(async () => {
      if (version > 1 && ++readsAfterWrite > 1) throw new Error('refresh failed')
      return { data: { items: makeItems(actions, `v${version}`) } } as never
    })
    renderPage()
    const group = await screen.findByRole('radiogroup', { name: '系统命令处理方式' })
    const blockAction = within(group).getByRole('radio', { name: '阻断' })
    await waitFor(() => expect(blockAction).toBeEnabled())
    fireEvent.click(blockAction)
    await user.click(screen.getByRole('button', { name: '保存全部调整' }))
    await user.click(screen.getByRole('button', { name: '确认保存' }))
    expect(await screen.findByText('部分调整未保存')).toBeInTheDocument()
    expect(screen.queryByText('全部保存成功')).not.toBeInTheDocument()
    expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledOnce()
    expect(readsAfterWrite).toBe(2)
  })

  it('只重试失败的行为', async () => {
    const user = userEvent.setup()
    let failOnce = true
    vi.mocked(securityPoliciesApi.updateAgentBehavior).mockImplementation(async (key, input) => {
      if (key === 'network_egress' && failOnce) {
        failOnce = false
        throw new Error('temporary')
      }
      actions[key] = input.action
      version += 1
      return { data: {} } as never
    })
    renderPage()

    const networkGroup = await screen.findByRole('radiogroup', { name: '访问外部网络处理方式' })
    const auditAction = within(networkGroup).getByRole('radio', { name: '风险告警并放行' })
    await waitFor(() => expect(auditAction).toBeEnabled())
    fireEvent.click(auditAction)
    await user.click(screen.getByRole('button', { name: '保存全部调整' }))
    await user.click(screen.getByRole('button', { name: '确认保存' }))

    expect(await screen.findByText('部分调整未保存')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试未保存项' }))
    expect(await screen.findByText('访问外部网络：仅记录 -> 风险告警并放行')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认保存' }))

    await waitFor(() => expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledTimes(2))
    expect(vi.mocked(securityPoliciesApi.updateAgentBehavior).mock.calls.map(([key]) => key)).toEqual([
      'network_egress',
      'network_egress',
    ])
  })

  const renderAt = (path: string) => render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <AgentBehaviorControl />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('从阻断记录跳来时定位到对应行为', async () => {
    renderAt('/security/agents?behavior=system_command')
    await screen.findByRole('radiogroup', { name: '系统命令处理方式' })
    expect(document.getElementById('agent-behavior-system_command')).toHaveClass('is-focused')
    expect(document.getElementById('agent-behavior-network_egress')).not.toHaveClass('is-focused')
  })

  it('行为参数不认识时不聚焦也不报错', async () => {
    renderAt('/security/agents?behavior=no_such_behavior')
    await screen.findByRole('radiogroup', { name: '系统命令处理方式' })
    expect(document.querySelector('.is-focused')).toBeNull()
  })
})
