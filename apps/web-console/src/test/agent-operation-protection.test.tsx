import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import AgentOperationProtection from '../pages/AgentOperationProtection'
import { agentApi, agentOperationProtectionApi, projectApi, tenantApi } from '../services/api'

const { mockAuth } = vi.hoisted(() => ({ mockAuth: { user: { role: 'platform_admin', tenant_id: 'tenant-a' } as any } }))

vi.mock('../services/api', () => ({
  agentApi: { list: vi.fn() },
  agentOperationProtectionApi: { getPolicy: vi.fn(), updatePolicy: vi.fn(), listEvents: vi.fn() },
  projectApi: { list: vi.fn() },
  tenantApi: { list: vi.fn() },
}))
vi.mock('../stores/auth', () => ({
  useAuthStore: (selector: (state: typeof mockAuth) => unknown) => selector(mockAuth),
}))
const renderPage = () => render(<MemoryRouter><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><AgentOperationProtection /></QueryClientProvider></MemoryRouter>)

describe('AgentOperationProtection', () => {
  beforeEach(() => {
    mockAuth.user = { role: 'platform_admin', tenant_id: 'tenant-a' }
    vi.mocked(tenantApi.list).mockResolvedValue({ data: { data: [
      { id: 'tenant-a', name: '本租户', status: 'active' },
      { id: 'tenant-b', name: '研发租户', status: 'active' },
    ] } } as never)
    vi.mocked(projectApi.list).mockResolvedValue({ data: { data: [{ id: 'project-1', name: '研发助手', status: 'active' }] } } as never)
    vi.mocked(agentApi.list).mockResolvedValue({ data: { data: [{ agent_type: 'openai-codex' }] } } as never)
    vi.mocked(agentOperationProtectionApi.listEvents).mockResolvedValue({ data: { items: [{
      public_event_id: 'evt_public_1', operation_id: 'op_1', protocol: 'responses', tool_name: 'shell_command',
      target_summary: 'filesystem_delete:1-targets', confidence: 1, status_code: 'blocked', status_label: 'blocked',
      current_action: 'block', notification_code: 'delivered', created_at: '2026-07-31T10:00:00Z',
    }], total: 1, limit: 20, offset: 0 } } as never)
    vi.mocked(agentOperationProtectionApi.updatePolicy).mockResolvedValue({ data: {} } as never)
    vi.mocked(agentOperationProtectionApi.getPolicy).mockImplementation(async (params) => ({ data: {
      tenant_scope: params?.tenant_scope || 'all',
      tenant_id: params?.tenant_id,
      scope_type: params?.scope_type || 'tenant',
      scope_ref: params?.scope_ref || '',
      mode: 'light',
      action: 'alert_allow',
      protocol: '',
      mode_default_action: 'alert_allow',
      current_action: 'alert_allow',
      config_source: 'tenant_policy',
      discardable_paths: ['node_modules', 'dist'],
      notify_channel_ids: ['channel-a'],
      channels: [{ id: 'channel-a', name: 'security', type: 'webhook', enabled: true }],
      version: params?.scope_type === 'tenant' ? 3 : 1,
      updated_at: '2026-07-31T10:00:00Z',
    } } as never))
  })

  it('shows controls, capability limits, evidence wording, and public status', async () => {
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText('控制对象：拟调用')).toBeInTheDocument()
    for (const label of ['审计：仅记录', '轻管理：告警并放行', '严格管控：阻断']) expect(screen.getByText(label)).toBeInTheDocument()
    expect(await screen.findByText('所有租户')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '跟随模式' })).toBeChecked()
    expect(screen.getByText('端侧执行：未知')).toBeInTheDocument()
    expect(await screen.findByText('已阻断')).toBeInTheDocument()
    expect(screen.queryByText('evt_public_1')).not.toBeInTheDocument()
    expect(screen.queryByText('op_1')).not.toBeInTheDocument()
    expect(screen.getByText('最近操作记录')).toBeInTheDocument()
    expect(screen.getByText('删除文件')).toBeInTheDocument()
    expect(screen.getByText('识别到 1 个目标；具体路径未提供')).toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: '跟随模式' }))
    // 2.9.22：确认不再只限 MCP 协议，租户作用域、通用模型客户端也可选。
    expect(screen.getByRole('radio', { name: '确认后执行' })).toBeEnabled()
    await user.click(screen.getByRole('switch', { name: '跟随模式' }))
    await user.click(screen.getByRole('button', { name: /保存策略/ }))
    expect(agentOperationProtectionApi.updatePolicy).toHaveBeenCalledWith(expect.objectContaining({ tenant_scope: 'all', mode: 'light', action: 'alert_allow', version: 3 }))
  })

  it('非 MCP 协议也能选“确认后执行”，保存不再强改为 MCP', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('所有租户')
    await user.click(screen.getByRole('switch', { name: '跟随模式' }))
    await user.click(screen.getByRole('radio', { name: '确认后执行' }))
    await user.click(screen.getByRole('button', { name: /保存策略/ }))
    await waitFor(() => expect(agentOperationProtectionApi.updatePolicy).toHaveBeenLastCalledWith(expect.objectContaining({ action: 'confirm', protocol: '' })))
  })

  it('uses business names for application and agent scopes instead of identifier inputs', async () => {
    const user = userEvent.setup()
    mockAuth.user = { role: 'tenant_admin', tenant_id: 'tenant-a' }
    renderPage()

    const scopeSelect = screen.getByRole('combobox', { name: '作用域' })
    await user.click(scopeSelect)
    await user.click(screen.getByText('应用', { exact: true }))

    expect(screen.queryByText('应用标识')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /保存策略/ })).toBeDisabled()
    const applicationSelect = screen.getByRole('combobox', { name: '应用' })
    await user.click(applicationSelect)
    await user.click(screen.getByText('研发助手', { exact: true }))
    await waitFor(() => expect(agentOperationProtectionApi.getPolicy).toHaveBeenLastCalledWith(expect.objectContaining({ tenant_scope: 'tenant', tenant_id: 'tenant-a', scope_type: 'application', scope_ref: 'project-1' })))

    await user.click(screen.getByRole('button', { name: /保存策略/ }))
    expect(agentOperationProtectionApi.updatePolicy).toHaveBeenLastCalledWith(expect.objectContaining({ scope_type: 'application', scope_ref: 'project-1' }))

    await user.click(scopeSelect)
    await user.click(screen.getByText('Agent', { exact: true }))
    expect(screen.queryByText('Agent 标识')).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '智能体类型' })).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '智能体类型' }))
    expect(await screen.findByText('OpenAI Codex', { exact: true })).toBeInTheDocument()
  })

  it('supports tenant switching and persists all Agent as a wildcard', async () => {
    const user = userEvent.setup()
    mockAuth.user = { role: 'platform_admin', tenant_id: 'tenant-a' }
    renderPage()

    const tenantSelect = screen.getByRole('combobox', { name: '目标租户' })
    await user.click(tenantSelect)
    await user.click(await screen.findByText('研发租户', { exact: true }))
    await waitFor(() => expect(agentOperationProtectionApi.getPolicy).toHaveBeenLastCalledWith(expect.objectContaining({ tenant_scope: 'tenant', tenant_id: 'tenant-b' })))

    const scopeSelect = screen.getByRole('combobox', { name: '作用域' })
    await user.click(scopeSelect)
    await user.click(screen.getByText('Agent', { exact: true }))
    const agentSelect = screen.getByRole('combobox', { name: '智能体类型' })
    await user.click(agentSelect)
    await user.click(await screen.findByText('所有 Agent', { exact: true }))
    await user.click(screen.getByRole('button', { name: /保存策略/ }))
    expect(agentOperationProtectionApi.updatePolicy).toHaveBeenLastCalledWith(expect.objectContaining({
      tenant_scope: 'tenant', tenant_id: 'tenant-b', scope_type: 'agent', scope_ref: '*',
    }))
  })
  it('keeps technical identifiers and request evidence in the details drawer', async () => {
    vi.mocked(agentOperationProtectionApi.listEvents).mockResolvedValue({ data: { items: [{ public_event_id: 'evt_exact', operation_id: 'op_exact', request_id: 'request/with-space', trace_id: 'trace_exact', protocol: 'messages', tool_name: 'shell_command', target_summary: 'filesystem_overwrite:2-targets', confidence: .85, status_code: 'execution_forwarded', current_action: 'record', notification_code: 'delivered', created_at: '2026-10-04T00:00:00Z' }], total: 1 } } as never)
    renderPage()
    expect(await screen.findByText('覆盖文件')).toBeInTheDocument()
    expect(screen.getByText('网关已转发')).toBeInTheDocument()
    expect(screen.queryByText('已转发执行')).not.toBeInTheDocument()
    expect(screen.queryByText('evt_exact')).not.toBeInTheDocument()
    expect(screen.queryByText('op_exact')).not.toBeInTheDocument()
    expect(screen.queryByText('Claude Messages')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByText('evt_exact')).toBeInTheDocument()
    expect(screen.getByText('op_exact')).toBeInTheDocument()
    expect(screen.getByText('Claude Messages')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '查看请求记录' })).toHaveAttribute('href', '/audit/access-retention?request_id=request%2Fwith-space')
    expect(screen.queryByText('执行成功')).not.toBeInTheDocument()
  })
  it('keeps unknown processing states unknown even when configuration says record', async () => {
    vi.mocked(agentOperationProtectionApi.listEvents).mockResolvedValue({ data: { items: [{ public_event_id: 'evt_unknown', operation_id: 'op_unknown', protocol: 'new-protocol', tool_name: 'unregistered', target_summary: 'target-incomplete', status_code: 'unrecognized', current_action: 'record', created_at: '' }], total: 1 } } as never)
    renderPage()
    expect(await screen.findByText('处理结果待确认')).toBeInTheDocument()
    expect(screen.getByText('目标信息不完整')).toBeInTheDocument()
    expect(screen.getByText('时间未记录')).toBeInTheDocument()
    expect(screen.queryByText('已记录')).not.toBeInTheDocument()
  })
  it('reads an authenticated known target-summary category without claiming completed damage', async () => {
    vi.mocked(agentOperationProtectionApi.listEvents).mockResolvedValue({ data: { items: [{ public_event_id: 'evt_database', operation_id: 'op_database', protocol: 'responses', tool_name: 'Bash', subcategory_code: 'other', target_summary: 'database_destroy:3-targets', status_code: 'recorded', current_action: 'record', created_at: '2026-10-04T00:00:00Z' }], total: 1 } } as never)
    renderPage()
    expect(await screen.findByText('删除数据库对象')).toBeInTheDocument()
    expect(screen.getByText('识别到 3 个目标；具体路径未提供')).toBeInTheDocument()
    expect(screen.queryByText('已删除 3 个数据库')).not.toBeInTheDocument()
  })

  // Low-1：被停用的策略不能被显示成「未配置」的默认值。
  it('shows a disabled saved policy as disabled instead of presenting the defaults', async () => {
    vi.mocked(agentOperationProtectionApi.getPolicy).mockResolvedValue({ data: {
      tenant_scope: 'all', scope_type: 'tenant', scope_ref: '', mode: 'strict', action: 'block', protocol: '',
      mode_default_action: 'block', current_action: 'block', config_source: 'tenant', configured: true, enabled: false,
      discardable_paths: ['dist'], notify_channel_ids: [], channels: [], version: 4, updated_at: '2026-07-31T10:00:00Z',
    } } as never)
    renderPage()
    expect(await screen.findByText('该范围的策略已停用')).toBeInTheDocument()
    expect(screen.getByText(/停用前保存的是「严格管控：阻断」/)).toBeInTheDocument()
    expect(screen.queryByText('该范围尚未配置，当前显示系统默认值')).not.toBeInTheDocument()
  })

  it('labels a never-configured scope as using the system defaults', async () => {
    vi.mocked(agentOperationProtectionApi.getPolicy).mockResolvedValue({ data: {
      tenant_scope: 'all', scope_type: 'tenant', scope_ref: '', mode: 'audit', action: 'record', protocol: '',
      mode_default_action: 'record', current_action: 'record', config_source: 'new_scope', configured: false, enabled: true,
      discardable_paths: [], notify_channel_ids: [], channels: [], version: 1, updated_at: '',
    } } as never)
    renderPage()
    expect(await screen.findByText('该范围尚未配置，当前显示系统默认值')).toBeInTheDocument()
    expect(screen.queryByText('该范围的策略已停用')).not.toBeInTheDocument()
  })

  it('shows no state banner for a normally enabled saved policy', async () => {
    renderPage()
    await screen.findByText('所有租户')
    expect(screen.queryByText('该范围的策略已停用')).not.toBeInTheDocument()
    expect(screen.queryByText('该范围尚未配置，当前显示系统默认值')).not.toBeInTheDocument()
  })
})
