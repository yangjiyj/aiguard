import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import AgentBehaviorPolicy from '../pages/security-policy/AgentBehaviorPolicy'
import { securityPoliciesApi, type PolicyCenterAgentBehavior } from '../services/securityPoliciesApi'

vi.mock('../services/securityPoliciesApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/securityPoliciesApi')>()
  return {
    ...actual,
    securityPoliciesApi: {
      ...actual.securityPoliciesApi,
      updateAgentBehavior: vi.fn(),
    },
  }
})

const item = (overrides: Partial<PolicyCenterAgentBehavior> = {}): PolicyCenterAgentBehavior => ({
  key: 'system_command',
  label: '系统命令',
  description: 'desc',
  configured_action: 'record',
  current_action: 'record',
  health: 'ok',
  allowed_actions: ['record', 'alert_allow', 'block'],
  has_advanced_overrides: false,
  configured: true,
  version: 'v1',
  ...overrides,
})

const allItems = (sensitive: PolicyCenterAgentBehavior): PolicyCenterAgentBehavior[] => [
  item({ key: 'destructive_operation' }),
  item({ key: 'system_command' }),
  sensitive,
  item({ key: 'network_egress' }),
  item({ key: 'database_change' }),
  item({ key: 'external_tool' }),
]

const policyView = (
  items: PolicyCenterAgentBehavior[],
  canManage = true,
  loadItems = vi.fn(async () => items),
  onReload = vi.fn(),
) => (
  <MemoryRouter>
    <AgentBehaviorPolicy items={items} auditOnly={false} canManage={canManage} loadItems={loadItems} onReload={onReload} />
  </MemoryRouter>
)

const renderPolicy = (items: PolicyCenterAgentBehavior[], canManage = true) =>
  render(policyView(items, canManage))

const TEXT_LABEL = "受限文件模式"
const SAVE_LABEL = "保存受限文件配置"
const TOGGLE_LABEL = "额外禁止访问的文件"
const ACTION_LABEL = "命中后的处理动作"
const RECORD_LABEL = "仅记录"
// 2.9.22 动作标签统一到 utils/actionLabels（告警放行）。
const ALLOW_LABEL = "告警放行"
const BLOCK_LABEL = "阻断"
const CONFLICT_LABEL = "配置已被其他人修改，请确认后重试"
const CONFIRM_LABEL = "确认保存"
const READ_FAILED_LABEL = "读取最新配置失败，请稍后重试"
const SAVED_LABEL = "已保存"
const MISMATCH_LABEL = "当前配置不一致"

describe('受限文件模式配置（sensitive_resource）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('sensitive_resource 行渲染折叠区，展开后有 textarea 与审计提示', () => {
    renderPolicy(allItems(item({ key: 'sensitive_resource' })))
    const section = screen.getByTestId('restricted-file-section')
    expect(section).toBeInTheDocument()
    // 展开
    fireEvent.click(screen.getByRole('button', { name: /额外禁止访问的文件/ }))
    expect(screen.getByLabelText('受限文件模式')).toBeInTheDocument()
    expect(screen.getByText(/全局处于记录模式时只记录不阻断/)).toBeInTheDocument()
  })

  it('非 sensitive_resource 行不渲染折叠区', () => {
    renderPolicy(allItems(item({ key: 'sensitive_resource' })))
    // 只应有一个折叠区（sensitive_resource）
    expect(screen.getAllByTestId('restricted-file-section')).toHaveLength(1)
  })

  it('输入两行保存后请求体正确（拆分、去空、去重 + 动作）', async () => {
    renderPolicy(allItems(item({ key: 'sensitive_resource', version: 'v9' })))
    fireEvent.click(screen.getByRole('button', { name: /额外禁止访问的文件/ }))
    fireEvent.change(screen.getByLabelText('受限文件模式'), { target: { value: '*.pdf\n\n*.docx\n*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: '保存受限文件配置' }))
    await waitFor(() => {
      expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledWith('sensitive_resource', expect.objectContaining({
        restricted_file_patterns: ['*.pdf', '*.docx'],
        restricted_file_action: 'block',
        version: 'v9',
      }))
    })
  })

  it('前端轻校验：含空白就地报错，不发请求', async () => {
    renderPolicy(allItems(item({ key: 'sensitive_resource' })))
    fireEvent.click(screen.getByRole('button', { name: /额外禁止访问的文件/ }))
    fireEvent.change(screen.getByLabelText('受限文件模式'), { target: { value: 'my file.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: '保存受限文件配置' }))
    await waitFor(() => {
      expect(screen.getByText(/含空白字符/)).toBeInTheDocument()
    })
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
  })

  it('canManage=false 时只读，不出保存按钮', () => {
    renderPolicy(allItems(item({ key: 'sensitive_resource' })), false)
    fireEvent.click(screen.getByRole('button', { name: /额外禁止访问的文件/ }))
    expect(screen.queryByRole('button', { name: SAVE_LABEL })).not.toBeInTheDocument()
    expect(screen.getByLabelText(TEXT_LABEL)).toBeDisabled()
    for (const radio of within(screen.getByRole('radiogroup', { name: ACTION_LABEL })).getAllByRole('radio')) {
      expect(radio).toBeDisabled()
    }
  })


  it("受限文件字段保存与加载回显" + ': clean props', () => {
    const initial = allItems(item({ key: 'sensitive_resource', restricted_file_patterns: ['*.pdf'], restricted_file_action: 'block' }))
    const { rerender } = renderPolicy(initial)
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    const latest = allItems(item({ key: 'sensitive_resource', version: 'v2', restricted_file_patterns: ['*.docx'], restricted_file_action: 'alert_allow' }))
    rerender(policyView(latest))
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.docx')
    expect(within(screen.getByRole('radiogroup', { name: ACTION_LABEL })).getByRole('radio', { name: ALLOW_LABEL })).toBeChecked()
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
  })

  it("受限文件字段保存与加载回显" + ': dirty text and action', () => {
    const { rerender } = renderPolicy(allItems(item({ key: 'sensitive_resource', restricted_file_patterns: ['*.pdf'] })))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: 'contracts/**' } })
    fireEvent.click(within(screen.getByRole('radiogroup', { name: ACTION_LABEL })).getByRole('radio', { name: RECORD_LABEL }))
    rerender(policyView(allItems(item({ key: 'sensitive_resource', version: 'v2', restricted_file_patterns: ['*.docx'], restricted_file_action: 'alert_allow' }))))
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('contracts/**')
    expect(within(screen.getByRole('radiogroup', { name: ACTION_LABEL })).getByRole('radio', { name: RECORD_LABEL })).toBeChecked()
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
  })

  it("保存需回读确认" + ': new version requires confirmation', async () => {
    let server = allItems(item({ key: 'sensitive_resource', version: 'v2', configured_action: 'alert_allow', restricted_file_patterns: ['*.docx'] }))
    const loadItems = vi.fn(async () => server)
    const onReload = vi.fn()
    vi.mocked(securityPoliciesApi.updateAgentBehavior).mockImplementation(async (_key, input) => {
      server = allItems(item({ key: 'sensitive_resource', version: 'v3', configured_action: input.action, restricted_file_patterns: input.restricted_file_patterns, restricted_file_action: input.restricted_file_action }))
      return { data: {} } as never
    })
    render(policyView(allItems(item({ key: 'sensitive_resource' })), true, loadItems, onReload))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    const dialog = await screen.findByRole('dialog', { name: CONFLICT_LABEL })
    expect(within(dialog).getByText('*.docx')).toBeInTheDocument()
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: CONFIRM_LABEL }))
    // 2.9.22 起保存同时提交作用范围；后端没返回时按三项全选。
    await waitFor(() => expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledWith('sensitive_resource', {
      action: 'alert_allow', version: 'v2', restricted_file_patterns: ['*.pdf'], restricted_file_action: 'block',
      restricted_file_scopes: ['tool_call', 'user_mention', 'proxy_output'],
    }))
    expect(await screen.findByText(SAVED_LABEL)).toBeInTheDocument()
    expect(loadItems).toHaveBeenCalledTimes(3)
    expect(onReload).toHaveBeenCalledTimes(1)
  })

  it("保存需回读确认" + ': changed again before confirmation', async () => {
    let server = allItems(item({ key: 'sensitive_resource', version: 'v2', restricted_file_patterns: ['*.docx'] }))
    const loadItems = vi.fn(async () => server)
    render(policyView(allItems(item({ key: 'sensitive_resource' })), true, loadItems))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    const dialog = await screen.findByRole('dialog', { name: CONFLICT_LABEL })
    server = allItems(item({ key: 'sensitive_resource', version: 'v3', restricted_file_patterns: ['contracts/**'] }))
    fireEvent.click(within(dialog).getByRole('button', { name: CONFIRM_LABEL }))
    expect(await within(dialog).findByText('contracts/**')).toBeInTheDocument()
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
  })

  it("保存需回读确认" + ': HTTP 409', async () => {
    vi.mocked(securityPoliciesApi.updateAgentBehavior).mockRejectedValue({ response: { status: 409 } })
    renderPolicy(allItems(item({ key: 'sensitive_resource' })))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(await screen.findByText(CONFLICT_LABEL)).toBeInTheDocument()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
    expect(screen.queryByText(SAVED_LABEL)).not.toBeInTheDocument()
  })

  it("保存需回读确认" + ': read failure', async () => {
    const items = allItems(item({ key: 'sensitive_resource' }))
    const loadItems = vi.fn(async (): Promise<PolicyCenterAgentBehavior[]> => { throw new Error('unavailable') })
    render(policyView(items, true, loadItems))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(await screen.findByText(READ_FAILED_LABEL)).toBeInTheDocument()
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
  })

  it("canManage=false 时只读，不出保存按钮" + ': health error', () => {
    renderPolicy(allItems(item({ key: 'sensitive_resource', health: 'error' })))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    expect(screen.getByLabelText(TEXT_LABEL)).toBeDisabled()
    expect(screen.getByRole('button', { name: SAVE_LABEL })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
  })

  it("canManage=false 时只读，不出保存按钮" + ': latest health error', async () => {
    const latest = allItems(item({ key: 'sensitive_resource', health: 'error', health_message: 'unavailable' }))
    render(policyView(allItems(item({ key: 'sensitive_resource' })), true, vi.fn(async () => latest)))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(await screen.findByText('unavailable')).toBeInTheDocument()
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
  })

  it.each(['confirm', 'toString', 'constructor'])("canManage=false 时只读，不出保存按钮" + ': raw baseline %s disables restricted writes', (rawAction) => {
    renderPolicy(allItems(item({ key: 'sensitive_resource', configured_action: rawAction, current_action: 'unknown', raw_configured_action: rawAction })))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    expect(screen.getByLabelText(TEXT_LABEL)).toBeDisabled()
    expect(screen.getByRole('button', { name: SAVE_LABEL })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
  })

  it.each(['confirm', 'toString', 'constructor'])("canManage=false 时只读，不出保存按钮" + ': latest raw baseline %s rejects restricted writes', async (rawAction) => {
    const latest = allItems(item({ key: 'sensitive_resource', configured_action: rawAction, current_action: 'unknown', raw_configured_action: rawAction }))
    const loadItems = vi.fn(async () => latest)
    render(policyView(allItems(item({ key: 'sensitive_resource' })), true, loadItems))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    const save = screen.getByRole('button', { name: SAVE_LABEL })
    fireEvent.click(save)
    expect(await screen.findByText('该类行为状态异常，请稍后重试。')).toBeInTheDocument()
    await waitFor(() => expect(save).toBeEnabled())
    expect(loadItems).toHaveBeenCalledOnce()
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
    expect(screen.queryByText(SAVED_LABEL)).not.toBeInTheDocument()
  })

  it("canManage=false 时只读，不出保存按钮" + ': revoke while reading', async () => {
    const items = allItems(item({ key: 'sensitive_resource' }))
    let completeRead!: (items: PolicyCenterAgentBehavior[]) => void
    const loadItems = vi.fn(() => new Promise<PolicyCenterAgentBehavior[]>((resolve) => { completeRead = resolve }))
    const { rerender } = render(policyView(items, true, loadItems))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    rerender(policyView(items, false, loadItems))
    completeRead(items)
    await waitFor(() => expect(screen.getByLabelText(TEXT_LABEL)).toBeDisabled())
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
  })

  it("保存需回读确认" + ': verify before success and refresh', async () => {
    let server = allItems(item({ key: 'sensitive_resource' }))
    const loadItems = vi.fn(async () => server)
    const onReload = vi.fn()
    const { rerender } = render(policyView(server, true, loadItems, onReload))
    vi.mocked(securityPoliciesApi.updateAgentBehavior).mockImplementation(async (_key, input) => {
      server = allItems(item({ key: 'sensitive_resource', version: 'v2', restricted_file_patterns: input.restricted_file_patterns, restricted_file_action: input.restricted_file_action }))
      return { data: {} } as never
    })
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf\n*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(await screen.findByText(SAVED_LABEL)).toBeInTheDocument()
    expect(loadItems).toHaveBeenCalledTimes(2)
    expect(onReload).toHaveBeenCalledOnce()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
    const refreshed = allItems(item({ key: 'sensitive_resource', version: 'v3', restricted_file_patterns: ['*.docx'], restricted_file_action: 'record' }))
    rerender(policyView(refreshed, true, loadItems, onReload))
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.docx')
    expect(screen.queryByText(SAVED_LABEL)).not.toBeInTheDocument()
  })

  it("保存需回读确认" + ': projection mismatch is not success', async () => {
    const items = allItems(item({ key: 'sensitive_resource', restricted_file_patterns: [], restricted_file_action: 'block' }))
    const onReload = vi.fn()
    render(policyView(items, true, vi.fn(async () => items), onReload))
    vi.mocked(securityPoliciesApi.updateAgentBehavior).mockResolvedValue({ data: {} } as never)
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(await screen.findByText(MISMATCH_LABEL)).toBeInTheDocument()
    expect(screen.queryByText(SAVED_LABEL)).not.toBeInTheDocument()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
    expect(onReload).toHaveBeenCalledOnce()
  })

  it("保存需回读确认" + ': refresh failure is not success after verified write', async () => {
    let server = allItems(item({ key: 'sensitive_resource' }))
    const loadItems = vi.fn(async () => server)
    const onReload = vi.fn(() => { throw new Error('refresh failed') })
    vi.mocked(securityPoliciesApi.updateAgentBehavior).mockImplementation(async (_key, input) => {
      server = allItems(item({ key: 'sensitive_resource', version: 'v2', configured_action: input.action, restricted_file_patterns: input.restricted_file_patterns, restricted_file_action: input.restricted_file_action }))
      return { data: {} } as never
    })
    render(policyView(server, true, loadItems, onReload))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(await screen.findByText(READ_FAILED_LABEL)).toBeInTheDocument()
    expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledOnce()
    expect(loadItems).toHaveBeenCalledTimes(2)
    expect(onReload).toHaveBeenCalledOnce()
    expect(screen.queryByText(SAVED_LABEL)).not.toBeInTheDocument()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
  })

  it("保存需回读确认" + ': readback failure is not success', async () => {
    const items = allItems(item({ key: 'sensitive_resource' }))
    const loadItems = vi.fn(async () => items).mockResolvedValueOnce(items).mockRejectedValueOnce(new Error('unavailable'))
    vi.mocked(securityPoliciesApi.updateAgentBehavior).mockResolvedValue({ data: {} } as never)
    render(policyView(items, true, loadItems))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(await screen.findByText(READ_FAILED_LABEL)).toBeInTheDocument()
    expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledOnce()
    expect(screen.queryByText(SAVED_LABEL)).not.toBeInTheDocument()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
  })


  it("canManage=false 时只读，不出保存按钮" + ': query error preserves the draft', () => {
    const items = allItems(item({ key: 'sensitive_resource' }))
    const loadItems = vi.fn(async () => items)
    const view = (isError: boolean) => <MemoryRouter><AgentBehaviorPolicy items={items} auditOnly={false} canManage loadItems={loadItems} onReload={vi.fn()} isError={isError} /></MemoryRouter>
    const { rerender } = render(view(false))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    rerender(view(true))
    expect(screen.getByText("智能体行为状态读取失败")).toBeInTheDocument()
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
    expect(screen.getByLabelText(TEXT_LABEL)).toBeDisabled()
    expect(screen.getByRole('button', { name: SAVE_LABEL })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    expect(loadItems).not.toHaveBeenCalled()
    rerender(view(false))
    expect(screen.getByLabelText(TEXT_LABEL)).toHaveValue('*.pdf')
    expect(screen.getByLabelText(TEXT_LABEL)).toBeEnabled()
  })

  it('批内多项保存：destructive_operation 与 sensitive_resource 同轮修改都发出 PUT', async () => {
    const initial = [
      item({ key: 'destructive_operation', version: 'v1' }),
      item({ key: 'sensitive_resource', version: 'v1' }),
    ]
    let server = initial
    let revision = 1
    const loadItems = vi.fn(async () => server)
    const onReload = vi.fn()
    // 模拟共享版本语义：每次成功保存推进全部 agentguard 类别的版本（含 file 类的
    // destructivePolicy 组合摘要），但只改动被保存项的动作。
    vi.mocked(securityPoliciesApi.updateAgentBehavior).mockImplementation(async (key, input) => {
      revision += 1
      server = server.map((it) => ({
        ...it,
        configured_action: it.key === key ? input.action : it.configured_action,
        current_action: it.key === key ? input.action : it.current_action,
        version: `v${revision}`,
      }))
      return { data: {} } as never
    })
    render(policyView(initial, true, loadItems, onReload))
    for (const group of screen.getAllByRole('radiogroup')) {
      fireEvent.click(within(group).getByRole('radio', { name: BLOCK_LABEL }))
    }
    fireEvent.click(screen.getByRole('button', { name: '保存全部调整' }))
    fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
    await waitFor(() => expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenCalledTimes(2))
    expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenNthCalledWith(1, 'destructive_operation', { action: 'block', version: 'v1' })
    expect(securityPoliciesApi.updateAgentBehavior).toHaveBeenNthCalledWith(2, 'sensitive_resource', { action: 'block', version: 'v2' })
    expect(await screen.findByText('全部保存成功')).toBeInTheDocument()
    expect(screen.queryByText(CONFLICT_LABEL)).not.toBeInTheDocument()
    expect(onReload).toHaveBeenCalledTimes(1)
  })

  it("canManage=false 时只读，不出保存按钮" + ': repeated clicks while saving', async () => {
    const items = allItems(item({ key: 'sensitive_resource' }))
    let completeRead!: (items: PolicyCenterAgentBehavior[]) => void
    const loadItems = vi.fn(() => new Promise<PolicyCenterAgentBehavior[]>((resolve) => { completeRead = resolve }))
    render(policyView(items, true, loadItems))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(TOGGLE_LABEL) }))
    fireEvent.change(screen.getByLabelText(TEXT_LABEL), { target: { value: '*.pdf' } })
    const save = screen.getByRole('button', { name: SAVE_LABEL })
    fireEvent.click(save)
    fireEvent.click(save)
    expect(loadItems).toHaveBeenCalledOnce()
    expect(save).toBeDisabled()
    completeRead(allItems(item({ key: 'sensitive_resource', health: 'error' })))
    await waitFor(() => expect(save).toBeEnabled())
    expect(securityPoliciesApi.updateAgentBehavior).not.toHaveBeenCalled()
  })
})
