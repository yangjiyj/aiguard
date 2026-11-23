import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import AgentBehaviorPolicy from '../pages/security-policy/AgentBehaviorPolicy'
import { securityPoliciesApi, type PolicyCenterAgentBehavior } from '../services/securityPoliciesApi'

const behavior = (overrides: Partial<PolicyCenterAgentBehavior> = {}): PolicyCenterAgentBehavior => ({
  key: 'system_command',
  label: '系统命令',
  description: '管理智能体调用系统命令工具时的处理动作',
  configured_action: 'record',
  current_action: 'record',
  health: 'ok',
  allowed_actions: ['record', 'alert_allow', 'block'],
  has_advanced_overrides: false,
  configured: true,
  version: 'version-1',
  ...overrides,
})

const ITEMS = [
  behavior({ key: 'destructive_operation', label: '删除与破坏', configured_action: 'block', current_action: 'block' }),
  behavior(),
  behavior({ key: 'sensitive_resource', label: '敏感资源访问', configured_action: 'alert_allow' }),
  behavior({ key: 'network_egress', label: '网络外联', has_advanced_overrides: true }),
  behavior({ key: 'database_change', label: '数据库变更' }),
  behavior({ key: 'external_tool', label: '外部工具（MCP）' }),
]

const renderPage = (items: PolicyCenterAgentBehavior[] = ITEMS, canManage = true, auditOnly = false) => render(
  <MemoryRouter>
    <AgentBehaviorPolicy
      items={items}
      auditOnly={auditOnly}
      canManage={canManage}
      loadItems={async () => items}
      onReload={vi.fn()}
    />
  </MemoryRouter>,
)

const GROUP_LABEL = "系统命令处理方式"
const BLOCK_LABEL = "阻断"
const ALLOW_LABEL = '\u98ce\u9669\u544a\u8b66\u5e76\u653e\u884c'
const EXTERNAL_BLOCK_LABEL = '\u7981\u7528'
const EXTERNAL_ALLOW_LABEL = '\u5141\u8bb8'
const MODE_PREFIX = '\u5f53\u524d\u5168\u5c40\u6a21\u5f0f\u4e0b'
const BASELINE_PREFIX = '\u57fa\u7ebf\u52a8\u4f5c'
const GLOBAL_RECORD_LABEL = '\u5168\u5c40\u6267\u884c\uff1a\u4ec5\u8bb0\u5f55'
const GLOBAL_RECORD_LINK_LABEL = '\u884c\u4e3a\u8bb0\u5f55'
const MCP_NOTE_LABEL = 'MCP \u5904\u7f6e\uff1a\u653e\u884c\u6216\u963b\u65ad'
const SEPARATOR = '\uff1a'
const RECORD_LABEL = "仅记录"
const SAVE_LABEL = "保存全部调整"
const CONFIRM_LABEL = "确认保存"
const CONFLICT_LABEL = "配置已被其他人修改，请确认后重试"
const UNKNOWN_LABEL = "实际处理待确认"
const ADVANCED_LABEL = "按单独规则处理"
const READ_FAILED_LABEL = "读取最新配置失败，请稍后重试"
const RETRY_LABEL = "重试未保存项"

describe('智能体行为配置', () => {
  it('external_tool effective Record is distinct from base admission', () => {
    renderPage([behavior({ key: 'external_tool', configured_action: 'block', current_action: 'block' })], false, true)
    expect(screen.getByText(`${BASELINE_PREFIX}${SEPARATOR}${EXTERNAL_BLOCK_LABEL}`)).toBeInTheDocument()
    expect(screen.getByText(`${MODE_PREFIX}${SEPARATOR}${RECORD_LABEL}`)).toBeInTheDocument()
    expect(screen.queryByText(`${MODE_PREFIX}${SEPARATOR}${EXTERNAL_ALLOW_LABEL}`)).not.toBeInTheDocument()
    for (const group of screen.getAllByRole('radiogroup')) {
      expect(group).toHaveClass('ant-segmented-disabled')
    }
    expect(screen.queryByRole('button', { name: SAVE_LABEL })).not.toBeInTheDocument()
  })

  it('显示六类可读行为和配置与实际动作，不提供推荐方案', () => {
    renderPage()

    for (const label of ['删除与破坏', '系统命令', "文件工具访问", '访问外部网络', "数据库工具调用", '调用外部工具']) {
      expect(screen.getByRole('heading', { name: label })).toBeInTheDocument()
    }
    expect(screen.getByText(`${BASELINE_PREFIX}${SEPARATOR}${ALLOW_LABEL}`)).toBeInTheDocument()
    expect(screen.getAllByText("当前全局模式下：仅记录").length).toBeGreaterThan(0)
    expect(screen.getByText('部分工具有单独处理方式')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '采用推荐方案' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '查看单独调整' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: '查看行为记录' }).length).toBeGreaterThan(0)
    expect(screen.queryByRole('link', { name: '查看智能体行为命中' })).not.toBeInTheDocument()
  })

  it('只锁定状态异常的行为', () => {
    renderPage([
      behavior({ health: 'error', health_message: '行为状态暂时不可用' }),
      behavior({ key: 'network_egress' }),
    ])

    expect(screen.getByText('行为状态暂时不可用')).toBeInTheDocument()
    expect(screen.getByRole('radiogroup', { name: '系统命令处理方式' })).toHaveClass('ant-segmented-disabled')
    expect(screen.getByRole('radiogroup', { name: '访问外部网络处理方式' })).not.toHaveClass('ant-segmented-disabled')
  })

  it('记录模式如实显示实际处理且只读账号不能修改', () => {
    renderPage(ITEMS, false, true)

    expect(screen.getByText(GLOBAL_RECORD_LABEL)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: GLOBAL_RECORD_LINK_LABEL })).toHaveAttribute('href', '/audit/access-retention?view=requests')
    const recordLinks = screen.getAllByRole('link', { name: '查看行为记录' })
    expect(recordLinks).toHaveLength(6)
    for (const link of recordLinks) expect(link).toHaveAttribute('href', '/audit/access-retention?view=requests')
    expect(screen.getAllByText(`${MODE_PREFIX}${SEPARATOR}${RECORD_LABEL}`)).toHaveLength(6)
    expect(screen.queryByRole('button', { name: '保存全部调整' })).not.toBeInTheDocument()
    for (const group of screen.getAllByRole('radiogroup')) {
      expect(group).toHaveClass('ant-segmented-disabled')
    }
  })


  it("受限文件字段保存与加载回显" + ': base action clean and dirty', () => {
    const initial = [behavior()]
    const view = (items: PolicyCenterAgentBehavior[]) => <MemoryRouter><AgentBehaviorPolicy items={items} auditOnly={false} canManage loadItems={async () => items} onReload={vi.fn()} /></MemoryRouter>
    const { rerender } = render(view(initial))
    const group = screen.getByRole('radiogroup', { name: GROUP_LABEL })
    fireEvent.click(within(group).getByRole('radio', { name: BLOCK_LABEL }))
    rerender(view([behavior({ configured_action: 'alert_allow', current_action: 'alert_allow', version: 'version-2' })]))
    expect(within(group).getByRole('radio', { name: BLOCK_LABEL })).toBeChecked()
    fireEvent.click(within(group).getByRole('radio', { name: ALLOW_LABEL }))
    rerender(view([behavior({ configured_action: 'record', current_action: 'record', version: 'version-3' })]))
    expect(within(group).getByRole('radio', { name: RECORD_LABEL })).toBeChecked()
  })

  it("保存需回读确认" + ': base action version changed', async () => {
    let latest = [behavior({ version: 'version-2', configured_action: 'alert_allow', current_action: 'alert_allow' })]
    const loadItems = vi.fn(async () => latest)
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockImplementation(async (_key, input) => {
      latest = [behavior({ version: 'version-3', configured_action: input.action, current_action: input.action })]
      return { data: {} } as never
    })
    render(<MemoryRouter><AgentBehaviorPolicy items={[behavior()]} auditOnly={false} canManage loadItems={loadItems} onReload={vi.fn()} /></MemoryRouter>)
    fireEvent.click(within(screen.getByRole('radiogroup', { name: GROUP_LABEL })).getByRole('radio', { name: BLOCK_LABEL }))
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
    expect(await screen.findByText(CONFLICT_LABEL)).toBeInTheDocument()
    expect(save).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
    await waitFor(() => expect(save).toHaveBeenCalledWith('system_command', { action: 'block', version: 'version-2' }))
    save.mockRestore()
  })

  it("保存需回读确认" + ': base action read failure preserves draft', async () => {
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockResolvedValue({ data: {} } as never)
    const loadItems = vi.fn(async (): Promise<PolicyCenterAgentBehavior[]> => { throw new Error('unavailable') })
    render(<MemoryRouter><AgentBehaviorPolicy items={[behavior()]} auditOnly={false} canManage loadItems={loadItems} onReload={vi.fn()} /></MemoryRouter>)
    fireEvent.click(within(screen.getByRole('radiogroup', { name: GROUP_LABEL })).getByRole('radio', { name: BLOCK_LABEL }))
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
    expect(await screen.findByText(new RegExp(READ_FAILED_LABEL))).toBeInTheDocument()
    expect(save).not.toHaveBeenCalled()
    expect(within(screen.getByRole('radiogroup', { name: GROUP_LABEL })).getByRole('radio', { name: BLOCK_LABEL })).toBeChecked()
    save.mockRestore()
  })

  it("只锁定状态异常的行为" + ': raw advanced action is not record', () => {
    renderPage([behavior({ configured_action: 'confirm', current_action: 'confirm', has_advanced_overrides: true })])
    expect(screen.getByText(/confirm/)).toBeInTheDocument()
    expect(screen.getByRole('radiogroup', { name: GROUP_LABEL })).toHaveClass('ant-segmented-disabled')
    expect(screen.queryByRole('button', { name: SAVE_LABEL })).not.toBeInTheDocument()
  })

  it(ADVANCED_LABEL + ': healthy advanced override is not execution', () => {
    renderPage([behavior({ has_advanced_overrides: true })])
    expect(screen.getByText(`${BASELINE_PREFIX}${SEPARATOR}${RECORD_LABEL}`)).toBeInTheDocument()
    expect(within(screen.getByRole('radiogroup', { name: GROUP_LABEL })).getByRole('radio', { name: RECORD_LABEL })).toBeChecked()
    expect(screen.getByText(new RegExp(ADVANCED_LABEL))).toBeInTheDocument()
    expect(screen.queryByText(new RegExp(UNKNOWN_LABEL))).not.toBeInTheDocument()
    expect(screen.getByRole('radiogroup', { name: GROUP_LABEL })).not.toHaveClass('ant-segmented-disabled')
    expect(screen.getByRole('link', { name: '查看行为记录' })).toHaveAttribute('href', '/audit/access-retention?view=requests')
  })


  it("只锁定状态异常的行为" + ': latest unavailable base action is not saved', async () => {
    const loadItems = vi.fn(async () => [behavior({ version: 'version-2', health: 'error', health_message: 'unavailable' })])
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockResolvedValue({ data: {} } as never)
    render(<MemoryRouter><AgentBehaviorPolicy items={[behavior()]} auditOnly={false} canManage loadItems={loadItems} onReload={vi.fn()} /></MemoryRouter>)
    fireEvent.click(within(screen.getByRole('radiogroup', { name: GROUP_LABEL })).getByRole('radio', { name: BLOCK_LABEL }))
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
    expect(await screen.findByText(/unavailable/)).toBeInTheDocument()
    expect(save).not.toHaveBeenCalled()
    expect(screen.queryByText(CONFLICT_LABEL)).not.toBeInTheDocument()
    save.mockRestore()
  })

  it("只锁定状态异常的行为" + ': unknown latest base action is not overwritten', async () => {
    const loadItems = vi.fn(async () => [behavior({ configured_action: 'confirm', current_action: 'confirm' })])
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockResolvedValue({ data: {} } as never)
    render(<MemoryRouter><AgentBehaviorPolicy items={[behavior()]} auditOnly={false} canManage loadItems={loadItems} onReload={vi.fn()} /></MemoryRouter>)
    fireEvent.click(within(screen.getByRole('radiogroup', { name: GROUP_LABEL })).getByRole('radio', { name: BLOCK_LABEL }))
    fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
    fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
    await waitFor(() => expect(loadItems).toHaveBeenCalledTimes(2))
    expect(save).not.toHaveBeenCalled()
    save.mockRestore()
  })

  it(CONFLICT_LABEL + ': later item changes during the first write', async () => {
    const initial = [behavior(), behavior({ key: 'network_egress' })]
    let latest = initial
    const loadItems = vi.fn(async () => latest)
    const onReload = vi.fn()
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockImplementation(async (key, input) => {
      latest = latest.map((item) => item.key === key
        ? { ...item, configured_action: input.action, current_action: input.action, version: 'version-saved' }
        : { ...item, configured_action: 'alert_allow', current_action: 'alert_allow', version: 'version-other' })
      return { data: {} } as never
    })
    try {
      render(<MemoryRouter><AgentBehaviorPolicy items={initial} auditOnly={false} canManage loadItems={loadItems} onReload={onReload} /></MemoryRouter>)
      for (const group of screen.getAllByRole('radiogroup')) {
        fireEvent.click(within(group).getByRole('radio', { name: BLOCK_LABEL }))
      }
      fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
      await waitFor(() => expect(onReload).toHaveBeenCalledOnce())
      expect(save).toHaveBeenCalledTimes(1)
      expect(save).toHaveBeenCalledWith('system_command', { action: 'block', version: 'version-1' })
      expect(screen.getByText(new RegExp(CONFLICT_LABEL))).toBeInTheDocument()
      expect(within(screen.getAllByRole('radiogroup')[1]).getByRole('radio', { name: BLOCK_LABEL })).toBeChecked()
    } finally {
      save.mockRestore()
    }
  })

  it('批内多项保存：两项同轮修改，两次 PUT 都发出且第二项用刷新后的版本', async () => {
    const initial = [behavior(), behavior({ key: 'network_egress' })]
    let server = initial
    let revision = 1
    const loadItems = vi.fn(async () => server)
    const onReload = vi.fn()
    // 模拟共享版本语义：每次成功保存推进全部 agentguard 类别的版本，但只改动被保存项的动作。
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockImplementation(async (key, input) => {
      revision += 1
      server = server.map((item) => ({
        ...item,
        configured_action: item.key === key ? input.action : item.configured_action,
        current_action: item.key === key ? input.action : item.current_action,
        version: `version-${revision}`,
      }))
      return { data: {} } as never
    })
    try {
      render(<MemoryRouter><AgentBehaviorPolicy items={initial} auditOnly={false} canManage loadItems={loadItems} onReload={onReload} /></MemoryRouter>)
      for (const group of screen.getAllByRole('radiogroup')) {
        fireEvent.click(within(group).getByRole('radio', { name: BLOCK_LABEL }))
      }
      fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
      await waitFor(() => expect(save).toHaveBeenCalledTimes(2))
      expect(save.mock.calls.map(([key]) => key)).toEqual(['system_command', 'network_egress'])
      expect(save).toHaveBeenNthCalledWith(1, 'system_command', { action: 'block', version: 'version-1' })
      expect(save).toHaveBeenNthCalledWith(2, 'network_egress', { action: 'block', version: 'version-2' })
      expect(screen.queryByText(new RegExp(CONFLICT_LABEL))).not.toBeInTheDocument()
      expect(screen.getByText('全部保存成功')).toBeInTheDocument()
      await waitFor(() => expect(onReload).toHaveBeenCalledTimes(1))
    } finally {
      save.mockRestore()
    }
  })

  it(CONFLICT_LABEL + ': retry after a real conflict saves only the remaining item with the refreshed version', async () => {
    const initial = [behavior(), behavior({ key: 'network_egress' })]
    let server = initial
    const loadItems = vi.fn(async () => server)
    const onReload = vi.fn()
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockImplementation(async (key, input) => {
      server = server.map((item) => item.key === key
        ? { ...item, configured_action: input.action, current_action: input.action, version: 'version-saved' }
        : { ...item, configured_action: 'alert_allow', current_action: 'alert_allow', version: 'version-other' })
      return { data: {} } as never
    })
    try {
      render(<MemoryRouter><AgentBehaviorPolicy items={initial} auditOnly={false} canManage loadItems={loadItems} onReload={onReload} /></MemoryRouter>)
      for (const group of screen.getAllByRole('radiogroup')) {
        fireEvent.click(within(group).getByRole('radio', { name: BLOCK_LABEL }))
      }
      fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
      await waitFor(() => expect(onReload).toHaveBeenCalledOnce())
      expect(save).toHaveBeenCalledTimes(1)
      fireEvent.click(screen.getByRole('button', { name: RETRY_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
      const dialog = await screen.findByRole('dialog')
      expect(await within(dialog).findByText(CONFLICT_LABEL)).toBeInTheDocument()
      expect(save).toHaveBeenCalledTimes(1)
      fireEvent.click(within(dialog).getByRole('button', { name: CONFIRM_LABEL }))
      await waitFor(() => expect(save).toHaveBeenCalledTimes(2))
      expect(save).toHaveBeenLastCalledWith('network_egress', { action: 'block', version: 'version-other' })
      await waitFor(() => expect(onReload).toHaveBeenCalledTimes(2))
    } finally {
      save.mockRestore()
    }
  })

  it(UNKNOWN_LABEL + ': raw response remains unknown on a health error', () => {
    renderPage([behavior({ configured_action: 'confirm', current_action: 'unknown', raw_configured_action: 'confirm', health: 'error', has_advanced_overrides: true })])
    expect(screen.getByText(/confirm/)).toBeInTheDocument()
    expect(screen.getByText(new RegExp(UNKNOWN_LABEL))).toBeInTheDocument()
    expect(screen.queryByText(new RegExp(ADVANCED_LABEL))).not.toBeInTheDocument()
    expect(screen.getByRole('radiogroup', { name: GROUP_LABEL })).toHaveClass('ant-segmented-disabled')
  })

  it(UNKNOWN_LABEL + ': raw advanced default remains visible beside a basic baseline', () => {
    renderPage([behavior({ configured_action: 'record', current_action: 'unknown', raw_configured_action: 'confirm', health: 'error', has_advanced_overrides: true })])
    expect(screen.getByText('confirm')).toBeInTheDocument()
    expect(screen.getByText(new RegExp(UNKNOWN_LABEL))).toBeInTheDocument()
    expect(screen.queryByText(new RegExp(ADVANCED_LABEL))).not.toBeInTheDocument()
    expect(screen.getByRole('radiogroup', { name: GROUP_LABEL })).toHaveClass('ant-segmented-disabled')
  })

  it(ADVANCED_LABEL + ': unknown current action on a healthy advanced response is not a read error', () => {
    renderPage([behavior({ current_action: 'unknown', has_advanced_overrides: true })])
    expect(screen.getByText(new RegExp(ADVANCED_LABEL))).toBeInTheDocument()
    expect(screen.queryByText(new RegExp(UNKNOWN_LABEL))).not.toBeInTheDocument()
  })

  it(UNKNOWN_LABEL + ': unknown global mode takes precedence over healthy advanced overrides', () => {
    const items = [behavior({ has_advanced_overrides: true })]
    render(<MemoryRouter><AgentBehaviorPolicy items={items} auditOnly={undefined} canManage loadItems={async () => items} onReload={vi.fn()} /></MemoryRouter>)
    expect(screen.getByText(new RegExp(UNKNOWN_LABEL))).toBeInTheDocument()
    expect(screen.queryByText(new RegExp(ADVANCED_LABEL))).not.toBeInTheDocument()
  })

  it.each(['confirm', 'toString', 'constructor'])(UNKNOWN_LABEL + ': %s is not a writable basic action', (rawAction) => {
    renderPage([behavior({ configured_action: rawAction, current_action: 'unknown', raw_configured_action: rawAction })])
    expect(screen.getByText(new RegExp(rawAction))).toBeInTheDocument()
    expect(screen.getByText(new RegExp(UNKNOWN_LABEL))).toBeInTheDocument()
    const group = screen.getByRole('radiogroup', { name: GROUP_LABEL })
    expect(group).toHaveClass('ant-segmented-disabled')
    expect(within(group).getByRole('radio', { name: RECORD_LABEL })).not.toBeChecked()
    expect(screen.queryByRole('button', { name: SAVE_LABEL })).not.toBeInTheDocument()
  })

  it(UNKNOWN_LABEL + ': later item becomes an advanced action during the first write', async () => {
    const initial = [behavior(), behavior({ key: 'network_egress' })]
    let latest = initial
    const loadItems = vi.fn(async () => latest)
    const onReload = vi.fn()
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockImplementation(async (key, input) => {
      latest = latest.map((item) => item.key === key
        ? { ...item, configured_action: input.action, current_action: input.action, version: 'version-saved' }
        : { ...item, configured_action: 'confirm', current_action: 'confirm' })
      return { data: {} } as never
    })
    try {
      render(<MemoryRouter><AgentBehaviorPolicy items={initial} auditOnly={false} canManage loadItems={loadItems} onReload={onReload} /></MemoryRouter>)
      for (const group of screen.getAllByRole('radiogroup')) {
        fireEvent.click(within(group).getByRole('radio', { name: BLOCK_LABEL }))
      }
      fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
      await waitFor(() => expect(onReload).toHaveBeenCalledOnce())
      expect(save).toHaveBeenCalledTimes(1)
      expect(save).toHaveBeenCalledWith('system_command', { action: 'block', version: 'version-1' })
      expect(within(screen.getAllByRole('radiogroup')[1]).getByRole('radio', { name: BLOCK_LABEL })).toBeChecked()
    } finally {
      save.mockRestore()
    }
  })

  it('调用外部工具不提供无法往返的仅记录选项', () => {
    renderPage()
    const group = screen.getByRole('radiogroup', { name: '调用外部工具处理方式' })
    expect(within(group).queryByRole('radio', { name: RECORD_LABEL })).not.toBeInTheDocument()
    expect(within(group).getAllByRole('radio')).toHaveLength(2)
    expect(within(group).getByRole('radio', { name: EXTERNAL_ALLOW_LABEL })).toBeInTheDocument()
    expect(within(group).getByRole('radio', { name: EXTERNAL_BLOCK_LABEL })).toBeInTheDocument()
    expect(screen.getByText(MCP_NOTE_LABEL)).toBeInTheDocument()
  })

  it('调用外部工具保存后显示服务器真实回读值', async () => {
    const initial = [behavior({ key: 'external_tool', label: '外部工具（MCP）' })]
    let server = initial
    let revision = 1
    const loadItems = vi.fn(async () => server)
    const onReload = vi.fn()
    const save = vi.spyOn(securityPoliciesApi, 'updateAgentBehavior').mockImplementation(async (_key, input) => {
      revision += 1
      server = [behavior({ key: 'external_tool', label: '外部工具（MCP）', configured_action: input.action, current_action: input.action, version: `version-${revision}` })]
      return { data: {} } as never
    })
    const view = (items: PolicyCenterAgentBehavior[]) => (
      <MemoryRouter><AgentBehaviorPolicy items={items} auditOnly={false} canManage loadItems={loadItems} onReload={onReload} /></MemoryRouter>
    )
    try {
      const { rerender } = render(view(initial))
      fireEvent.click(within(screen.getByRole('radiogroup', { name: '调用外部工具处理方式' })).getByRole('radio', { name: EXTERNAL_BLOCK_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
      await waitFor(() => expect(save).toHaveBeenCalledWith('external_tool', { action: 'block', version: 'version-1' }))
      await waitFor(() => expect(onReload).toHaveBeenCalledOnce())
      expect(screen.getByText('全部保存成功')).toBeInTheDocument()
      expect(screen.queryByText(new RegExp(CONFLICT_LABEL))).not.toBeInTheDocument()
      rerender(view(server))
      expect(screen.getByText(`${BASELINE_PREFIX}${SEPARATOR}${EXTERNAL_BLOCK_LABEL}`)).toBeInTheDocument()
      expect(screen.getByText(`${MODE_PREFIX}${SEPARATOR}${EXTERNAL_BLOCK_LABEL}`)).toBeInTheDocument()
      const persisted = within(screen.getByRole('radiogroup', { name: '调用外部工具处理方式' })).getByRole('radio', { name: EXTERNAL_BLOCK_LABEL })
      expect(persisted).toBeChecked()
      fireEvent.click(within(screen.getByRole('radiogroup', { name: '调用外部工具处理方式' })).getByRole('radio', { name: EXTERNAL_ALLOW_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: SAVE_LABEL }))
      fireEvent.click(screen.getByRole('button', { name: CONFIRM_LABEL }))
      await waitFor(() => expect(save).toHaveBeenNthCalledWith(2, 'external_tool', { action: 'alert_allow', version: 'version-2' }))
      await waitFor(() => expect(onReload).toHaveBeenCalledTimes(2))
      expect(save).toHaveBeenCalledTimes(2)
      expect(screen.queryByText(new RegExp(CONFLICT_LABEL))).not.toBeInTheDocument()
      rerender(view(server))
      expect(screen.getByText(`${BASELINE_PREFIX}${SEPARATOR}${EXTERNAL_ALLOW_LABEL}`)).toBeInTheDocument()
      expect(screen.getByText(`${MODE_PREFIX}${SEPARATOR}${EXTERNAL_ALLOW_LABEL}`)).toBeInTheDocument()
      expect(within(screen.getByRole('radiogroup', { name: '调用外部工具处理方式' })).getByRole('radio', { name: EXTERNAL_ALLOW_LABEL })).toBeChecked()
    } finally {
      save.mockRestore()
    }
  })
})
