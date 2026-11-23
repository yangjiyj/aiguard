import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { message } from 'antd'
import ProtectionItemTable from '../components/protection/ProtectionItemTable'
import ProtectionGroupSection from '../components/protection/ProtectionGroupSection'
import McpProtectionSettings from '../pages/McpProtectionSettings'
import api, { type ProtectionSettingItem } from '../services/api'
import { chooseOption, PROTECTION_ITEMS, protectionItem } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }
})

const loop = PROTECTION_ITEMS.find((item) => item.key === 'agent.tool_failure_loop')!
const identity = PROTECTION_ITEMS.find((item) => item.key === 'agent.identity_rejected')!

function renderTable(items: ProtectionSettingItem[], canManage = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const view = render(
    <MemoryRouter><QueryClientProvider client={client}><ProtectionItemTable ariaLabel="表" items={items} canManage={canManage} /></QueryClientProvider></MemoryRouter>,
  )
  const rerender = (next: ProtectionSettingItem[]) => view.rerender(
    <MemoryRouter><QueryClientProvider client={client}><ProtectionItemTable ariaLabel="表" items={next} canManage={canManage} /></QueryClientProvider></MemoryRouter>,
  )
  return { ...view, rerender }
}

describe('防护项表格', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.mocked(message.error).mockClear()
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
  })

  it('数字参数高于上限时拉回上限再保存（输入 99999，上限 86400）', async () => {
    const user = userEvent.setup()
    renderTable([loop])
    const input = screen.getByRole('spinbutton', { name: '工具连续失败窗口（秒）' })
    await user.clear(input)
    await user.type(input, '99999')
    fireEvent.blur(input)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', {
      items: { 'agent.tool_failure_loop': { action: 'alert_allow', params: { window_seconds: 86400, threshold: 5 } } },
    }))
  })

  it('数字参数低于下限时拉回下限再保存', async () => {
    const user = userEvent.setup()
    renderTable([loop])
    const input = screen.getByRole('spinbutton', { name: '工具连续失败次数' })
    await user.clear(input)
    await user.type(input, '1')
    fireEvent.blur(input)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', {
      items: { 'agent.tool_failure_loop': { action: 'alert_allow', params: { window_seconds: 600, threshold: 2 } } },
    }))
  })

  it('字符串列表参数输入完成（离开输入框）后才保存', async () => {
    renderTable([identity])
    const select = screen.getByRole('combobox', { name: '调用身份异常可信客户端' })
    fireEvent.change(select, { target: { value: 'claude-code' } })
    fireEvent.keyDown(select, { key: 'Enter', code: 'Enter', keyCode: 13 })
    expect(api.put).not.toHaveBeenCalled()
    fireEvent.blur(select)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', {
      items: { 'agent.identity_rejected': { action: 'alert_allow', params: { trusted_agent_types: ['claude-code'] } } },
    }))
  })

  it('字符串列表输入后不按回车直接失焦也能保存', async () => {
    renderTable([identity])
    const select = screen.getByRole('combobox', { name: '调用身份异常可信客户端' })
    fireEvent.change(select, { target: { value: 'cursor' } })
    fireEvent.blur(select)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', {
      items: { 'agent.identity_rejected': { action: 'alert_allow', params: { trusted_agent_types: ['cursor'] } } },
    }))
  })

  it('未聚焦时点标签上的 × 删除立即保存', async () => {
    renderTable([{ ...identity, params: { trusted_agent_types: ['codex', 'cursor'] } }])
    const tag = screen.getByText('codex').closest('.ant-select-selection-item') as HTMLElement
    fireEvent.click(tag.querySelector('.ant-select-selection-item-remove') as HTMLElement)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', {
      items: { 'agent.identity_rejected': { action: 'alert_allow', params: { trusted_agent_types: ['cursor'] } } },
    }))
  })

  it('这组没有防护项时不留空白', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (url: string) => (url === '/protection-settings' ? { data: { items: PROTECTION_ITEMS.filter((item) => item.group !== 'mcp') } } : { data: { data: [] } }) as never)
    const { container } = render(
      <MemoryRouter><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <McpProtectionSettings canEdit />
      </QueryClientProvider></MemoryRouter>,
    )
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/protection-settings'))
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  it('不认识的参数类型只读显示', () => {
    renderTable([protectionItem('agent.x', 'agent_fallback', '新项', { params: { mode: 'strict' }, param_specs: [{ key: 'mode', label: '模式', kind: 'enum', default: 'loose' }] })])
    expect(screen.getByText('模式：strict')).toBeInTheDocument()
    expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument()
  })

  it('保存失败提示后端原因并回滚', async () => {
    vi.mocked(api.put).mockRejectedValue({ response: { data: { error: { code: 'invalid_request', message: '动作不在可选范围内' } } } })
    renderTable([loop])
    await chooseOption(screen.getByRole('combobox', { name: '工具连续失败动作' }), '阻断')
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('动作不在可选范围内'))
    expect(screen.getByRole('combobox', { name: '工具连续失败动作' }).closest('.ant-select')).toHaveTextContent('告警放行')
  })

  it('同样内容刷新不覆盖还没离开输入框的参数', async () => {
    const user = userEvent.setup()
    const { rerender } = renderTable([loop])
    const input = screen.getByRole('spinbutton', { name: '工具连续失败窗口（秒）' })
    await user.clear(input)
    await user.type(input, '1200')
    rerender([{ ...loop, params: { ...loop.params } }])
    expect(screen.getByRole('spinbutton', { name: '工具连续失败窗口（秒）' })).toHaveValue('1200')
  })

  it('防护项读取失败时提示', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new Error('boom'))
    render(
      <MemoryRouter><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ProtectionGroupSection group="skill" title="调用防护" ariaLabel="Skill 调用防护" canManage />
      </QueryClientProvider></MemoryRouter>,
    )
    expect(await screen.findByText('防护项读取失败')).toBeInTheDocument()
  })

  it('过期的例外不计入条数', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (url: string) => {
      if (url === '/protection-settings') return { data: { items: PROTECTION_ITEMS } } as never
      return { data: { data: [
        { id: 'e1', rule_id: 'skill.identity_invalid', enabled: true },
        { id: 'e2', rule_id: 'skill.identity_invalid', enabled: true, expires_at: '2020-01-01T00:00:00Z' },
        { id: 'e3', rule_id: 'skill.identity_invalid', enabled: true, expires_at: '9999-12-31T00:00:00Z' },
      ] } } as never
    })
    render(
      <MemoryRouter><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ProtectionGroupSection group="skill" title="调用防护" ariaLabel="Skill 调用防护" canManage />
      </QueryClientProvider></MemoryRouter>,
    )
    const row = (await screen.findByText('Skill 身份异常')).closest('tr') as HTMLElement
    expect(await within(row).findByText('2 条')).toBeInTheDocument()
  })
})
