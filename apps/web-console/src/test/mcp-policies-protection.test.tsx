import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import McpProtectionSettings from '../pages/McpProtectionSettings'
import McpRedlineSettings from '../pages/McpRedlineSettings'
import api, { agentGuardApi, mcpRedlineApi } from '../services/api'
import { chooseOption, PROTECTION_ITEMS } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

function wrap(node: JSX.Element, entry = '/mcp-gateway/policies') {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        {node}
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('MCP 调用策略：调用防护与安全红线', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api, 'get').mockImplementation(async (url: string) => {
      if (url === '/protection-settings') return { data: { items: PROTECTION_ITEMS } } as never
      return { data: { data: [{ id: 'e1', rule_id: 'cloud_metadata', enabled: true }] } } as never
    })
    vi.spyOn(api, 'put').mockResolvedValue({ data: { items: PROTECTION_ITEMS } } as never)
    vi.spyOn(mcpRedlineApi, 'list').mockResolvedValue({ data: { items: [{ rule_name: 'cloud_metadata', action: 'alert' }] } } as never)
    vi.spyOn(mcpRedlineApi, 'update').mockResolvedValue({ data: { items: [] } } as never)
  })

  it('只显示 mcp 组，改动作与参数调用防护项接口', async () => {
    const user = userEvent.setup()
    wrap(<McpProtectionSettings canEdit />)
    const table = await screen.findByRole('table', { name: 'MCP 调用防护' })
    expect(await within(table).findByText('未准入的 MCP 服务')).toBeInTheDocument()
    expect(within(table).queryByText('SSH 私钥')).not.toBeInTheDocument()
    await chooseOption(within(table).getByRole('combobox', { name: '未准入的 MCP 服务动作' }), '阻断')
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', { items: { 'mcp.admission': { action: 'block', params: {} } } }))
    const timeout = within(table).getByRole('spinbutton', { name: '扫描超时超时（秒）' })
    await user.clear(timeout)
    await user.type(timeout, '10')
    fireEvent.blur(timeout)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', { items: { 'mcp.scan_timeout': { action: 'alert_allow', params: { timeout_seconds: 10 } } } }))
  })

  it('无权角色只读', async () => {
    wrap(<McpProtectionSettings canEdit={false} />)
    const select = await screen.findByRole('combobox', { name: '未准入的 MCP 服务动作' })
    expect(select).toBeDisabled()
    expect(screen.getByRole('button', { name: '扫描超时加例外' })).toBeDisabled()
  })

  it('加例外预填防护项键，目标按 mcp:服务名/工具名 写', async () => {
    const user = userEvent.setup()
    wrap(<McpProtectionSettings canEdit />, '/mcp-gateway/policies?protection=mcp.scan_timeout')
    const label = await screen.findByText('扫描超时')
    expect(label.closest('tr')).toHaveClass('is-focused')
    await user.click(screen.getByRole('button', { name: '扫描超时加例外' }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('mcp.scan_timeout')
    expect(screen.getByPlaceholderText('mcp:服务名/工具名（工具可省）')).toBeInTheDocument()
  })

  it('红线四档动作，可关闭，可加例外', async () => {
    const user = userEvent.setup()
    const create = vi.spyOn(agentGuardApi, 'createException').mockResolvedValue({ data: {} } as never)
    wrap(<McpRedlineSettings canEdit />)
    const select = await screen.findByRole('combobox', { name: '红线处置-cloud_metadata' })
    fireEvent.mouseDown(select)
    for (const label of ['关闭', '仅记录', '告警', '阻断']) {
      expect((await screen.findAllByText(label, { selector: '.ant-select-item-option-content' })).length).toBeGreaterThan(0)
    }
    fireEvent.click((await screen.findAllByText('关闭', { selector: '.ant-select-item-option-content' }))[0])
    await waitFor(() => expect(mcpRedlineApi.update).toHaveBeenCalledWith({ cloud_metadata: 'off' }))

    expect(await screen.findByText('1 条')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /加例外$/ }))
    expect(await screen.findByLabelText('关联规则')).toHaveValue('cloud_metadata')
    await user.type(screen.getByLabelText('目标匹配'), 'mcp:内部检索/search')
    await user.type(screen.getByLabelText('审批原因'), '内部服务')
    await user.click(screen.getByRole('button', { name: '创建例外' }))
    await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({ rule_id: 'cloud_metadata', target_pattern: 'mcp:内部检索/search', scope_type: 'tenant' })))
  })

  it('红线区块不带说明句', async () => {
    wrap(<McpRedlineSettings canEdit />)
    await screen.findByRole('combobox', { name: '红线处置-cloud_metadata' })
    expect(screen.queryByText(/对所有 MCP 工具调用参数生效/)).not.toBeInTheDocument()
  })

  it('红线只读', async () => {
    wrap(<McpRedlineSettings canEdit={false} />)
    expect(await screen.findByRole('combobox', { name: '红线处置-cloud_metadata' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /加例外$/ })).toBeDisabled()
  })
})
