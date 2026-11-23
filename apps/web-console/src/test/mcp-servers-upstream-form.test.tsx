import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import McpServers from '../pages/McpServers'

const mocks = vi.hoisted(() => ({
  settingsGet: vi.fn(),
  listServers: vi.fn(),
  createServer: vi.fn(),
  updateServer: vi.fn(),
  shadowCheck: vi.fn(),
  info: vi.fn(),
  error: vi.fn(),
  success: vi.fn(),
}))

vi.mock('../services/api', () => ({
  default: { get: mocks.settingsGet },
  mcpServerApi: {
    list: mocks.listServers, listTools: vi.fn().mockResolvedValue({ data: { items: [] } }),
    create: mocks.createServer, update: mocks.updateServer, delete: vi.fn(), sync: vi.fn(),
    testConnection: vi.fn(), setAdmission: vi.fn(),
  },
  mcpToolApi: { shadowCheck: mocks.shadowCheck, setAdmission: vi.fn() },
}))

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: mocks.success, warning: vi.fn(), error: mocks.error, info: mocks.info } }
})

const legacyServer = {
  id: 'mcp_legacy', tenant_id: 't', name: '智慧芽', server_url: 'https://mcp.zhihuiya.example/mcp', owner: 'ops',
  trust_level: 'high', transport: 'streamable_http', status: 'active', auth_configured: true,
  capabilities: { protocol_version: '2025-11-25' }, created_at: '2026-01-01T00:00:00Z', tool_count: 3,
  last_synced_at: '2026-10-18T00:00:00Z', admission_status: 'approved',
  upstream: { transport: 'streamable_http', effective_transport: 'streamable_http', auth_location: 'header', auth_name: 'Authorization', auth_template: 'Bearer {secret}', protocol_version: '2025-11-25' },
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><McpServers /></QueryClientProvider>)
}

describe('MCP 服务表单：上游连接设置', () => {
  beforeEach(() => {
    Object.values(mocks).forEach((m) => m.mockReset())
    mocks.settingsGet.mockResolvedValue({ data: {} })
    mocks.shadowCheck.mockResolvedValue({ data: { warnings: [] } })
    mocks.listServers.mockResolvedValue({ data: { servers: [legacyServer] } })
    mocks.createServer.mockResolvedValue({ data: {} })
    mocks.updateServer.mockResolvedValue({ data: {} })
  })

  it('注册表单展示传输方式、鉴权位置、参数名、值模板、额外请求头与厂商预设，默认自动识别', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /注册 MCP 服务/ }))
    const dialog = await screen.findByRole('dialog')
    for (const text of ['厂商预设', '传输方式', '鉴权密钥', '鉴权位置', '请求头名称', '值模板', '添加额外请求头']) {
      expect(within(dialog).getAllByText(new RegExp(text)).length).toBeGreaterThan(0)
    }
    expect(within(dialog).getByText('自动识别（推荐）')).toBeInTheDocument()
  })

  it('存量 streamable_http 服务编辑时保持原传输方式，提交不新增上游配置字段', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /编辑/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getAllByText('Streamable HTTP').length).toBeGreaterThan(0)
    await userEvent.click(within(dialog).getByRole('button', { name: /提\s*交/ }))
    await waitFor(() => expect(mocks.updateServer).toHaveBeenCalled())
    const [id, payload] = mocks.updateServer.mock.calls[0]
    expect(id).toBe('mcp_legacy')
    expect(payload.transport).toBe('streamable_http')
    expect(payload.capabilities).toEqual({ protocol_version: '2025-11-25' })
    expect(payload).not.toHaveProperty('auth_location')
    expect(payload).not.toHaveProperty('extra_headers')
  })

  it('选择「URL 路径」后，服务地址的占位提示与密钥说明随之变化，选项文案为 URL 路径', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /注册 MCP 服务/ }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.click(within(dialog).getByText('请求头', { selector: '.ant-select-selection-item' }))
    await userEvent.click(await screen.findByText('URL 路径', { selector: '.ant-select-item-option-content' }))
    expect(within(dialog).getAllByText(/\{密钥\}/).length).toBeGreaterThan(0)
  })

  // R1：antd 把 option 的 value 写进下拉虚拟列表的无障碍辅助节点（role=option 的 aria-label / 隐藏 listbox 文本），
  // 读屏软件会读出 `{secret}`。option value 必须是内部代号，渲染出的整棵 DOM 都不能出现该字面量。
  it('值模板下拉展开后，整个 DOM（含无障碍辅助节点）都不出现 {secret} 字面量', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /注册 MCP 服务/ }))
    const dialog = await screen.findByRole('dialog')
    expect(document.body.innerHTML).not.toContain('{secret}')
    const select = within(dialog).getByText('Bearer + 密钥', { selector: '.ant-select-selection-item' })
    await userEvent.click(select)
    await screen.findAllByText('仅密钥（原样）')
    expect(document.body.innerHTML).not.toContain('{secret}')
    expect(document.body.textContent).not.toContain('{secret}')
    for (const el of Array.from(document.body.querySelectorAll('[aria-label],[title],[value],[data-value]'))) {
      for (const attr of ['aria-label', 'title', 'value', 'data-value']) {
        expect(el.getAttribute(attr) || '').not.toContain('{secret}')
      }
    }
  })

  it('选「仅密钥」提交时映射回后端认得的模板值 {secret}', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /注册 MCP 服务/ }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.type(within(dialog).getByPlaceholderText('例如: 内部知识库检索'), '新服务')
    await userEvent.type(within(dialog).getByPlaceholderText('例如: https://mcp.example.com/mcp'), 'https://mcp.example.com/mcp')
    await userEvent.click(within(dialog).getByText('Bearer + 密钥', { selector: '.ant-select-selection-item' }))
    await userEvent.click(await screen.findByText('仅密钥（原样）', { selector: '.ant-select-item-option-content' }))
    await userEvent.click(within(dialog).getByRole('button', { name: /提\s*交/ }))
    await waitFor(() => expect(mocks.createServer).toHaveBeenCalled())
    const payload = mocks.createServer.mock.calls[0][0]
    expect(payload.capabilities.upstream_auth_template).toBe('{secret}')
  })

  it('编辑已保存的自定义模板：以中文标签回显且不露出 {secret}，原样提交不改变存储值', async () => {
    mocks.listServers.mockResolvedValue({ data: { servers: [{
      ...legacyServer, capabilities: { protocol_version: '2025-11-25', upstream_auth_template: 'Token {secret}', upstream_auth_header_name: 'X-Api-Token' },
      upstream: { ...legacyServer.upstream, auth_name: 'X-Api-Token', auth_template: 'Token {secret}' },
    }] } })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /编辑/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Token {密钥}', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    expect(document.body.innerHTML).not.toContain('{secret}')
    await userEvent.click(within(dialog).getByRole('button', { name: /提\s*交/ }))
    await waitFor(() => expect(mocks.updateServer).toHaveBeenCalled())
    expect(mocks.updateServer.mock.calls[0][1].capabilities.upstream_auth_template).toBe('Token {secret}')
  })

  // L-3：已保存的 URL 参数鉴权服务（模板为空时的口径是「原样」）打开编辑，值模板不能显示成 Bearer。
  it('值模板为空时下拉不显示 Bearer，而是提示按位置取默认', async () => {
    mocks.listServers.mockResolvedValue({ data: { servers: [{
      ...legacyServer,
      capabilities: { protocol_version: '2025-11-25', upstream_auth_location: 'query', upstream_auth_query_param: 'key' },
      upstream: { ...legacyServer.upstream, auth_location: 'query', auth_name: 'key', auth_template: '' },
    }] } })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /编辑/ }))
    const dialog = await screen.findByRole('dialog')
    // formValuesFromServer 对 URL 参数的空模板给出「原样」，所以这里应显示「仅密钥（原样）」而不是 Bearer
    expect(within(dialog).queryByText('Bearer + 密钥', { selector: '.ant-select-selection-item' })).not.toBeInTheDocument()
    expect(within(dialog).getByText('仅密钥（原样）', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
  })

  it('列表与连接信息全部中文化，不出现裸英文枚举', async () => {
    renderPage()
    await screen.findByText('智慧芽')
    expect(screen.queryByText('streamable_http')).not.toBeInTheDocument()
    expect(screen.queryByText('auto')).not.toBeInTheDocument()
  })
})
