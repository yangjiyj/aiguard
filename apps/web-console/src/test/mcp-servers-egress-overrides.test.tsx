import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Modal } from 'antd'
import McpServers from '../pages/McpServers'
import { useAuthStore } from '../stores/auth'

const mocks = vi.hoisted(() => ({
  settingsGet: vi.fn(),
  listServers: vi.fn(),
  createServer: vi.fn(),
  updateServer: vi.fn(),
  shadowCheck: vi.fn(),
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
  return { ...actual, message: { success: vi.fn(), warning: vi.fn(), error: vi.fn(), info: vi.fn() } }
})

const server = {
  id: 'mcp_1', tenant_id: 't', name: '内部检索', server_url: 'https://mcp.corp.example/mcp', owner: 'ops',
  trust_level: 'high', transport: 'streamable_http', status: 'active', auth_configured: false,
  capabilities: {}, created_at: '2026-01-01T00:00:00Z', tool_count: 1, admission_status: 'approved',
  egress_overrides: { allow_internal_hostnames: true },
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><McpServers /></QueryClientProvider>)
}

describe('MCP 服务表单：高级出站', () => {
  afterEach(() => Modal.destroyAll())
  beforeEach(() => {
    Object.values(mocks).forEach((m) => m.mockReset())
    useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true })
    mocks.settingsGet.mockResolvedValue({ data: {} })
    mocks.shadowCheck.mockResolvedValue({ data: { warnings: [] } })
    mocks.listServers.mockResolvedValue({ data: { servers: [server] } })
    mocks.updateServer.mockResolvedValue({ data: {} })
  })

  it('打开出站放行要二次确认，提交带上全部放行项', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: /编辑/ }))
    const group = await screen.findByRole('group', { name: '高级出站' })
    expect(within(group).getByRole('switch', { name: '允许内部主机名' })).toBeChecked()

    await user.click(within(group).getByRole('switch', { name: '允许云元数据地址' }))
    expect(await screen.findByText('网关可被用来访问这些地址。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认打开' }))
    await waitFor(() => expect(within(group).getByRole('switch', { name: '允许云元数据地址' })).toBeChecked())

    await user.click(within(group).getByRole('switch', { name: '跳过证书校验' }))
    expect(await screen.findByText('网关不再校验上游证书，连接可能被冒充。')).toBeInTheDocument()
    const confirms = screen.getAllByRole('button', { name: '确认打开' })
    await user.click(confirms[confirms.length - 1])
    await waitFor(() => expect(within(group).getByRole('switch', { name: '跳过证书校验' })).toBeChecked())

    const dialog = group.closest('.ant-modal') as HTMLElement
    await user.click(within(dialog).getByRole('button', { name: /提\s*交/ }))
    await waitFor(() => expect(mocks.updateServer).toHaveBeenCalled())
    const [, payload] = mocks.updateServer.mock.calls[0]
    expect(payload.egress_overrides).toEqual({
      allow_loopback: false,
      allow_link_local: false,
      allow_metadata: true,
      allow_internal_hostnames: true,
      allow_same_host_redirect: false,
      insecure_skip_verify: true,
      trusted_ca_pem: '',
    })
  })

  it('租户级角色看到的高级出站开关只读（已打开的可以关）', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'u2', username: 'so', role: 'security_officer', tenant_id: 'tenant-a' }, isAuthenticated: true })
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: /编辑/ }))
    const group = await screen.findByRole('group', { name: '高级出站' })
    expect(within(group).getByRole('switch', { name: '跳过证书校验' })).toBeDisabled()
    expect(within(group).getByRole('switch', { name: '允许内部主机名' })).toBeEnabled()
    expect(screen.getByRole('switch', { name: '允许内网地址' })).toBeDisabled()
    expect(within(group).getByLabelText('信任的 CA 证书')).toBeDisabled()
  })

  it('允许内网地址也要二次确认，取消则不打开', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: /编辑/ }))
    const toggle = await screen.findByRole('switch', { name: '允许内网地址' })
    await user.click(toggle)
    const content = await screen.findAllByText('网关可被用来访问这些地址。')
    const confirm = content[content.length - 1].closest('.ant-modal') as HTMLElement
    await user.click(within(confirm).getByRole('button', { name: /取\s*消/ }))
    expect(toggle).not.toBeChecked()
  })
})
