import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import GatewayAccess from '../components/GatewayAccess'
import { useGatewayAccess } from '../hooks/useGatewayAccess'
import SystemSettings from '../pages/SystemSettings'
import { useAuthStore } from '../stores/auth'

const mockApi = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), post: vi.fn() }))
// 系统设置页内嵌的“故障处理”“检测执行”区块经 systemSettingsApi 读、securitySystemSettingsApi 写（批次 5），
// 与页面主表单共用 ['system-settings'] 查询；模拟里缺了它们，共享查询会报错，主表单读不到值。
vi.mock('../services/api', () => ({
  default: mockApi,
  billingEmployeeApi: { settings: vi.fn().mockResolvedValue({ data: { data: { currency: 'USD' } } }) },
  systemSettingsApi: { get: () => mockApi.get('/system/settings'), update: (patch: Record<string, unknown>) => mockApi.put('/system/settings', patch) },
  securitySystemSettingsApi: { update: (patch: Record<string, unknown>) => mockApi.put('/security/system-settings', patch) },
}))

afterEach(() => { cleanup(); useAuthStore.setState({ user: null }) })

function Harness({ settings, onCopy, showClientGuide }: { settings: Record<string, unknown>; onCopy?: (v: string) => unknown; showClientGuide?: boolean }) {
  const access = useGatewayAccess(settings)
  return <GatewayAccess access={access} onCopy={onCopy} showClientGuide={showClientGuide} />
}

describe('调用入口组件里的按协议接入地址（密钥管理页、模型接入抽屉共用）', () => {
  beforeEach(() => localStorage.clear())

  it('在入口下方给出 Anthropic 协议的无 /v1 地址，OpenAI 地址只出现一次', () => {
    const copy = vi.fn()
    render(<Harness settings={{ gateway_public_base_url: 'https://models.example/customer/v1', gateway_public_url_mode: 'configured' }} onCopy={copy} />)
    // OpenAI 协议地址已在入口里展示，不重复渲染第二份。
    expect(screen.getAllByText('https://models.example/customer/v1')).toHaveLength(1)
    expect(screen.getByText('https://models.example/customer')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '复制 Anthropic 协议地址' }))
    expect(copy).toHaveBeenCalledWith('https://models.example/customer')
  })

  it('选中的入口是 https 配明文端口时给出针对性错误提示', () => {
    render(<Harness settings={{ gateway_public_base_url: 'https://gw.test:8080/v1', gateway_public_url_mode: 'configured' }} />)
    expect(screen.getAllByRole('alert').some(node => node.textContent?.includes('8080') && node.textContent?.includes('明文'))).toBe(true)
  })

  it('showClientGuide=false 时保持原样（例如 MCP 页面不适用模型协议）', () => {
    render(<Harness settings={{ gateway_public_base_url: 'https://gw.test/v1', gateway_public_url_mode: 'configured' }} showClientGuide={false} />)
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByText('Anthropic 协议')).toBeNull()
  })
})

describe('系统设置：对外调用地址输入框的即时提示', () => {
  const renderPage = () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    return render(
      <QueryClientProvider client={queryClient}><MemoryRouter><SystemSettings /></MemoryRouter></QueryClientProvider>,
    )
  }

  beforeEach(() => {
    vi.clearAllMocks()
    // 系统设置表单只对系统管理员渲染（币种切换改造后）；这里以平台管理员身份打开页面。
    useAuthStore.setState({ user: { id: 'a', username: '管理员', role: 'platform_admin', tenant_id: 'tenant-a' } as any })
    mockApi.get.mockResolvedValue({ data: { log_retention_days: '90', gateway_public_base_url: 'http://customer.example:8084/v1' } })
  })

  it('填写 https + 8080 或重复 /v1 时立即提示，改对后提示消失', async () => {
    renderPage()
    const input = await screen.findByLabelText('对外调用地址（Base URL）')
    await waitFor(() => expect(input).toHaveValue('http://customer.example:8084/v1'))
    expect(screen.queryByText(/通常是网关的明文 HTTP 端口/)).toBeNull()

    await userEvent.clear(input)
    await userEvent.type(input, 'https://gw.customer.test:8080/v1/v1')
    expect(await screen.findByText(/端口 8080 通常是网关的明文 HTTP 端口/)).toBeInTheDocument()
    expect(screen.getByText(/地址里重复写了 \/v1/)).toBeInTheDocument()

    await userEvent.clear(input)
    await userEvent.type(input, 'http://gw.customer.test:8080/v1')
    await waitFor(() => expect(screen.queryByText(/通常是网关的明文 HTTP 端口/)).toBeNull())
    expect(screen.queryByText(/地址里重复写了 \/v1/)).toBeNull()
  })

  it('说明里写明两类协议的写法，保存行为不受提示影响（提示不阻止保存）', async () => {
    mockApi.put.mockResolvedValue({ data: {} })
    renderPage()
    const input = await screen.findByLabelText('对外调用地址（Base URL）')
    await waitFor(() => expect(input).toHaveValue('http://customer.example:8084/v1'))
    expect(screen.getByText(/Anthropic 协议客户端（如 Claude Code）不要带 \/v1/)).toBeInTheDocument()
    await userEvent.clear(input)
    await userEvent.type(input, 'https://gw.customer.test:8080/v1')
    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalledWith('/system/settings',
      expect.objectContaining({ gateway_public_base_url: 'https://gw.customer.test:8080/v1' })))
  })
})
