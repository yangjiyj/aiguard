import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ProxySettings from '../pages/ProxySettings'
import * as api from '../services/api'

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      warning: vi.fn(),
      error: vi.fn(),
    },
  }
})

const renderProxySettings = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ProxySettings />
    </QueryClientProvider>,
  )
}

describe('ProxySettings page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(api.caApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(api.default, 'get').mockResolvedValue({ data: { outbound_proxy_enabled: 'false' } } as any)
    vi.spyOn(api.proxyApi, 'getWhitelist').mockResolvedValue({ data: { data: [], total: 0 } } as any)
  })

  it('reads tenant whitelist coverage alongside the forward proxy address', async () => {
    const getWhitelistSpy = vi.spyOn(api.proxyApi, 'getWhitelist')
    renderProxySettings()

    await waitFor(() => {
      expect(screen.getByText('网络与证书')).toBeInTheDocument()
      expect(screen.getByText('正向代理接入配置')).toBeInTheDocument()
      expect(screen.getByText('localhost')).toBeInTheDocument()
      expect(screen.getAllByText('3128')).toHaveLength(2)
    })

    expect(screen.queryByText('访问密钥')).not.toBeInTheDocument()
    expect(screen.queryByText('放行域名列表')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /添加放行域名/i })).not.toBeInTheDocument()
    await waitFor(() => expect(getWhitelistSpy).toHaveBeenCalledTimes(1))
  })

  it('does not show an empty-whitelist warning for configured tenant targets', async () => {
    vi.mocked(api.proxyApi.getWhitelist).mockResolvedValue({ data: { data: [{ id: 'target-1', host_pattern: 'api.example.test' }], total: 1 } } as any)
    renderProxySettings()
    await waitFor(() => expect(api.proxyApi.getWhitelist).toHaveBeenCalledTimes(1))
    expect(screen.queryByTestId('forward-proxy-whitelist-empty')).not.toBeInTheDocument()
  })

  it('distinguishes an unavailable whitelist from a successfully empty table', async () => {
    vi.mocked(api.proxyApi.getWhitelist).mockRejectedValue(new Error('unavailable'))
    renderProxySettings()
    expect(await screen.findByTestId('forward-proxy-whitelist-unavailable')).toBeInTheDocument()
    expect(screen.queryByTestId('forward-proxy-whitelist-empty')).not.toBeInTheDocument()
  })

  it('saves the encrypted gateway egress proxy without rendering the saved address', async () => {
    const getSpy = vi.spyOn(api.default, 'get').mockResolvedValue({
      data: { outbound_proxy_enabled: 'true', outbound_proxy_url: '***' },
    } as any)
    const putSpy = vi.spyOn(api.default, 'put').mockResolvedValue({ data: { message: 'settings updated' } } as any)

    renderProxySettings()
    fireEvent.click(await screen.findByText('网关出网代理'))
    await waitFor(() => expect(screen.getByText('当前已配置')).toBeInTheDocument())

    const field = screen.getByPlaceholderText('http://proxy.customer.local:8080')
    expect(field).toHaveValue('')
    fireEvent.change(field, { target: { value: 'http://new-proxy.example.test:8080' } })
    fireEvent.click(screen.getByRole('button', { name: '保存出网代理' }))

    await waitFor(() => expect(putSpy).toHaveBeenCalledWith('/system/settings', {
      outbound_proxy_enabled: true,
      outbound_proxy_url: 'http://new-proxy.example.test:8080',
    }))
    expect(getSpy).toHaveBeenCalledWith('/system/settings')
  })
})
