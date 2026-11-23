import { useAuthStore } from '../stores/auth'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SystemSettings from '../pages/SystemSettings'

const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
  billingSettings: vi.fn().mockResolvedValue({ data: { data: { currency: 'CNY' } } }),
}))

// 2.9.22 起页面里的“故障处理”“检测执行”经 systemSettingsApi / securitySystemSettingsApi 读写，这里接到同一个 mock 上。
vi.mock('../services/api', () => ({
  default: mockApi,
  billingEmployeeApi: { settings: mockApi.billingSettings },
  systemSettingsApi: { get: () => mockApi.get('/system/settings'), update: (patch: Record<string, unknown>) => mockApi.put('/system/settings', patch) },
  securitySystemSettingsApi: { update: (patch: Record<string, unknown>) => mockApi.put('/security/system-settings', patch) },
}))

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      error: vi.fn(),
    },
  }
})

describe('SystemSettings LSE 集成配置', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
    useAuthStore.setState({ user: { id: 'admin', username: '管理员', role: 'admin', tenant_id: 't1' } })
    mockApi.get.mockResolvedValue({
      data: {
        system_name: 'AI算力安全网关',
        session_ttl: '24h',
        log_retention_days: '90',
        allow_registration: 'false',
        content_audit_enabled: 'true',
        tool_audit_enabled: 'true',
        security_audit_only: 'true',
        lse_base_url: 'https://lse.example.com',
      },
    })
    mockApi.put.mockResolvedValue({ data: { message: 'ok' } })
  })

  const renderPage = () =>
    render(
      <QueryClientProvider client={queryClient}>
        <SystemSettings />
      </QueryClientProvider>
    )

  it('回填并提交 lse_base_url', async () => {
    renderPage()
    expect(await screen.findByDisplayValue('https://lse.example.com')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))

    await waitFor(() => expect(mockApi.put).toHaveBeenCalled())
    const body = mockApi.put.mock.calls.find((c: any) => c[0] === '/system/settings')?.[1] as any
    expect(body?.lse_base_url).toBe('https://lse.example.com')
  })
})
