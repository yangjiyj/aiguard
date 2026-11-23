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
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

const baseSettings = {
  log_retention_days: '90',
  allow_registration: 'false',
  content_audit_enabled: 'false',
  tool_audit_enabled: 'false',
  security_execution_mode: { configured_mode: 'record', effective_mode: 'record', locked: false, source: 'admin_settings', runtime_verified: true, runtime_status: 'verified' },
}

describe('系统设置：AI 生成内容标识与响应缓存', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    useAuthStore.setState({ user: { id: 'admin', username: '管理员', role: 'admin', tenant_id: 't1' } })
    mockApi.put.mockResolvedValue({ data: {} })
  })
  const renderPage = () => render(<QueryClientProvider client={queryClient}><SystemSettings /></QueryClientProvider>)

  it('读取字符串形式的设置，保存时按服务端格式提交', async () => {
    mockApi.get.mockResolvedValue({
      data: {
        ...baseSettings,
        ai_content_explicit_label_enabled: 'true',
        ai_content_watermark_enabled: 'false',
        ai_content_explicit_label_text: '以上内容由 AI 生成',
        ai_content_label_agent_types: '["enterprise-portal","customer-desk"]',
        response_cache_enabled: 'true',
        response_cache_ttl_seconds: '600',
        response_cache_max_temperature: '0',
        response_cache_shared_project_ids: '["p_1"]',
        response_cache_generation: '4',
      },
    })
    renderPage()

    // 表单在设置加载完成后才回填，先等回填结果出现。
    await waitFor(() => expect(screen.getByLabelText('显式标识')).toBeChecked())
    expect(screen.getByLabelText('隐式水印')).not.toBeChecked()
    expect(screen.getByLabelText('启用响应缓存')).toBeChecked()
    // step=0.1 时 antd 按一位小数显示，0 显示为 0.0；提交的仍是数值 0（见下方断言）。
    await waitFor(() => expect(screen.getByLabelText('可缓存的最高 temperature')).toHaveValue('0.0'))
    expect(screen.getByText('customer-desk')).toBeInTheDocument()
    expect(screen.getByText('p_1')).toBeInTheDocument()

    // 2.9.22 起页面另有“保存故障处理”“保存检测执行”，这里点原表单的“保存设置”。
    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalled())
    const payload = mockApi.put.mock.calls[0][1]
    expect(payload).toEqual(expect.objectContaining({
      ai_content_explicit_label_enabled: true,
      ai_content_watermark_enabled: false,
      ai_content_label_agent_types: '["enterprise-portal","customer-desk"]',
      response_cache_enabled: true,
      response_cache_ttl_seconds: 600,
      response_cache_max_temperature: 0,
      response_cache_shared_project_ids: '["p_1"]',
    }))
    expect(payload).not.toHaveProperty('response_cache_generation')
  })

  it('清空缓存只提交递增后的代号', async () => {
    mockApi.get.mockResolvedValue({ data: { ...baseSettings, response_cache_generation: '4' } })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: '清空全部缓存' }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalledWith('/system/settings', { response_cache_generation: '5' }))
  })
})
