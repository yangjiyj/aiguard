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

describe('SystemSettings page', () => {
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
  })

  const renderPage = () =>
    render(
      <QueryClientProvider client={queryClient}>
        <SystemSettings />
      </QueryClientProvider>
    )

  it('uses customer-facing labels and treats string booleans as real switch values', async () => {
    mockApi.get.mockResolvedValue({
      data: {
        system_name: 'AI算力安全网关',
        session_ttl: '24h',
        log_retention_days: '90',
        allow_registration: 'false',
        content_audit_enabled: 'false',
        tool_audit_enabled: 'true',
        security_execution_mode: { configured_mode: 'record', effective_mode: 'record', locked: false, source: 'admin_settings', runtime_verified: true, runtime_status: 'verified' },
      },
    })

    renderPage()

    expect(await screen.findByLabelText('日志与内容留存天数')).toBeInTheDocument()
    expect(screen.queryByLabelText('系统显示名称')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('管理员登录有效期')).not.toBeInTheDocument()
    expect(screen.getByLabelText('对外调用地址（Base URL）')).toBeInTheDocument()
    expect(screen.queryByText('组织称谓')).not.toBeInTheDocument()
    expect(screen.getByText(/到期自动清理：访问记录明细、内容留存/)).toBeInTheDocument()
    expect(screen.getByText(/不会清理：安全事件及其关联的访问记录/)).toBeInTheDocument()
    expect(screen.getByText(/计费记录长期保留/)).toBeInTheDocument()
    expect(screen.getByText('为防误删，最少保留 30 天。')).toBeInTheDocument()
    expect(screen.getByLabelText('日志与内容留存天数')).toHaveAttribute('aria-valuemin', '30')
    expect(screen.getByText('货币设置')).toBeInTheDocument()
    expect(screen.getByText(/不进行汇率换算/)).toBeInTheDocument()
    expect(screen.queryByText(/最终汇率由财务结算决定/)).not.toBeInTheDocument()
    expect(screen.getByText('安全策略状态')).toBeInTheDocument()
    expect(screen.getByText('当前安全执行模式')).toBeInTheDocument()
    expect(await screen.findByText('观察留痕')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '前往策略中心配置' })).toHaveAttribute(
      'href',
      '/security/policies?section=overview',
    )

    await waitFor(() => {
      expect(screen.getByLabelText('开放自助注册')).not.toBeChecked()
      expect(screen.getByLabelText('启用内容审计')).not.toBeChecked()
      expect(screen.getByLabelText('启用工具调用审计')).toBeChecked()
    })
  })

  it('保存实际网关地址后刷新共享设置缓存', async () => {
    mockApi.get.mockResolvedValue({ data: {
      gateway_public_base_url: 'http://customer.example:8084/v1',
      log_retention_days: '90',
    } })
    mockApi.put.mockResolvedValue({ data: {} })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    renderPage()
    const input = await screen.findByLabelText('对外调用地址（Base URL）')
    await waitFor(() => expect(input).toHaveValue('http://customer.example:8084/v1'))
    await userEvent.clear(input)
    await userEvent.type(input, 'https://models.example/gateway/v1')
    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalledWith('/system/settings',
      expect.objectContaining({ gateway_public_base_url: 'https://models.example/gateway/v1' })))
    await waitFor(() => expect(invalidate).toHaveBeenCalledWith({ queryKey: ['system-settings'] }))
  })

  it('支持客户内网单标签主机名，并拒绝带凭据的调用地址', async () => {
    mockApi.get.mockResolvedValue({ data: { log_retention_days: '90' } })
    mockApi.put.mockResolvedValue({ data: {} })
    renderPage()
    const input = await screen.findByLabelText('对外调用地址（Base URL）')
    await waitFor(() => expect(screen.getByLabelText('日志与内容留存天数')).toHaveValue('90'))
    await userEvent.type(input, 'http://user:password@gateway:8084/v1')
    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))
    expect(await screen.findByText(/请输入不含账号密码/)).toBeInTheDocument()
    expect(mockApi.put).not.toHaveBeenCalled()
    await userEvent.clear(input)
    await userEvent.type(input, 'http://gateway:8084/v1')
    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalledWith('/system/settings',
      expect.objectContaining({ gateway_public_base_url: 'http://gateway:8084/v1' })))
  })

  it('保存其他系统设置时不提交策略中心托管字段', async () => {
    mockApi.get.mockResolvedValue({
      data: {
        system_name: 'AI算力安全网关',
        session_ttl: '24h',
        log_retention_days: '90',
        allow_registration: 'false',
        content_audit_enabled: 'true',
        tool_audit_enabled: 'true',
        security_execution_mode: { configured_mode: 'record', effective_mode: 'record', locked: false, source: 'admin_settings', runtime_verified: true, runtime_status: 'verified' },
      },
    })
    mockApi.put.mockResolvedValue({ data: { message: 'settings updated' } })

    renderPage()

    await screen.findByLabelText('日志与内容留存天数')
    await userEvent.click(await screen.findByLabelText('开放自助注册'))
    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith('/system/settings', expect.objectContaining({
        allow_registration: true,
        log_retention_days: 90,
      }))
    })
    const payload = mockApi.put.mock.calls[0][1]
    expect(payload).not.toHaveProperty('security_audit_only')
    expect(payload).not.toHaveProperty('file_content_dlp_enabled')
    expect(payload).not.toHaveProperty('security_execution_mode')
  })

  it('只读展示统一实际模式，不读取或展示工程字段', async () => {
    mockApi.get.mockResolvedValue({
      data: {
        allow_registration: 'false',
        content_audit_enabled: 'false',
        tool_audit_enabled: 'false',
        security_execution_mode: { configured_mode: 'record', effective_mode: 'record', locked: true, source: 'deployment', runtime_verified: true, runtime_status: 'verified' },
        security_audit_only: 'true',
        file_content_dlp_enabled: 'false',
      },
    })
    renderPage()

    expect(await screen.findByText('观察留痕')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '前往策略中心配置' })).toBeInTheDocument()
    expect(screen.queryByText(/文件正文检测/)).not.toBeInTheDocument()
    expect(screen.queryByText(/SECURITY_FILE_CONTENT_DLP_ENABLED|file_content_dlp_enabled|security_audit_only/)).not.toBeInTheDocument()
  })

  it('保存失败时恢复服务端原状态，不出现假成功', async () => {
    mockApi.get.mockResolvedValue({
      data: {
        allow_registration: 'false',
        content_audit_enabled: 'false',
        tool_audit_enabled: 'false',
        security_execution_mode: { configured_mode: 'record', effective_mode: 'record', locked: false, source: 'admin_settings', runtime_verified: true, runtime_status: 'verified' },
        file_content_dlp_enabled: 'false',
        log_retention_days: '90',
      },
    })
    mockApi.put.mockRejectedValue(new Error('network'))

    renderPage()
    const sw = await screen.findByLabelText('开放自助注册')
    await userEvent.click(sw) // 用户切到开
    expect(sw).toBeChecked()
    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))

    // 保存失败后，UI 必须恢复为服务端原状态（关），不能显示已开启但运行态未生效。
    await waitFor(() => {
      expect(sw).not.toBeChecked()
    })
    expect(mockApi.put).toHaveBeenCalledTimes(1)
  })

  it('告警自动关闭：开关与天数随所填天数更新说明并按库优先口径保存', async () => {
    mockApi.get.mockResolvedValue({ data: { log_retention_days: '90', alert_ttl_enabled: 'false', alert_group_ttl_days: '14' } })
    mockApi.put.mockResolvedValue({ data: {} })
    renderPage()

    const sw = await screen.findByLabelText('自动关闭陈旧告警')
    await waitFor(() => expect(sw).not.toBeChecked())
    const days = screen.getByLabelText('自动关闭天数')
    await waitFor(() => expect(days).toHaveValue('14'))
    expect(days).toHaveAttribute('aria-valuemin', '1')
    expect(days).toHaveAttribute('aria-valuemax', '365')
    expect(screen.getByText('只自动关闭 14 天无新发生的输入侧告警，高危类型（密钥泄露、诱饵命中等）不自动关闭')).toBeInTheDocument()

    await userEvent.click(sw)
    await userEvent.clear(days)
    await userEvent.type(days, '30')
    expect(await screen.findByText('只自动关闭 30 天无新发生的输入侧告警，高危类型（密钥泄露、诱饵命中等）不自动关闭')).toBeInTheDocument()
    // 不破坏留存天数一项。
    expect(screen.getByLabelText('日志与内容留存天数')).toHaveValue('90')

    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalledWith('/system/settings', expect.objectContaining({
      alert_ttl_enabled: true,
      alert_group_ttl_days: 30,
      log_retention_days: 90,
    })))
  })

  it('告警自动关闭天数超出 1~365 时拒绝保存', async () => {
    mockApi.get.mockResolvedValue({ data: { log_retention_days: '90', alert_ttl_enabled: 'true', alert_group_ttl_days: '14' } })
    mockApi.put.mockResolvedValue({ data: {} })
    renderPage()
    const days = await screen.findByLabelText('自动关闭天数')
    await waitFor(() => expect(days).toHaveValue('14'))
    await userEvent.clear(days)
    await userEvent.click(screen.getByRole('button', { name: /保存设置/ }))
    expect(await screen.findByText('请输入自动关闭天数')).toBeInTheDocument()
    expect(mockApi.put).not.toHaveBeenCalled()
  })
})
