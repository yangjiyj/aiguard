import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SystemSettings from '../pages/SystemSettings'
import api, { billingEmployeeApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { chooseOption } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

function renderPage(role = 'platform_admin', tenant_id = 'tenant_default') {
  useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role, tenant_id }, isAuthenticated: true })
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <SystemSettings />
    </QueryClientProvider>,
  )
}

describe('系统设置：故障处理与检测执行', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api, 'get').mockResolvedValue({ data: { guardrail_fail_closed_enabled: 'false', semantic_block_stages: '["input"]', log_retention_days: 90 } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(billingEmployeeApi, 'settings').mockResolvedValue({ data: { data: { currency: 'CNY' } } } as never)
  })

  it('故障处理：各项可选放行并告警或拦截，只提交本区块的键', async () => {
    renderPage()
    const section = await screen.findByRole('region', { name: '故障处理' })
    const guardrail = within(section).getByRole('combobox', { name: '安全检测不可用' })
    await waitFor(() => expect(guardrail).toBeEnabled())
    await chooseOption(guardrail, '拦截')
    // 与告警原因同名。
    await chooseOption(within(section).getByRole('combobox', { name: '日志留存不可用' }), '拦截')
    await userEvent.click(within(section).getByRole('button', { name: '保存故障处理' }))
    // 只提交改动过的键，没改的（含环境变量或默认值折算的显示值）不回写。
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', {
      guardrail_fail_closed_enabled: true,
      retention_failure_mode: 'closed',
    }))
  })

  it('检测执行：输出检测方式、可拦截阶段、置信度降级、智能体监测', async () => {
    const user = userEvent.setup()
    renderPage()
    const section = await screen.findByRole('region', { name: '检测执行' })
    const output = within(section).getByRole('combobox', { name: '模型输出检测' })
    await waitFor(() => expect(output).toBeEnabled())
    await chooseOption(output, '缓冲严格')
    await user.type(await within(section).findByRole('spinbutton', { name: '缓冲上限（字节）' }), '65536')
    await chooseOption(within(section).getByRole('combobox', { name: '智能分析可拦截的阶段' }), '输出')
    // 键缺失时按后端默认：门控开、阈值 0.55；只改阈值时只提交阈值。
    expect(within(section).getByRole('switch', { name: '低置信度降为告警' })).toBeChecked()
    const threshold = await within(section).findByRole('spinbutton', { name: '置信度阈值' })
    expect(threshold).toHaveValue('0.55')
    await user.clear(threshold)
    await user.type(threshold, '0.6')
    await chooseOption(within(section).getByRole('combobox', { name: '智能体安全监测' }), '按策略')
    await user.click(within(section).getByRole('button', { name: '保存检测执行' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', {
      output_security_mode: 'strict_buffered',
      output_strict_max_bytes: 65536,
      confidence_threshold: 0.6,
      semantic_block_stages: '["input","output"]',
      agent_security_monitor_disposition: 'follow_policy',
    }))
  })

  it('缓冲上限与可拦截阶段按后端范围校验', async () => {
    const user = userEvent.setup()
    renderPage()
    const section = await screen.findByRole('region', { name: '检测执行' })
    const output = within(section).getByRole('combobox', { name: '模型输出检测' })
    await waitFor(() => expect(output).toBeEnabled())
    await chooseOption(output, '缓冲严格')
    await user.type(await within(section).findByRole('spinbutton', { name: '缓冲上限（字节）' }), '100')
    const stages = within(section).getByRole('combobox', { name: '智能分析可拦截的阶段' })
    await user.click(within(stages.closest('.ant-select') as HTMLElement).getByLabelText('close'))
    await user.click(within(section).getByRole('button', { name: '保存检测执行' }))
    expect(await within(section).findByText('需在 1024 到 67108864 之间')).toBeInTheDocument()
    expect(within(section).getByText('至少选一个阶段')).toBeInTheDocument()
    expect(api.put).not.toHaveBeenCalled()
  })

  it('租户级安全员只读', async () => {
    renderPage('security_officer', 'tenant-a')
    const section = await screen.findByRole('region', { name: '故障处理' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(within(section).getByRole('combobox', { name: '安全检测不可用' })).toBeDisabled()
  })

  it('安全员可改，审计员只读', async () => {
    const { unmount } = renderPage('security_officer')
    const editable = await screen.findByRole('region', { name: '故障处理' })
    await waitFor(() => expect(within(editable).getByRole('combobox', { name: '安全检测不可用' })).toBeEnabled())
    unmount()
    renderPage('auditor')
    const section = await screen.findByRole('region', { name: '故障处理' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(within(section).getByRole('combobox', { name: '安全检测不可用' })).toBeDisabled()
    expect(within(screen.getByRole('region', { name: '检测执行' })).getByRole('button', { name: '保存检测执行' })).toBeDisabled()
  })
})
