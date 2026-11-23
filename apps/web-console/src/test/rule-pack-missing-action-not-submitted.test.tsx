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
  return { ...actual, message: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }
})

// 批次 4 把 rule_pack_missing_action 从可写键里移除，PUT 带上它会 400。
const KEY = 'rule_pack_missing_action'


describe('控制台不提交 rule_pack_missing_action', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true })
    vi.spyOn(api, 'get').mockResolvedValue({ data: { [KEY]: 'block', log_retention_days: 90, alert_group_ttl_days: 14, guardrail_fail_closed_enabled: 'false' } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(billingEmployeeApi, 'settings').mockResolvedValue({ data: { data: { currency: 'CNY' } } } as never)
  })


  it('读到这个键后，系统设置各处保存都不回写它', async () => {
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        <SystemSettings />
      </QueryClientProvider>,
    )
    const saveAll = await screen.findByRole('button', { name: /保存设置/ })
    await waitFor(() => expect(screen.getByLabelText('日志与内容留存天数')).toHaveValue('90'))
    await user.click(saveAll)
    const failure = screen.getByRole('region', { name: '故障处理' })
    await chooseOption(within(failure).getByRole('combobox', { name: '安全检测不可用' }), '拦截')
    await user.click(within(failure).getByRole('button', { name: '保存故障处理' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledTimes(2))
    for (const [, body] of vi.mocked(api.put).mock.calls) {
      expect(Object.keys(body as Record<string, unknown>)).not.toContain(KEY)
    }
  })
})
