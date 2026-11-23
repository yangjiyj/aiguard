import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { Modal, message } from 'antd'
import { DetectionExecutionSettings, FailureHandlingSettings } from '../pages/system-settings/SecuritySettingsSections'
import { ForwardProxyEgressForm } from '../pages/ForwardProxyEgress'
import IdentityEgressSettings from '../components/identity/IdentityEgressSettings'
import AgentGuard from '../pages/AgentGuard'
import api from '../services/api'
import { useAuthStore } from '../stores/auth'
import { chooseOption, last } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }
})

const REJECT = { response: { data: { error: { code: 'invalid_request', message: '后端拒绝了这次保存' } } } }

function wrap(node: JSX.Element) {
  return render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>{node}</QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('设置表单保存失败保留输入，互不覆盖', () => {
  afterEach(() => Modal.destroyAll())
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.mocked(message.error).mockClear()
    useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true })
    vi.spyOn(api, 'get').mockResolvedValue({ data: { semantic_block_stages: '["input"]' } } as never)
    vi.spyOn(api, 'put').mockRejectedValue(REJECT)
  })

  it('故障处理保存失败：提示后端原因，保留选择', async () => {
    wrap(<FailureHandlingSettings canManage />)
    const section = await screen.findByRole('region', { name: '故障处理' })
    const guardrail = within(section).getByRole('combobox', { name: '安全检测不可用' })
    await waitFor(() => expect(guardrail).toBeEnabled())
    await chooseOption(guardrail, '拦截')
    await userEvent.click(within(section).getByRole('button', { name: '保存故障处理' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('后端拒绝了这次保存'))
    expect(guardrail.closest('.ant-select')).toHaveTextContent('拦截')
  })

  it('检测执行保存失败：提示后端原因，保留选择', async () => {
    wrap(<DetectionExecutionSettings canManage />)
    const section = await screen.findByRole('region', { name: '检测执行' })
    const monitor = within(section).getByRole('combobox', { name: '智能体安全监测' })
    await waitFor(() => expect(monitor).toBeEnabled())
    await chooseOption(monitor, '按策略')
    await userEvent.click(within(section).getByRole('button', { name: '保存检测执行' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('后端拒绝了这次保存'))
    expect(monitor.closest('.ant-select')).toHaveTextContent('按策略')
  })

  it('一个区块保存成功后刷新，不覆盖另一个区块还没保存的改动', async () => {
    vi.mocked(api.put).mockResolvedValue({ data: {} } as never)
    wrap(<><FailureHandlingSettings canManage /><DetectionExecutionSettings canManage /></>)
    const detection = await screen.findByRole('region', { name: '检测执行' })
    const monitor = within(detection).getByRole('combobox', { name: '智能体安全监测' })
    await waitFor(() => expect(monitor).toBeEnabled())
    await chooseOption(monitor, '按策略')
    const failure = screen.getByRole('region', { name: '故障处理' })
    await chooseOption(within(failure).getByRole('combobox', { name: '安全检测不可用' }), '拦截')
    vi.mocked(api.get).mockResolvedValue({ data: { semantic_block_stages: '["input"]', guardrail_fail_closed_enabled: 'true' } } as never)
    await userEvent.click(within(failure).getByRole('button', { name: '保存故障处理' }))
    await waitFor(() => expect(api.get).toHaveBeenCalledTimes(2))
    expect(monitor.closest('.ant-select')).toHaveTextContent('按策略')
  })

  it('只提交本人改动过的键，别人改过而本人没动的键不写回旧值', async () => {
    vi.mocked(api.put).mockResolvedValue({ data: {} } as never)
    wrap(<><FailureHandlingSettings canManage /><DetectionExecutionSettings canManage /></>)
    const failure = await screen.findByRole('region', { name: '故障处理' })
    const guardrail = within(failure).getByRole('combobox', { name: '安全检测不可用' })
    await waitFor(() => expect(guardrail).toBeEnabled())
    await chooseOption(guardrail, '拦截')
    // 别人在此期间把“日志留存不可用”改成了拦截；检测执行区块保存后刷新会读到它。
    vi.mocked(api.get).mockResolvedValue({ data: { semantic_block_stages: '["input"]', retention_failure_mode: 'closed' } } as never)
    const detection = screen.getByRole('region', { name: '检测执行' })
    await chooseOption(within(detection).getByRole('combobox', { name: '智能体安全监测' }), '按策略')
    await userEvent.click(within(detection).getByRole('button', { name: '保存检测执行' }))
    await waitFor(() => expect(api.get).toHaveBeenCalledTimes(2))
    vi.mocked(api.put).mockClear()
    await userEvent.click(within(failure).getByRole('button', { name: '保存故障处理' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', { guardrail_fail_closed_enabled: true }))
  })

  it('保存期间表单禁用', async () => {
    vi.mocked(api.put).mockReturnValue(new Promise(() => {}) as never)
    wrap(<FailureHandlingSettings canManage />)
    const section = await screen.findByRole('region', { name: '故障处理' })
    const guardrail = within(section).getByRole('combobox', { name: '安全检测不可用' })
    await waitFor(() => expect(guardrail).toBeEnabled())
    await chooseOption(guardrail, '拦截')
    await userEvent.click(within(section).getByRole('button', { name: '保存故障处理' }))
    await waitFor(() => expect(within(section).getByRole('combobox', { name: '日志留存不可用' })).toBeDisabled())
  })

  it('出站限制保存失败：提示后端原因，保留已打开的开关', async () => {
    const user = userEvent.setup()
    wrap(<ForwardProxyEgressForm canManage />)
    const section = await screen.findByRole('region', { name: '出站限制' })
    const toggle = within(section).getByRole('switch', { name: '允许访问回环地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    await user.click(toggle)
    const confirm = last(await screen.findAllByText('网关可被用来访问这些地址。')).closest('.ant-modal') as HTMLElement
    await user.click(within(confirm).getByRole('button', { name: '确认打开' }))
    await user.click(within(section).getByRole('button', { name: '保存出站限制' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('后端拒绝了这次保存'))
    expect(toggle).toBeChecked()
  })

  it('身份源出站地址保存失败：提示后端原因，保留输入', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: { idp_block_private: 'true' } } as never)
    const user = userEvent.setup()
    wrap(<IdentityEgressSettings canManage />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    await user.click(toggle)
    const confirm = last(await screen.findAllByText('控制面可被用来访问这些地址。')).closest('.ant-modal') as HTMLElement
    await user.click(within(confirm).getByRole('button', { name: '确认打开' }))
    await user.click(screen.getByRole('button', { name: '保存出站地址' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('后端拒绝了这次保存'))
    expect(toggle).toBeChecked()
  })

  it('本人批准保存失败：提示后端原因，开关回到服务端值', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => (url === '/system/settings' ? { data: {} } : { data: { data: [] } }) as never)
    const user = userEvent.setup()
    wrap(<AgentGuard />)
    await user.click(await screen.findByRole('tab', { name: '待确认操作' }))
    const toggle = await screen.findByRole('switch', { name: '允许本人批准' })
    await waitFor(() => expect(toggle).toBeEnabled())
    await user.click(toggle)
    const confirm = last(await screen.findAllByText('触发确认的人可以自己批准这次操作。')).closest('.ant-modal') as HTMLElement
    await user.click(within(confirm).getByRole('button', { name: '确认打开' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('后端拒绝了这次保存'))
    expect(toggle).not.toBeChecked()
  })
})
