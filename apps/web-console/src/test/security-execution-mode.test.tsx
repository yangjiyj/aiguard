import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConfigProvider, message } from 'antd'
import SecurityExecutionModeCard from '../components/SecurityExecutionModeCard'
import { effectiveSecurityAction, normalizeSecurityExecutionMode, type SecurityExecutionMode } from '../services/securityExecutionMode'
import api from '../services/api'

vi.mock('../services/api', () => ({ default: { get: vi.fn(), put: vi.fn() } }))
vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

const mode: SecurityExecutionMode = {
  configured_mode: 'protect',
  effective_mode: 'protect',
  locked: false,
  source: 'admin_settings',
  runtime_verified: true,
  runtime_status: 'verified',
  last_modified_by: '管理员',
  last_modified_at: '2026-08-25T06:00:00Z',
}
const initialRecord: SecurityExecutionMode = {
  ...mode,
  configured_mode: 'record',
  effective_mode: 'record',
  source: 'deployment',
  runtime_verified: false,
  runtime_status: 'pending',
}

function renderCard(canManage = true, serverMode = mode) {
  vi.mocked(api.get).mockResolvedValue({ data: { security_execution_mode: serverMode } } as never)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><ConfigProvider theme={{ token: { motion: false } }}><SecurityExecutionModeCard canManage={canManage} /></ConfigProvider></QueryClientProvider>)
}

describe('全局安全执行模式', () => {
  beforeEach(() => vi.resetAllMocks())

  it('集中映射后端契约且不猜默认值', () => {
    expect(normalizeSecurityExecutionMode({ security_execution_mode: mode })).toEqual(mode)
    expect(normalizeSecurityExecutionMode({})).toBeUndefined()
    expect(effectiveSecurityAction('block', 'record')).toBe('记录/告警放行')
  })

  it('展示配置、实际、来源、回执和最近修改', async () => {
    renderCard()
    expect(await screen.findByText('防护阻断正在运行')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '全局防护模式' })).toBeInTheDocument()
    expect(screen.getByText('配置模式')).toBeInTheDocument()
    expect(screen.getByText('客户模式')).toBeInTheDocument()
    expect(screen.getByText('配置来源')).toBeInTheDocument()
    expect(screen.getByText('系统设置')).toBeInTheDocument()
    expect(screen.getAllByText('运行已确认').length).toBeGreaterThan(0)
    expect(screen.getByText(/全局模式控制策略可执行的最高处置级别/)).toBeInTheDocument()
  })

  it('非平台管理员不能切换或保存当前模式', async () => {
    renderCard(false, initialRecord)
    expect(await screen.findByText('观察留痕待同步')).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '防护阻断' })).toBeDisabled()
    expect(screen.getByRole('radio', { name: '观察留痕' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存当前模式' })).toBeDisabled()
    expect(screen.getByText(/只有平台管理员可以修改/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '防护阻断' }))
    fireEvent.click(screen.getByRole('button', { name: '保存当前模式' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(api.put).not.toHaveBeenCalled()
  })

  it('仅确认后发送 PUT，并展示记录模式影响文案', async () => {
    const user = userEvent.setup()
    vi.mocked(api.put).mockResolvedValue({ data: {} } as never)
    renderCard()
    const recordRadio = await screen.findByRole('radio', { name: '观察留痕' })
    await waitFor(() => expect(recordRadio).toBeEnabled())
    fireEvent.click(recordRadio)
    expect(api.put).not.toHaveBeenCalled()
    expect(screen.getByText(/主动处置将停止/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确认并应用' })).toBeDisabled()
    await user.type(screen.getByLabelText('变更原因'), '应急降级演练')
    await user.click(screen.getByRole('button', { name: '确认并应用' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/system/settings', { security_execution_mode: 'record', change_reason: '应急降级演练' }))
  })

  it('旧安装审计模式可在界面切换保护，运行回执确认前不宣称生效', async () => {
    const user = userEvent.setup()
    renderCard(true, initialRecord)
    const protectRadio = await screen.findByRole('radio', { name: '防护阻断' })
    await waitFor(() => expect(protectRadio).toBeEnabled())
    expect(screen.getByText(/当前沿用安装时的观察留痕配置/)).toBeInTheDocument()
    expect(screen.getByText('安装初始配置')).toBeInTheDocument()
    expect(screen.queryByText(/已锁定|环境变量|后台命令/)).not.toBeInTheDocument()
    expect(screen.getByText('观察留痕待同步')).toBeInTheDocument()
    fireEvent.click(protectRadio)
    expect(api.put).not.toHaveBeenCalled()
    expect(screen.getByText(/命中策略的业务请求可能被脱敏、要求人工确认或阻断/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确认并应用' })).toBeDisabled()
    await user.type(screen.getByLabelText('变更原因'), '  客户启用正式防护  ')
    vi.mocked(api.put).mockResolvedValue({ data: {} } as never)
    vi.mocked(api.get).mockResolvedValue({ data: { security_execution_mode: { ...mode, effective_mode: 'record', runtime_verified: false, runtime_status: 'pending' } } } as never)
    await user.click(screen.getByRole('button', { name: '确认并应用' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/system/settings', { security_execution_mode: 'protect', change_reason: '客户启用正式防护' }))
    expect(await screen.findByText('防护阻断待同步')).toBeInTheDocument()
    expect(screen.queryByText(/正在运行/)).not.toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(protectRadio).toBeChecked()
    vi.mocked(api.get).mockResolvedValue({ data: { security_execution_mode: mode } } as never)
    await user.click(screen.getByRole('button', { name: '刷新状态' }))
    expect(await screen.findByText('防护阻断正在运行')).toBeInTheDocument()
    expect(screen.queryByText(/当前沿用安装时/)).not.toBeInTheDocument()
  })

  // 2.9.22 去掉部署只审计锁：即使旧后端仍返回 locked=true，也不再禁用防护阻断。
  it('locked 不再禁用防护阻断', async () => {
    renderCard(true, { ...initialRecord, locked: true, source: 'deployment', runtime_verified: true, runtime_status: 'verified' })
    const protect = await screen.findByRole('radio', { name: '防护阻断' })
    await waitFor(() => expect(protect).toBeEnabled())
    expect(screen.queryByText(/部署已锁定为观察留痕/)).not.toBeInTheDocument()
    expect(screen.queryByText('部署锁定')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '防护阻断' }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
  })

  it('初始观察留痕可保存当前模式，显式持久化而无需先切换保护', async () => {
    const user = userEvent.setup()
    renderCard(true, initialRecord)
    const saveButton = await screen.findByRole('button', { name: '保存当前模式' })
    await waitFor(() => expect(saveButton).toBeEnabled())
    await user.click(saveButton)
    expect(screen.getByRole('dialog', { name: '确认切换为观察留痕' })).toBeInTheDocument()
    expect(api.put).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('变更原因'), '客户试运行阶段保持观察')
    vi.mocked(api.put).mockResolvedValue({ data: {} } as never)
    vi.mocked(api.get).mockResolvedValue({ data: { security_execution_mode: { ...initialRecord, source: 'admin_settings' } } } as never)
    await user.click(screen.getByRole('button', { name: '确认并应用' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/system/settings', { security_execution_mode: 'record', change_reason: '客户试运行阶段保持观察' }))
    expect(await screen.findByText('系统设置')).toBeInTheDocument()
  })

  it('取消确认不会保存或改变服务端模式', async () => {
    const user = userEvent.setup()
    renderCard(true, initialRecord)
    const protectRadio = await screen.findByRole('radio', { name: '防护阻断' })
    await waitFor(() => expect(protectRadio).toBeEnabled())
    fireEvent.click(protectRadio)
    await user.click(screen.getByRole('button', { name: /取\s*消/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByRole('radio', { name: '观察留痕' })).toBeChecked()
    expect(api.put).not.toHaveBeenCalled()
  })

  it('保存失败展示错误并保留服务端模式与变更原因供重试', async () => {
    const user = userEvent.setup()
    vi.mocked(api.put).mockRejectedValue(new Error('network error'))
    renderCard(true, initialRecord)
    const protectRadio = await screen.findByRole('radio', { name: '防护阻断' })
    await waitFor(() => expect(protectRadio).toBeEnabled())
    fireEvent.click(protectRadio)
    await user.type(screen.getByLabelText('变更原因'), '启用客户防护')
    await user.click(screen.getByRole('button', { name: '确认并应用' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('保存失败，页面将继续显示服务端原值'))
    expect(screen.getByRole('radio', { name: '观察留痕' })).toBeChecked()
    expect(screen.getByLabelText('变更原因')).toHaveValue('启用客户防护')
    expect(screen.queryByText('防护阻断正在运行')).not.toBeInTheDocument()
    expect(message.success).not.toHaveBeenCalled()
  })

  it('服务端拒绝权限时不显示保存成功', async () => {
    const user = userEvent.setup()
    vi.mocked(api.put).mockRejectedValue({ response: { status: 403, data: { error: { message: '只有平台管理员可以修改全局模式' } } } })
    renderCard(true, initialRecord)
    const protectRadio = await screen.findByRole('radio', { name: '防护阻断' })
    await waitFor(() => expect(protectRadio).toBeEnabled())
    fireEvent.click(protectRadio)
    await user.type(screen.getByLabelText('变更原因'), '启用保护')
    await user.click(screen.getByRole('button', { name: '确认并应用' }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('只有平台管理员可以修改全局模式'))
    expect(screen.getByRole('radio', { name: '观察留痕' })).toBeChecked()
    expect(message.success).not.toHaveBeenCalled()
  })

  it.each([
    ['record', 'verified'],
    ['record', 'applied'],
    ['protect', 'verified'],
    ['protect', 'pending'],
    ['protect', 'failed'],
  ] as const)('没有运行确认时 %s / %s 仅展示待同步', async (value, status) => {
    renderCard(true, { ...mode, configured_mode: value, effective_mode: value, runtime_verified: false, runtime_status: status })
    expect(await screen.findByText(value === 'record' ? '观察留痕待同步' : '防护阻断待同步')).toBeInTheDocument()
    expect(screen.queryByText(/正在运行/)).not.toBeInTheDocument()
    expect(screen.queryByText('运行已确认')).not.toBeInTheDocument()
    expect(screen.getAllByText('待运行确认').length).toBeGreaterThan(0)
  })
})
