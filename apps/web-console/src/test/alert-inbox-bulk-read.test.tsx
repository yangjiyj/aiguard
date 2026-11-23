import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { message } from 'antd'
import dayjs from 'dayjs'
import AlertInbox from '../pages/AlertInbox'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'

// 管理员专用「把某一类历史通知标为已读」：入口仅控制台管理员可见，三步（选范围 → 预览 → 输入条数二次确认）。
// 后端接口全部 mock，按契约 C/D/E 断言请求。

const FROM = '2026-09-03T16:00:00Z'
const TO = '2026-10-13T16:00:00Z'

const typeSummary = {
  data: {
    types: [
      { type: 'alert', unread: 11944, total: 11944, first_at: '2026-09-04T00:00:00Z', last_at: '2026-10-13T00:00:00Z', bulk_read_allowed: true },
      { type: 'security_event', unread: 30, total: 80, first_at: '2026-09-04T00:00:00Z', last_at: '2026-10-13T00:00:00Z', bulk_read_allowed: false },
      { type: 'mystery.kind', unread: 7, total: 7, bulk_read_allowed: true },
    ],
  },
}

const previewOf = (n: number) => ({ data: { type: 'alert', from: FROM, to: TO, matched_unread: n, first_at: FROM, last_at: TO, timezone: 'Asia/Shanghai' } })

const setRole = (role: string) => useAuthStore.setState({ user: { id: 'u1', username: 'u', role, tenant_id: 't1' }, isAuthenticated: true, token: 't' })

describe('消息中心：管理员批量标为已读', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.restoreAllMocks()
    setRole('platform_admin')
    vi.spyOn(api.alertGroupApi, 'list').mockResolvedValue({ data: { items: [], total: 0, limit: 50, offset: 0 } } as any)
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({ data: { timezone: 'Asia/Shanghai' } } as any)
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue({ data: { groups: [], total_groups: 0, total_items: 0, unread_count: 0, timezone: 'Asia/Shanghai' } } as any)
    vi.spyOn(api.ws8AlertInboxApi, 'typeSummary').mockResolvedValue(typeSummary as any)
  })

  const renderPage = () =>
    render(<QueryClientProvider client={queryClient}><AlertInbox /></QueryClientProvider>)

  it.each(['platform_admin', 'admin', 'tenant_owner', 'tenant_admin'])('%s 能看到「批量标为已读…」按钮', async (role) => {
    setRole(role)
    renderPage()
    expect(await screen.findByRole('button', { name: /批量标为已读/ })).toBeInTheDocument()
  })

  it.each(['viewer', 'security_officer', 'auditor', 'dept_manager'])('%s 看不到「批量标为已读…」按钮，也不会请求类别汇总', async (role) => {
    setRole(role)
    renderPage()
    await screen.findByRole('radiogroup', { name: '消息展示方式' })
    expect(screen.queryByRole('button', { name: /批量标为已读/ })).not.toBeInTheDocument()
    expect(api.ws8AlertInboxApi.typeSummary).not.toHaveBeenCalled()
  })

  const openDialog = async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /批量标为已读/ }))
    return await screen.findByRole('dialog')
  }

  // antd RangePicker 的日期输入：直接对 input 做 change+Enter，避免依赖弹出面板的点选。
  // 选完起始日后组件会重渲染，结束日输入框要重新查询（探针验证过这样写才稳定）。
  const pickRange = (dialog: HTMLElement, start = '2026-09-04', end = '2026-10-13') => {
    const first = dialog.querySelectorAll('.ant-picker-input input')[0]
    fireEvent.mouseDown(first)
    fireEvent.focus(first)
    fireEvent.change(first, { target: { value: start } })
    fireEvent.keyDown(first, { key: 'Enter', keyCode: 13 })
    const second = dialog.querySelectorAll('.ant-picker-input input')[1]
    fireEvent.mouseDown(second)
    fireEvent.focus(second)
    fireEvent.change(second, { target: { value: end } })
    fireEvent.keyDown(second, { key: 'Enter', keyCode: 13 })
  }

  it('类别下拉显示中文类别名 + 未读数；受保护类别 disabled 并说明；未知类别显示「其它类别」附类型码', async () => {
    const dialog = await openDialog()
    expect(api.ws8AlertInboxApi.typeSummary).toHaveBeenCalled()
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '消息类别' }))

    expect(await screen.findByText(/访问与额度治理事件 · 未读 11,944/)).toBeInTheDocument()
    const protectedOpt = screen.getByText(/安全事件 · 未读 30/).closest('.ant-select-item-option') as HTMLElement
    expect(protectedOpt).toHaveClass('ant-select-item-option-disabled')
    expect(screen.getByText(/其它类别/)).toBeInTheDocument()
    expect(screen.getByText('mystery.kind')).toBeInTheDocument()
    expect(within(dialog).getByText('安全告警类消息不支持批量已读，请逐条处理或到告警页按告警组处置')).toBeInTheDocument()
  })

  it('类别和时间范围没选齐前，「查询将影响的条数」按钮禁用', async () => {
    const dialog = await openDialog()
    const query = within(dialog).getByRole('button', { name: '查询将影响的条数' })
    expect(query).toBeDisabled()

    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '消息类别' }))
    fireEvent.click(await screen.findByText(/访问与额度治理事件 · 未读 11,944/))
    expect(query).toBeDisabled() // 只选了类别，时间范围缺失

    pickRange(dialog)
    await waitFor(() => expect(query).toBeEnabled())
  })

  it('预览文案：将把【类别】在 from ～ to 之间的 n 条未读消息标记为已读，并声明不关闭告警/不删数据', async () => {
    const preview = vi.spyOn(api.ws8AlertInboxApi, 'bulkReadPreview').mockResolvedValue(previewOf(11944) as any)
    const dialog = await openDialog()
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '消息类别' }))
    fireEvent.click(await screen.findByText(/访问与额度治理事件 · 未读 11,944/))
    pickRange(dialog)
    const query = within(dialog).getByRole('button', { name: '查询将影响的条数' })
    await waitFor(() => expect(query).toBeEnabled())
    fireEvent.click(query)

    await waitFor(() => expect(preview).toHaveBeenCalledTimes(1))
    // from/to 为租户时区自然日换算出的 RFC3339 窗口（左闭右开）。
    const call = preview.mock.calls[0][0] as any
    expect(call.type).toBe('alert')
    expect(dayjs(call.from).isValid()).toBe(true)
    expect(dayjs(call.to).isAfter(dayjs(call.from))).toBe(true)
    const text = await within(dialog).findByTestId('bulk-read-preview')
    // 文案里的范围是用户选的含当日自然日（后端 to 为次日零点的开区间，直接显示会让人以为多了一天）。
    expect(text).toHaveTextContent('将把【访问与额度治理事件】在 2026-09-04 ～ 2026-10-13 之间的 11,944 条未读消息标记为已读。')
    expect(text).toHaveTextContent('此操作只改变消息中心里的已读状态，不会关闭告警、不会删除或修改任何数据。')
  })

  it('预览为 0 条：提示「该范围内没有未读消息」，不允许继续（没有确认输入框和确认按钮）', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'bulkReadPreview').mockResolvedValue(previewOf(0) as any)
    const bulk = vi.spyOn(api.ws8AlertInboxApi, 'bulkRead').mockResolvedValue({ data: {} } as any)
    const dialog = await openDialog()
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '消息类别' }))
    fireEvent.click(await screen.findByText(/访问与额度治理事件 · 未读 11,944/))
    pickRange(dialog)
    const query = within(dialog).getByRole('button', { name: '查询将影响的条数' })
    await waitFor(() => expect(query).toBeEnabled())
    fireEvent.click(query)

    expect(await within(dialog).findByText('该范围内没有未读消息')).toBeInTheDocument()
    expect(within(dialog).queryByLabelText('输入影响条数以确认')).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: /确认标为已读/ })).not.toBeInTheDocument()
    expect(bulk).not.toHaveBeenCalled()
  })

  const reachConfirmStep = async (n = 11944) => {
    vi.spyOn(api.ws8AlertInboxApi, 'bulkReadPreview').mockResolvedValue(previewOf(n) as any)
    const dialog = await openDialog()
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '消息类别' }))
    fireEvent.click(await screen.findByText(/访问与额度治理事件 · 未读 11,944/))
    pickRange(dialog)
    const query = within(dialog).getByRole('button', { name: '查询将影响的条数' })
    await waitFor(() => expect(query).toBeEnabled())
    fireEvent.click(query)
    await within(dialog).findByTestId('bulk-read-preview')
    return dialog
  }

  it('必须手动输入条数才启用红色确认按钮；输错不启用；确认后以 expected_count 与预览回显的 from/to 调用 bulkRead，并刷新消息列表', async () => {
    const bulk = vi.spyOn(api.ws8AlertInboxApi, 'bulkRead').mockResolvedValue({ data: { ok: true, marked_read: 11944, type: 'alert', from: FROM, to: TO } } as any)
    const success = vi.spyOn(message, 'success').mockImplementation(() => undefined as any)
    const dialog = await reachConfirmStep()
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')

    const confirm = within(dialog).getByRole('button', { name: '确认标为已读（11944 条）' })
    expect(confirm).toBeDisabled()
    expect(confirm).toHaveClass('ant-btn-dangerous')
    const input = within(dialog).getByLabelText('输入影响条数以确认')
    fireEvent.change(input, { target: { value: '11943' } })
    expect(confirm).toBeDisabled()
    fireEvent.change(input, { target: { value: '11944' } })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)

    await waitFor(() => expect(bulk).toHaveBeenCalledWith({ type: 'alert', from: FROM, to: TO, expected_count: 11944, confirm: true }))
    await waitFor(() => expect(success).toHaveBeenCalledWith('已将 11944 条消息标为已读'))
    // jsdom 里 antd 的退场动画不会走完（动画结束事件不触发），弹窗会停在 ant-zoom-leave：视为已关闭。
    await waitFor(() => {
      const d = screen.queryByRole('dialog')
      expect(d === null || d.classList.contains('ant-zoom-leave')).toBe(true)
    })
    // 折叠视图与逐条视图共用 alerts-inbox 前缀的 queryKey，一次 invalidate 全部刷新。
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['alerts-inbox'] })
    // 类别下拉里的未读数缓存也要刷新，否则再次打开弹窗会看到已清零的类别仍显示旧未读数。
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['alerts-inbox-type-summary'] })
  })

  it('409 count_changed：提示范围内未读数已变化（现为 X 条），回到预览步骤并刷新预览，不关闭弹窗', async () => {
    const bulk = vi.spyOn(api.ws8AlertInboxApi, 'bulkRead').mockRejectedValue({
      response: { status: 409, data: { error: { code: 'count_changed', message: 'count changed', details: { current_count: 12001 } } } },
    })
    const error = vi.spyOn(message, 'error').mockImplementation(() => undefined as any)
    const dialog = await reachConfirmStep()
    const preview = vi.mocked(api.ws8AlertInboxApi.bulkReadPreview)
    preview.mockResolvedValue(previewOf(12001) as any)

    fireEvent.change(within(dialog).getByLabelText('输入影响条数以确认'), { target: { value: '11944' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认标为已读（11944 条）' }))

    await waitFor(() => expect(bulk).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(error).toHaveBeenCalledWith('范围内的未读数已变化（现为 12001 条），请重新查询后再确认'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    // 刷新预览：用新的条数重新给出二次确认，旧的输入被清空。
    await waitFor(() => expect(preview.mock.calls.length).toBeGreaterThanOrEqual(2))
    expect(await within(dialog).findByRole('button', { name: '确认标为已读（12001 条）' })).toBeDisabled()
    expect(within(dialog).getByLabelText('输入影响条数以确认')).toHaveValue('')
  })

  it('403：提示「仅管理员可以执行该操作」；其它错误：提示「操作失败，未做任何修改」，都不露英文', async () => {
    const bulk = vi.spyOn(api.ws8AlertInboxApi, 'bulkRead').mockRejectedValueOnce({ response: { status: 403, data: { error: { code: 'forbidden', message: 'forbidden' } } } })
    const error = vi.spyOn(message, 'error').mockImplementation(() => undefined as any)
    const dialog = await reachConfirmStep()

    fireEvent.change(within(dialog).getByLabelText('输入影响条数以确认'), { target: { value: '11944' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认标为已读（11944 条）' }))
    await waitFor(() => expect(error).toHaveBeenLastCalledWith('仅管理员可以执行该操作'))

    bulk.mockRejectedValueOnce({ response: { status: 500, data: { error: { code: 'internal', message: 'boom' } } } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认标为已读（11944 条）' }))
    await waitFor(() => expect(error).toHaveBeenLastCalledWith('操作失败，未做任何修改'))
    expect(error).not.toHaveBeenCalledWith(expect.stringMatching(/forbidden|boom|internal/))
  })

  it('预览阶段 type_protected：提示安全告警类消息不支持批量已读', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'bulkReadPreview').mockRejectedValue({
      response: { status: 400, data: { error: { code: 'type_protected', message: 'protected' } } },
    })
    const error = vi.spyOn(message, 'error').mockImplementation(() => undefined as any)
    const dialog = await openDialog()
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '消息类别' }))
    fireEvent.click(await screen.findByText(/访问与额度治理事件 · 未读 11,944/))
    pickRange(dialog)
    const query = within(dialog).getByRole('button', { name: '查询将影响的条数' })
    await waitFor(() => expect(query).toBeEnabled())
    fireEvent.click(query)

    await waitFor(() => expect(error).toHaveBeenCalledWith('安全告警类消息不支持批量已读，请逐条处理或到告警页按告警组处置'))
    expect(within(dialog).queryByRole('button', { name: /确认标为已读/ })).not.toBeInTheDocument()
  })
})
