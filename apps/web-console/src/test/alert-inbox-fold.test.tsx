import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { message } from 'antd'
import AlertInbox from '../pages/AlertInbox'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'

// 消息中心「同类消息折叠」视图（默认）+ 管理员批量已读。后端接口全部 mock，按契约 A-E 断言请求参数。
// 时区取 Asia/Shanghai（+8）：2026-10-09T16:00:03Z = 2026-10-10 00:00:03。

const sampleOf = (over: Record<string, unknown> = {}) => ({
  id: 'sample-1', tenant_id: 't1', severity: 'warning', type: 'alert', title: 'governor 事件：alert',
  body_json: { reason: 'model not allowed for team', alert_only: true },
  read_at: null, created_at: '2026-10-10T15:58:10Z', ...over,
})

const groupOf = (over: Record<string, unknown> = {}) => ({
  key: 'g-alert-1', type: 'alert', severity: 'warning', day: '2026-10-10',
  day_start: '2026-10-09T16:00:00Z', day_end: '2026-10-10T16:00:00Z',
  count: 1221, unread_count: 1200, first_at: '2026-10-09T16:00:03Z', last_at: '2026-10-10T15:58:10Z',
  sample: sampleOf(), ...over,
})

const foldedResp = (groups: any[], over: Record<string, unknown> = {}) => ({
  data: { groups, total_groups: groups.length, total_items: groups.reduce((n, g) => n + g.count, 0), unread_count: 20539, timezone: 'Asia/Shanghai', ...over },
})

const detailItem = (n: number, over: Record<string, unknown> = {}) => ({
  id: `item-${n}`, tenant_id: 't1', severity: 'warning', type: 'alert', title: 'governor 事件：alert',
  body_json: { reason: 'model not allowed for team', alert_only: true },
  read_at: null, created_at: `2026-10-10T0${n % 10}:00:00Z`, ...over,
})

const ADMIN = { id: 'u1', username: 'admin', role: 'platform_admin', tenant_id: 't1' }

describe('消息中心：同类消息折叠视图', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.restoreAllMocks()
    useAuthStore.setState({ user: ADMIN, isAuthenticated: true, token: 't' })
    vi.spyOn(api.alertGroupApi, 'list').mockResolvedValue({ data: { items: [], total: 0, limit: 50, offset: 0 } } as any)
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({ data: { timezone: 'Asia/Shanghai' } } as any)
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [] } } as any)
  })

  const renderPage = () =>
    render(<QueryClientProvider client={queryClient}><AlertInbox /></QueryClientProvider>)

  it('默认进入「按天折叠」，显示 ×N、未读 M、首末时间与日期', async () => {
    const folded = vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([groupOf()]) as any)
    renderPage()

    expect(await screen.findByText('×1,221')).toBeInTheDocument()
    expect(screen.getByText('未读 1,200')).toBeInTheDocument()
    expect(screen.getByText('首次 00:00:03 · 末次 23:58:10')).toBeInTheDocument()
    expect(screen.getByText('2026-10-10')).toBeInTheDocument()
    // 折叠视图首次请求：默认仅看未读，服务端按组分页。
    expect(folded).toHaveBeenCalledWith({ unread: true, limit: 20, offset: 0 })
    // Segmented 默认选中「按天折叠」，逐条明细可切换。
    const seg = screen.getByRole('radiogroup', { name: '消息展示方式' })
    const selected = seg.querySelector('.ant-segmented-item-selected')
    expect(selected).toHaveTextContent('按天折叠')
    expect(within(seg).getByText('逐条明细').closest('.ant-segmented-item')).not.toHaveClass('ant-segmented-item-selected')
  })

  it('N=1 也显示 ×1；内容用 sample 的中文标题，详情前加「最近一条：」，来源与风险域为中文', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([groupOf({ count: 1, unread_count: 1 })]) as any)
    renderPage()

    expect(await screen.findByText('×1')).toBeInTheDocument()
    expect(screen.getByText('未读 1')).toBeInTheDocument()
    expect(screen.getByText('模型访问策略通知')).toBeInTheDocument()
    expect(screen.getByText('最近一条：当前团队模型策略仅告警，未阻断请求')).toBeInTheDocument()
    const row = screen.getByText('模型访问策略通知').closest('tr') as HTMLElement
    expect(within(row).getByText('访问与额度治理')).toBeInTheDocument()
    expect(within(row).getAllByText('访问治理').length).toBeGreaterThanOrEqual(1)
  })

  it('页头与统计：共 X 组 / Y 条，页头徽标未读数取响应里的 unread_count', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([groupOf()], { total_groups: 966, total_items: 20539, unread_count: 20539 }) as any)
    renderPage()

    expect(await screen.findByText(/共 966 组 \/ 20,539 条/)).toBeInTheDocument()
    expect(document.querySelector('.ant-badge-count')?.textContent).toContain('20539')
  })

  it('严重度必须有图标 + 文字 + aria-label，不能只靠颜色', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([
      groupOf({ key: 'g-h', severity: 'high', sample: sampleOf({ severity: 'high', type: 'security_event', title: '', body_json: { event_type: 'data_security', action: 'block' } }) }),
    ]) as any)
    renderPage()

    const badge = await screen.findByLabelText('严重度：高危')
    expect(badge).toHaveTextContent('高危')
    expect(badge.querySelector('.anticon')).not.toBeNull()
  })

  it('展开按钮有中文 aria-label；首次展开才请求明细，展示「共 N 条原始消息」且条数等于组 count', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([groupOf({ count: 3, unread_count: 2 })]) as any)
    const items = vi.spyOn(api.ws8AlertInboxApi, 'foldedItems').mockResolvedValue({
      data: { items: [detailItem(1), detailItem(2, { read_at: '2026-10-10T09:00:00Z' }), detailItem(3)], total: 3 },
    } as any)
    renderPage()

    await screen.findByText('×3')
    expect(items).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '展开明细' }))

    expect(await screen.findByText('共 3 条原始消息')).toBeInTheDocument()
    // 明细接口参数全部取自 group 原值，并沿用当前「仅未读」筛选。
    expect(items).toHaveBeenCalledWith({
      key: 'g-alert-1', type: 'alert', severity: 'warning',
      day_start: '2026-10-09T16:00:00Z', day_end: '2026-10-10T16:00:00Z', unread: true, limit: 20, offset: 0,
    })
    const detail = screen.getByLabelText('原始消息明细')
    expect(within(detail).getAllByRole('row').filter((r) => r.getAttribute('data-row-key'))).toHaveLength(3)
    expect(within(detail).getAllByText('未读')).toHaveLength(2)
    expect(within(detail).getAllByText('已读')).toHaveLength(1)
    // 收起后再展开不重复请求。
    fireEvent.click(screen.getByRole('button', { name: '收起明细' }))
    fireEvent.click(screen.getByRole('button', { name: '展开明细' }))
    await screen.findByText('共 3 条原始消息')
    expect(items).toHaveBeenCalledTimes(1)
  })

  it('明细分页：pageSize 20，翻页请求 offset 20，总数来自组 count 不丢条', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([groupOf({ count: 45, unread_count: 45 })]) as any)
    const page = (from: number, to: number) => Array.from({ length: to - from }, (_, i) => detailItem(from + i + 1))
    const items = vi.spyOn(api.ws8AlertInboxApi, 'foldedItems').mockImplementation(((params: any) => Promise.resolve({
      data: { items: params.offset === 0 ? page(0, 20) : page(20, 40), total: 45 },
    })) as any)
    renderPage()

    await screen.findByText('×45')
    fireEvent.click(screen.getByRole('button', { name: '展开明细' }))
    await screen.findByText('共 45 条原始消息')
    const detail = screen.getByLabelText('原始消息明细')
    expect(within(detail).getAllByRole('row').filter((r) => r.getAttribute('data-row-key'))).toHaveLength(20)

    fireEvent.click(within(detail).getByTitle('2'))
    await waitFor(() => expect(items).toHaveBeenLastCalledWith(expect.objectContaining({ key: 'g-alert-1', limit: 20, offset: 20 })))
  })

  it('明细里未读行的「标记已读」调用 alertApi.markRead，成功后刷新折叠列表与明细', async () => {
    const folded = vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([groupOf({ count: 1, unread_count: 1 })]) as any)
    const items = vi.spyOn(api.ws8AlertInboxApi, 'foldedItems').mockResolvedValue({ data: { items: [detailItem(1)], total: 1 } } as any)
    const markRead = vi.spyOn(api.alertApi, 'markRead').mockResolvedValue({ data: {} } as any)
    vi.spyOn(message, 'success').mockImplementation(() => undefined as any)
    renderPage()

    await screen.findByText('×1')
    fireEvent.click(screen.getByRole('button', { name: '展开明细' }))
    const detail = await screen.findByLabelText('原始消息明细')
    await within(detail).findByText('共 1 条原始消息')
    const foldedBefore = folded.mock.calls.length
    const itemsBefore = items.mock.calls.length

    fireEvent.click(within(detail).getByRole('button', { name: /标记已读/ }))
    await waitFor(() => expect(markRead).toHaveBeenCalledWith('item-1'))
    await waitFor(() => expect(folded.mock.calls.length).toBeGreaterThan(foldedBefore))
    await waitFor(() => expect(items.mock.calls.length).toBeGreaterThan(itemsBefore))
  })

  it('筛选联动：「仅显示未读」开关与严重度筛选都传到 folded 接口，并回到第 1 页', async () => {
    const folded = vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([groupOf()]) as any)
    renderPage()
    await screen.findByText('×1,221')

    fireEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(folded).toHaveBeenLastCalledWith({ limit: 20, offset: 0 }))

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '按严重度筛选' }))
    const option = await waitFor(() => {
      const el = document.querySelectorAll('.ant-select-item-option')[1]
      expect(el).toBeTruthy()
      return el as HTMLElement
    })
    fireEvent.click(option)
    await waitFor(() => expect(folded).toHaveBeenLastCalledWith({ severity: 'high', limit: 20, offset: 0 }))
  })

  it('来源(type)筛选传到 folded 接口；风险域 Segmented 在客户端按 sample 的域过滤当前页组', async () => {
    const folded = vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([
      groupOf(),
      groupOf({ key: 'g-skill', type: 'security_event', severity: 'low', sample: sampleOf({ id: 's2', severity: 'low', type: 'security_event', title: '', body_json: { event_type: 'skill_invocation_risk', action: 'audit' } }) }),
    ]) as any)
    renderPage()
    await screen.findByText('模型访问策略通知')
    expect(screen.getAllByText(/Skill 调用风险/).length).toBeGreaterThanOrEqual(1)

    const skillOption = screen.getAllByText('Skill').map((el) => el.closest('.ant-segmented-item')).find(Boolean) as HTMLElement
    fireEvent.click(skillOption)
    await waitFor(() => expect(screen.queryByText('模型访问策略通知')).not.toBeInTheDocument())
    expect(screen.getAllByText(/Skill 调用风险/).length).toBeGreaterThanOrEqual(1)

    fireEvent.click(screen.getByText('全部'))
    await screen.findByText('模型访问策略通知')

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '按来源筛选' }))
    fireEvent.click(await screen.findByTitle('运行故障'))
    await waitFor(() => expect(folded).toHaveBeenLastCalledWith({ type: 'runtime_fault', unread: true, limit: 20, offset: 0 }))
  })

  it('切到「逐条明细」走原有接口且不再请求折叠接口；切回来后再次使用折叠接口', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([groupOf()]) as any)
    const folded = vi.mocked(api.ws8AlertInboxApi.folded)
    const legacy = vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [sampleOf({ id: 'legacy-1' })] } } as any)
    renderPage()
    await screen.findByText('×1,221')
    expect(legacy).not.toHaveBeenCalled() // 折叠视图下不请求旧的逐条接口

    const seg = screen.getByRole('radiogroup', { name: '消息展示方式' })
    fireEvent.click(within(seg).getByText('逐条明细'))
    await waitFor(() => expect(legacy).toHaveBeenCalledWith(true))
    expect(await screen.findByText('模型访问策略通知')).toBeInTheDocument()
    expect(screen.queryByText('×1,221')).not.toBeInTheDocument()
    const foldedCallsInDetail = folded.mock.calls.length

    fireEvent.click(within(seg).getByText('按天折叠'))
    expect(await screen.findByText('×1,221')).toBeInTheDocument()
    expect(folded.mock.calls.length).toBeGreaterThanOrEqual(foldedCallsInDetail)
  })

  it('折叠表格里不出现 governor / reservation_overrun / fail-open / model not allowed 等英文', async () => {
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue(foldedResp([
      groupOf(),
      groupOf({ key: 'g2', sample: sampleOf({ id: 's2', body_json: { reason: 'fail-open: quota error: timeout: ctx' } }) }),
      groupOf({ key: 'g3', type: 'quota.admission.reservation_overrun', sample: sampleOf({ id: 's3', type: 'quota.admission.reservation_overrun', title: 'governor 事件：quota.admission.reservation_overrun', body_json: { reason: 'actual token usage exceeded the conservative reservation' } }) }),
      groupOf({ key: 'g4', type: 'quota.admission.runtime_fault', sample: sampleOf({ id: 's4', type: 'quota.admission.runtime_fault', title: 'governor 事件：quota.admission.runtime_fault', body_json: { reason: 'soft quota observation unavailable' } }) }),
      groupOf({ key: 'g5', type: 'model_route_degraded', sample: sampleOf({ id: 's5', type: 'model_route_degraded', title: '模型仅剩一条健康线路', body_json: { model_name: 'gpt-5.6-sol', provider_ref: 'prov_ab12' } }) }),
      groupOf({ key: 'g6', type: 'weird.kind', sample: sampleOf({ id: 's6', type: 'weird.kind', title: 'governor 事件：weird.kind', body_json: { reason: 'weird english' } }) }),
    ]) as any)
    renderPage()

    expect(await screen.findByText('额度预占不足通知')).toBeInTheDocument()
    expect(screen.getByText('额度检查超时，已放行请求')).toBeInTheDocument()
    expect(screen.getByText('额度观测不可用')).toBeInTheDocument()
    expect(screen.getByText('其它事件')).toBeInTheDocument()
    expect(screen.getByText('最近一条：模型：gpt-5.6-sol')).toBeInTheDocument()
    expect(screen.queryByText(/governor|reservation_overrun|fail-open|model not allowed|runtime_fault|weird|prov_/)).toBeNull()
    expect(screen.getAllByText('访问与额度治理').length).toBeGreaterThanOrEqual(1)
  })
})
