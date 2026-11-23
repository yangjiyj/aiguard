import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { message } from 'antd'
import AlertGroupBacklog from '../components/AlertGroupBacklog'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'

// 测试数据：消息中心「告警组积压处置」区块。客户可见，不得露出英文枚举或技术 id。
const groups = [
  { id: 'ag_test_1', severity: 'high', status: 'open', type: 'security_event', title: '安全事件【高危】数据安全 · 处置：审计', rule_name: '国内银行卡号', occurrence_count: 12, first_seen_at: '2026-09-01T01:00:00Z', last_seen_at: '2026-09-02T01:00:00Z' },
  { id: 'ag_test_2', severity: 'medium', status: 'open', type: 'runtime_fault', title: '检测运行故障 · 处置：审计', rule_name: '', occurrence_count: 3, first_seen_at: '2026-09-01T01:00:00Z', last_seen_at: '2026-09-03T01:00:00Z' },
  { id: 'ag_test_3', severity: 'low', status: 'open', type: 'access_governance', title: '模型访问策略通知', rule_name: '', occurrence_count: 1, first_seen_at: '2026-09-01T01:00:00Z', last_seen_at: '2026-09-04T01:00:00Z' },
]

describe('AlertGroupBacklog', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.restoreAllMocks()
    useAuthStore.setState({ user: { id: 'u1', username: 'admin', role: 'platform_admin' }, isAuthenticated: true, token: 't' })
  })

  const renderBlock = () => render(
    <QueryClientProvider client={queryClient}><AlertGroupBacklog timezone="Asia/Shanghai" /></QueryClientProvider>,
  )

  const rowCheckbox = (title: string) => {
    const row = screen.getByText(title).closest('tr') as HTMLElement
    return within(row).getByRole('checkbox')
  }

  it('lists open alert groups in Chinese without raw enums or ids', async () => {
    const list = vi.spyOn(api.alertGroupApi, 'list').mockResolvedValue({ data: { items: groups, total: 3, limit: 50, offset: 0 } } as any)
    renderBlock()
    expect(await screen.findByText('国内银行卡号')).toBeInTheDocument()
    expect(list).toHaveBeenCalledWith({ status: 'open', limit: 50, offset: 0 })
    expect(screen.getAllByText('运行故障').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('访问治理').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('共 3 个告警组')).toBeInTheDocument()
    const block = screen.getByLabelText('告警组积压处置')
    for (const raw of ['security_event', 'runtime_fault', 'access_governance', 'ag_test_1', 'open', 'false_positive']) {
      expect(within(block).queryByText(new RegExp(`^${raw}$`))).not.toBeInTheDocument()
      expect(block.textContent).not.toContain(raw)
    }
  })

  it('passes type and rule filters to the server', async () => {
    const list = vi.spyOn(api.alertGroupApi, 'list').mockResolvedValue({ data: { items: groups, total: 3, limit: 50, offset: 0 } } as any)
    renderBlock()
    await screen.findByText('国内银行卡号')

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '按告警类型筛选' }))
    fireEvent.click(await screen.findByTitle('运行故障'))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ status: 'open', type: 'runtime_fault', limit: 50, offset: 0 }))

    const ruleBox = screen.getByRole('searchbox', { name: '按规则筛选' })
    fireEvent.change(ruleBox, { target: { value: '国内银行卡号' } })
    fireEvent.keyDown(ruleBox, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ status: 'open', type: 'runtime_fault', rule: '国内银行卡号', limit: 50, offset: 0 }))
  })

  it('confirms the count, sends only checked ids and reports success/failure counts', async () => {
    vi.spyOn(api.alertGroupApi, 'list').mockResolvedValue({ data: { items: groups, total: 3, limit: 50, offset: 0 } } as any)
    const batch = vi.spyOn(api.alertGroupApi, 'batchStatus').mockResolvedValue({ data: { requested: 2, updated: 1, failed: [{ id: 'ag_test_2', reason: 'not_open' }] } } as any)
    const warn = vi.spyOn(message, 'warning').mockImplementation(() => undefined as any)
    renderBlock()
    await screen.findByText('国内银行卡号')

    const fpButton = screen.getByRole('button', { name: '批量标记误报' })
    expect(fpButton).toBeDisabled()
    fireEvent.click(rowCheckbox('安全事件【高危】数据安全 · 处置：审计'))
    fireEvent.click(rowCheckbox('检测运行故障 · 处置：审计'))
    expect(screen.getByText('已选 2 个')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '批量标记误报' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('确认批量标记误报')).toBeInTheDocument()
    expect(dialog.textContent).toContain('将对选中的 2 个告警组执行「标记误报」')
    fireEvent.change(within(dialog).getByLabelText('处置说明'), { target: { value: '测试规则误报' } })
    expect(batch).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: /确认标记误报 2 个/ }))

    await waitFor(() => expect(batch).toHaveBeenCalledTimes(1))
    const body = batch.mock.calls[0][0]
    expect(body.ids).toEqual(['ag_test_1', 'ag_test_2'])
    expect(body.status).toBe('false_positive')
    expect(body.note).toBe('测试规则误报')
    expect(body.filters).toMatchObject({ status: 'open' })
    await waitFor(() => expect(warn).toHaveBeenCalledWith('标记误报：成功 1 个，失败 1 个'))
    expect(await screen.findByText('批量标记误报完成：成功 1 个，失败 1 个')).toBeInTheDocument()
    expect(screen.getByText('状态已变化（已被处置或不处于待处置）：1 个')).toBeInTheDocument()
    expect(screen.queryByText(/not_open/)).not.toBeInTheDocument()
  })

  it('cancelling the confirmation sends nothing', async () => {
    vi.spyOn(api.alertGroupApi, 'list').mockResolvedValue({ data: { items: groups, total: 3, limit: 50, offset: 0 } } as any)
    const batch = vi.spyOn(api.alertGroupApi, 'batchStatus')
    renderBlock()
    await screen.findByText('国内银行卡号')
    fireEvent.click(rowCheckbox('模型访问策略通知'))
    fireEvent.click(screen.getByRole('button', { name: '批量关闭' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toContain('将对选中的 1 个告警组执行「关闭」')
    fireEvent.click(within(dialog).getByRole('button', { name: /取\s*消/ }))
    // antd Modal 的离场动画在 jsdom 中不会结束，这里以"已进入离场状态 + 未发请求"为准。
    await waitFor(() => expect(dialog.className).toContain('ant-zoom-leave'))
    expect(batch).not.toHaveBeenCalled()
    expect(screen.getByText('已选 1 个')).toBeInTheDocument()
  })

  it('read-only roles see the list without selection or batch buttons', async () => {
    useAuthStore.setState({ user: { id: 'u2', username: 'aud', role: 'auditor' } })
    vi.spyOn(api.alertGroupApi, 'list').mockResolvedValue({ data: { items: groups, total: 3, limit: 50, offset: 0 } } as any)
    renderBlock()
    await screen.findByText('国内银行卡号')
    expect(screen.queryByRole('button', { name: '批量确认' })).not.toBeInTheDocument()
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
  })
})
