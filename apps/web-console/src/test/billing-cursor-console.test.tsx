import { billingSourceLabels, sourceRegex } from './billingSourceLabels'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { BillingWalletTestHarness, BillingLedgerTestHarness } from './BillingWalletTestHarness'
import { useAuthStore } from '../stores/auth'
import * as api from '../services/api'

const response = (data: any) => ({ data: { data } } as any)
const cursorPage = (rows: any[], hasMore: boolean, nextCursor: string) =>
  ({ data: { data: rows, meta: { has_more: hasMore, next_cursor: nextCursor } } } as any)

const customer = (id: string, name: string) => ({
  user_id: id, username: name, email: `${id}@example.com`, customer_group: 'default',
  customer_group_name: '默认客户组', customer_group_status: 'active',
  balance_micros: 5_000_000, reserved_micros: 1_000_000, available_micros: 4_000_000,
  wallet_id: `wallet-${id}`,
})

// jsdom 中动画事件不触发，关闭的弹窗会以各种中间态滞留 DOM，
// 因此按标题唯一定位当前要操作的弹窗
const openModalByTitle = async (title: RegExp) => {
  const find = () => {
    const dialogs = Array.from(document.querySelectorAll('[role="dialog"]')) as HTMLElement[]
    return dialogs.find((d) => title.test(d.querySelector('.ant-modal-title')?.textContent || ''))
  }
  await waitFor(() => expect(find()).toBeTruthy())
  return within(find() as HTMLElement)
}

const clickDropdownItem = async (text: RegExp) => {
  await waitFor(() => {
    const open = document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden)')
    expect(open.length).toBeGreaterThan(0)
  })
  const open = Array.from(document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden)'))
  const items = Array.from(open[open.length - 1].querySelectorAll('.ant-select-item-option-content'))
  const item = items.find((el) => text.test(el.textContent || ''))
  expect(item).toBeTruthy()
  fireEvent.click(item as HTMLElement)
}

describe('客户账本游标分页（opt-in，上一页 cursor 栈）', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    window.sessionStorage.clear()
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue({ data: [
      { id: 'tenant-a', name: 'XX科技' },
      { id: 'tenant-b', name: 'YY集团' },
    ] } as any)
    vi.spyOn(api.billingAdminApi, 'runtime').mockResolvedValue(response({ mode: 'prepaid', description: '预付费' }))
    vi.spyOn(api.billingAdminApi, 'models').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'customerGroups').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'ledger').mockResolvedValue(cursorPage([], false, ''))
    vi.spyOn(api.billingAdminApi, 'prices').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'redemptions').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'tariffs').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'previewTariff').mockResolvedValue(response(null))
  })

  afterEach(() => {
    vi.restoreAllMocks()
    cleanup()
    document.body.innerHTML = ''
    window.sessionStorage.clear()
  })

  const renderPage = () => render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <BillingWalletTestHarness />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('next page carries the server cursor and prev page replays the cursor stack', async () => {
    const user = userEvent.setup()
    // 按游标分派而不是按调用次序：上一页会重新请求第一页，顺序 mock 会错位
    const pages: Record<string, { rows: any[]; hasMore: boolean; next: string }> = {
      '': { rows: [customer('user-a', 'Alice')], hasMore: true, next: 'cursor-2' },
      'cursor-2': { rows: [customer('user-b', 'Bob')], hasMore: true, next: 'cursor-3' },
      'cursor-3': { rows: [customer('user-c', 'Carol')], hasMore: false, next: '' },
    }
    const spy = vi.spyOn(api.billingAdminApi, 'customers').mockImplementation(
      (_tenant: string, cursor?: string) => {
        const page = pages[cursor || '']
        return Promise.resolve(cursorPage(page.rows, page.hasMore, page.next))
      },
    )
    renderPage()
    await user.click(await screen.findByRole('tab', { name: sourceRegex(billingSourceLabels.accounts) }))
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('第 1 页 · 本页 1 条客户')).toBeInTheDocument()

    // 下一页：携带服务端 next_cursor
    const nextButton = () => screen.getByRole('button', { name: '下一页' })
    const prevButton = () => screen.getByRole('button', { name: '上一页' })
    expect(prevButton()).toBeDisabled()
    await user.click(nextButton())
    expect(await screen.findByText('Bob')).toBeInTheDocument()
    expect(spy).toHaveBeenCalledWith('tenant-a', 'cursor-2', 100)
    await waitFor(() => expect(screen.getByText('第 2 页 · 本页 1 条客户')).toBeInTheDocument())

    // 再下一页：第三页无 has_more，「下一页」必须禁用且标注已到最后一页
    await user.click(nextButton())
    expect(await screen.findByText('Carol')).toBeInTheDocument()
    await waitFor(() => expect(nextButton()).toBeDisabled())
    expect(screen.getByText(/已到最后一页/)).toBeInTheDocument()
    expect(screen.queryByText('Alice')).not.toBeInTheDocument()

    // 上一页：从本地游标栈回退到第二页（不是重新拉第一页）
    await user.click(prevButton())
    expect(await screen.findByText('Bob')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('第 2 页 · 本页 1 条客户')).toBeInTheDocument())
    // 上一页从栈里弹出，不需要新的服务端游标，也不回到第一页
    expect(screen.queryByText('Alice')).not.toBeInTheDocument()

    // 回到第一页：请求不带 cursor
    await user.click(prevButton())
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    await waitFor(() => expect(prevButton()).toBeDisabled())
    expect(screen.getByText('第 1 页 · 本页 1 条客户')).toBeInTheDocument()
  })

  it('shows an explicit warning instead of paging when has_more is true but no cursor is given', async () => {
    const user = userEvent.setup()
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue(cursorPage([customer('user-a', 'Alice')], true, ''))
    renderPage()
    await user.click(await screen.findByRole('tab', { name: sourceRegex(billingSourceLabels.accounts) }))
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('服务端称还有更多数据但未返回游标')).toBeInTheDocument()
    // 没有游标就不能翻页，也绝不显示成「已到最后一页」
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
    expect(screen.queryByText(/已到最后一页/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(api.billingAdminApi.customers).toHaveBeenCalledTimes(1)
  })

  it('does not claim a page boundary when the server sends no cursor metadata at all', async () => {
    const user = userEvent.setup()
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue(response([customer('user-a', 'Alice')]))
    renderPage()
    await user.click(await screen.findByRole('tab', { name: sourceRegex(billingSourceLabels.accounts) }))
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    // 没有 has_more 字段：不能据此断言「已到最后一页」
    expect(screen.getByText('游标分页协议异常')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '下一页' })).not.toBeInTheDocument()
    expect(screen.queryByText(/已到最后一页/)).not.toBeInTheDocument()
  })

  it('drops the cursor stack when the tenant changes so page two never replays on another tenant', async () => {
    const user = userEvent.setup()
    const spy = vi.spyOn(api.billingAdminApi, 'customers').mockImplementation(
      (tenant: string, cursor?: string) => Promise.resolve(cursorPage(
        // 每个租户的第一页各一条；第二个租户还备有第二页，用于验证旧栈深不泄漏
        cursor
          ? [customer('user-b2', 'Bob2')]
          : tenant === 'tenant-b'
            ? [customer('user-c', 'Carol')]
            : [customer('user-a', 'Alice')],
        !cursor, cursor ? '' : (tenant === 'tenant-b' ? 'cursor-b2' : 'cursor-a2'),
      )),
    )
    renderPage()
    await user.click(await screen.findByRole('tab', { name: sourceRegex(billingSourceLabels.accounts) }))
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('Bob2')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText(/^第 2 页 · 本页 1 条客户/)).toBeInTheDocument())

    // 切到另一个租户：游标栈作废，回到第 1 页且不带任何游标
    fireEvent.mouseDown(screen.getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByText('YY集团', { selector: '.ant-select-dropdown .ant-select-item-option-content' }))
    expect(await screen.findByText('Carol')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('第 1 页 · 本页 1 条客户')).toBeInTheDocument())
    const lastCall = spy.mock.calls[spy.mock.calls.length - 1]
    expect(lastCall[0]).toBe('tenant-b')
    expect(lastCall[1]).toBe('')
    // 上一页在新的第一页上禁用：旧租户的栈深不泄漏
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
  })

  it('does not declare a paging verdict while the first page is still loading', async () => {
    const user = userEvent.setup()
    let release: (value: any) => void = () => {}
    vi.spyOn(api.billingAdminApi, 'customers').mockImplementation(
      () => new Promise((resolve) => { release = resolve }),
    )
    renderPage()
    await user.click(await screen.findByRole('tab', { name: sourceRegex(billingSourceLabels.accounts) }))
    // 响应未到：既不能说「未启用游标分页」，也不能说「已到最后一页」
    expect(screen.queryByText('服务端称还有更多数据但未返回游标')).not.toBeInTheDocument()
    expect(screen.queryByText(/已到最后一页/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '下一页' })).not.toBeInTheDocument()
    release(cursorPage([customer('user-a', 'Alice')], true, 'cursor-2'))
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    // 响应到达后才按协议给结论
    expect(screen.getByRole('button', { name: '下一页' })).toBeEnabled()
  })

  it('rejects a non-boolean has_more instead of guessing the protocol from truthiness', async () => {
    const user = userEvent.setup()
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue({
      data: { data: [customer('user-a', 'Alice')], meta: { has_more: 'true', next_cursor: 'cursor-2' } },
    } as any)
    renderPage()
    await user.click(await screen.findByRole('tab', { name: sourceRegex(billingSourceLabels.accounts) }))
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    // has_more 是字符串：协议不成立，不能因为'true' 是 truthy 就当成有下一页
    expect(screen.getByText('游标分页协议异常')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '下一页' })).not.toBeInTheDocument()
  })

  it('treats a whitespace-only next_cursor as a protocol defect', async () => {
    const user = userEvent.setup()
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue(cursorPage([customer('user-a', 'Alice')], true, '   '))
    renderPage()
    await user.click(await screen.findByRole('tab', { name: sourceRegex(billingSourceLabels.accounts) }))
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    // 空串/空白游标不能当可用游标
    expect(screen.getByText('服务端称还有更多数据但未返回游标')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
  })

  it('renders ledger amounts in the row currency and never assumes CNY', async () => {
    const user = userEvent.setup()
    vi.spyOn(api.billingAdminApi, 'ledger').mockResolvedValue(cursorPage([
      { id: 'e1', wallet_id: 'w-usd', user_id: 'user-a', username: 'Alice', currency: 'USD',
        event_type: 'credit', balance_delta_micros: 2_000_000, reserved_delta_micros: 0,
        balance_after_micros: 2_000_000, request_id: '', created_at: '2026-10-02T05:00:00Z', metadata: {} },
      { id: 'e2', wallet_id: 'w-nocur', user_id: 'user-b', username: 'Bob', currency: '',
        event_type: 'adjustment', balance_delta_micros: -1_000_000, reserved_delta_micros: 0,
        balance_after_micros: null, request_id: '', created_at: '2026-10-02T05:00:00Z', metadata: {} },
    ], false, ''))
    render(<MemoryRouter><QueryClientProvider client={queryClient}><BillingLedgerTestHarness /></QueryClientProvider></MemoryRouter>)
    await user.click(await screen.findByRole('tab', { name: /计费账本/ }))
    // 非 CNY 钱包按其币种显示，绝不用 ¥；金额统一 3 位小数
    expect(await screen.findByText('USD 2.000')).toBeInTheDocument()
    expect(screen.getByText('+USD 2.000')).toBeInTheDocument()
    // 币种缺失：显示「未知币种」而不是默认 ¥
    expect(screen.getByText('-1.000（未知币种）')).toBeInTheDocument()
    // 金额缺失：显示「未知」而不是 0
    expect(screen.getByText('未知')).toBeInTheDocument()
    expect(screen.queryByText(/¥2\.000000/)).not.toBeInTheDocument()
  })
})

describe('待确认钱包操作按登录管理员隔离', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    window.sessionStorage.clear()
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue({ data: [{ id: 'tenant-a', name: 'XX科技' }] } as any)
    vi.spyOn(api.billingAdminApi, 'runtime').mockResolvedValue(response({ mode: 'prepaid', description: '预付费' }))
    vi.spyOn(api.billingAdminApi, 'models').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue(cursorPage([customer('user-a', 'Alice')], false, ''))
    vi.spyOn(api.billingAdminApi, 'customerGroups').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'ledger').mockResolvedValue(cursorPage([], false, ''))
    vi.spyOn(api.billingAdminApi, 'prices').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'redemptions').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'tariffs').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'previewTariff').mockResolvedValue(response(null))
  })

  afterEach(() => {
    vi.restoreAllMocks()
    cleanup()
    document.body.innerHTML = ''
    window.sessionStorage.clear()
  })

  const Harness = () => {
    const authUserID = useAuthStore((state: any) => state.user?.id)
    return <>
      <button onClick={() => useAuthStore.setState({ user: { id: 'user-2', username: 'bob', role: 'platform_admin' } })}>切换为 user-2</button>
      <span>当前：{authUserID}</span>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter><BillingWalletTestHarness /></MemoryRouter>
      </QueryClientProvider>
    </>
  }

  const renderHarness = () => render(<Harness />)

  it('never resumes or sends another admin\'s pending op after an account switch', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockRejectedValue(new Error('network lost'))
    useAuthStore.setState({ user: { id: 'user-1', username: 'alice', role: 'platform_admin' } })
    renderHarness()

    // user-1 提交一次充值失败，留下待确认操作
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    let modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    fireEvent.mouseDown(modal.getByRole('combobox'))
    await clickDropdownItem(/Alice/)
    await user.type(modal.getByRole('spinbutton'), '5')
    await user.type(modal.getByRole('textbox', { name: '备注' }), '合同预付款')
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    const key1 = (creditSpy.mock.calls[0][0] as any).idempotency_key
    await user.click(modal.getByRole('button', { name: '取 消' }))

    const storedForUser1 = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    expect(storedForUser1['tenant-a:user-1:credit'].idempotency_key).toBe(key1)

    // 切换到 user-2：待确认队列是另一个作用域，绝不恢复 user-1 的操作
    await user.click(screen.getByRole('button', { name: /切换为 user-2/ }))
    expect(screen.getByText('当前：user-2')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    // 表单为空：没有继承 user-1 的冻结 payload
    expect(modal.getByRole('spinbutton')).toHaveValue('')
    expect(screen.queryByText('已有待确认的原值，重试将原样重发')).not.toBeInTheDocument()

    fireEvent.mouseDown(modal.getByRole('combobox'))
    await clickDropdownItem(/Alice/)
    await user.type(modal.getByRole('spinbutton'), '7')
    await user.type(modal.getByRole('textbox', { name: '备注' }), '第二笔')
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(2))
    const second = creditSpy.mock.calls[1][0] as any
    expect(second.idempotency_key).not.toBe(key1)
    // user-1 的待确认操作原样保留，未被 user-2 的提交清掉
    const storedAfter = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    expect(storedAfter['tenant-a:user-1:credit'].idempotency_key).toBe(key1)
    expect(storedAfter['tenant-a:user-2:credit'].idempotency_key).toBe(second.idempotency_key)
  })

  it('blocks and preserves a stored op whose owner is a different admin even under the same scope key', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockRejectedValue(new Error('network lost'))
    useAuthStore.setState({ user: { id: 'user-2', username: 'bob', role: 'platform_admin' } })
    // 存储残留：作用域键正确但所有者是 user-1
    window.sessionStorage.setItem('billing-console-pending-wallet-ops-v2', JSON.stringify({
      'tenant-a:user-2:credit': { idempotency_key: 'console-credit:other-admin', owner_user_id: 'user-1',
        payload: { tenant_id: 'tenant-a', user_id: 'user-a', amount_micros: 9_000_000, reason: '他人操作' } },
    }))
    renderHarness()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    expect(modal.getByRole('spinbutton')).toHaveValue('')
    fireEvent.mouseDown(modal.getByRole('combobox'))
    await clickDropdownItem(/Alice/)
    await user.type(modal.getByRole('spinbutton'), '5')
    await user.type(modal.getByRole('textbox', { name: '备注' }), '本人操作')
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    expect(creditSpy).not.toHaveBeenCalled()
    expect(JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')['tenant-a:user-2:credit'].idempotency_key).toBe('console-credit:other-admin')
  })
})
