import { billingSourceLabels, sourceRegex } from './billingSourceLabels'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { BillingWalletTestHarness } from './BillingWalletTestHarness'
import * as api from '../services/api'

const response = (data: any) => ({ data: { data } } as any)
// 客户与账本列表走游标分页协议：响应必须带 has_more/next_cursor
const cursorPage = (rows: any[], hasMore: boolean, nextCursor: string) =>
  ({ data: { data: rows, meta: { has_more: hasMore, next_cursor: nextCursor } } } as any)

const creditPayload = (callIndex: number) =>
  (api.billingAdminApi.credit as any).mock.calls[callIndex][0] as Record<string, any>

// 充值/调账卡片按钮带图标，可达名形如 "dollar 客户充值"，用正则匹配。
// antd Select 需要 fireEvent.mouseDown 才展开下拉；role=option 会匹配到
// 选择器内无点击处理的无障碍列表，必须点真正的下拉项内容。
// jsdom 中动画事件不触发，关闭的弹窗会以各种中间态滞留 DOM，
// 因此按标题唯一定位当前要操作的弹窗
const openModalByTitle = async (title: RegExp) => {
  const find = () => {
    const dialogs = screen.queryAllByRole('dialog')
    return dialogs.find((d) => title.test(d.querySelector('.ant-modal-title')?.textContent || ''))
  }
  await waitFor(() => expect(find()).toBeTruthy())
  return within(find() as HTMLElement)
}

// 已关闭的下拉节点会残留 DOM，在当前未隐藏的下拉中等待目标选项
const clickDropdownItem = async (text: RegExp, listID?: string | null) => {
  const item = await waitFor(() => {
    const associated = listID ? document.getElementById(listID)?.closest('.ant-select-dropdown:not(.ant-select-dropdown-hidden)') : null
    const open = listID ? associated ? [associated] : [] : Array.from(document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden)'))
    expect(open.length).toBeGreaterThan(0)
    const items = open.reverse().flatMap(dropdown => Array.from(dropdown.querySelectorAll('.ant-select-item-option-content')))
    const target = items.find((element) => text.test(element.textContent || ''))
    expect(target).toBeTruthy()
    return target as HTMLElement
  }, { timeout: 10000 })
  fireEvent.click(item)
}

const pickCustomer = async (modal: ReturnType<typeof within>) => {
  const select = modal.getByRole('combobox')
  fireEvent.mouseDown(select)
  await clickDropdownItem(/Alice/, select.getAttribute('aria-controls'))
}

// 还原 window.sessionStorage 的原始属性描述符。必须在每个用例后无条件执行：
// 假存储一旦残留，后续所有读写都会抛错，把无关用例一起带崩。
const originalSessionStorageDescriptor = Object.getOwnPropertyDescriptor(window, 'sessionStorage')
  || Object.getOwnPropertyDescriptor(Object.getPrototypeOf(window), 'sessionStorage')
const restoreSessionStorage = () => {
  if (!originalSessionStorageDescriptor) return
  Object.defineProperty(window, 'sessionStorage', originalSessionStorageDescriptor)
}

// 提交瞬间按钮处于 loading 态（antd 会忽略点击），等 loading 清除后再点
// isPending=false 的 UI 传播在非 act 环境下有最长约 2.5s 的延迟，
// 用 act 主动刷新后再等按钮退出 loading，避免加载态吞掉点击
const clickWhenReady = async (user: ReturnType<typeof userEvent.setup>, modal: ReturnType<typeof within>, name: RegExp) => {
  await act(async () => { await new Promise((r) => setTimeout(r, 3000)) })
  await waitFor(() => {
    const button = modal.getByRole('button', { name })
    expect(button.className).not.toContain('ant-btn-loading')
  }, { timeout: 10000 })
  await user.click(modal.getByRole('button', { name }))
}

const fillCreditForm = async (user: ReturnType<typeof userEvent.setup>, modal: ReturnType<typeof within>, amount = '5') => {
  await pickCustomer(modal)
  await user.type(modal.getByRole('spinbutton'), amount)
  await user.type(modal.getByRole('textbox', { name: '备注' }), '合同预付款')
}

describe('wallet credit/adjust pending-op idempotency', () => {
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
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue(cursorPage([
      { user_id: 'user-a', username: 'Alice', email: 'alice@example.com', customer_group: 'default',
        customer_group_name: '默认客户组', customer_group_status: 'active',
        balance_micros: 5_000_000, reserved_micros: 1_000_000, available_micros: 4_000_000,
        wallet_id: 'wallet-a' },
    ], false, ''))
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
    restoreSessionStorage()
    window.sessionStorage.clear()
  })

  const renderPage = async () => {
    const view = render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <BillingWalletTestHarness />
      </QueryClientProvider>
    </MemoryRouter>,
  )
    await within(await screen.findByRole('table')).findByText('Alice', {}, { timeout: 10000 })
    return view
  }

  it('retries keep the same key and the frozen payload even if the form changes', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit')
      .mockRejectedValueOnce(new Error('network lost'))
      .mockResolvedValue(response({ ok: true }))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    expect(creditPayload(0).amount_micros).toBe(5_000_000)
    // 冻结后表单禁用：用户无法再改动客户/金额/原因，重试只发冻结 payload
    expect(modal.getByRole('spinbutton')).toBeDisabled()
    expect(modal.getByRole('textbox', { name: '备注' })).toBeDisabled()
    await clickWhenReady(user, modal, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(2))
    expect(creditPayload(1).amount_micros).toBe(5_000_000)
    expect(creditPayload(0).idempotency_key).toBeTruthy()
    expect(creditPayload(1).idempotency_key).toBe(creditPayload(0).idempotency_key)
  })

  it('close and reopen resumes the pending operation with the same key', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit')
      .mockRejectedValueOnce(new Error('network lost'))
      .mockResolvedValue(response({ ok: true }))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    let modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    // 响应未知时关闭弹窗
    await user.click(modal.getByRole('button', { name: '取 消' }))
    // 重开：恢复冻结 payload 预填并保持同一幂等键
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    expect(modal.getByRole('spinbutton')).toHaveValue('5.00')
    await clickWhenReady(user, modal, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(2))
    expect(creditPayload(1).idempotency_key).toBe(creditPayload(0).idempotency_key)
    // 入账成功后待确认操作清除，再开是全新幂等键
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await clickWhenReady(user, modal, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(3))
    expect(creditPayload(2).idempotency_key).not.toBe(creditPayload(0).idempotency_key)
  })

  it('a page refresh restores the pending operation from storage', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit')
      .mockRejectedValueOnce(new Error('network lost'))
      .mockResolvedValue(response({ ok: true }))
    const first = await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    const keyBeforeRefresh = creditPayload(0).idempotency_key
    // 模拟刷新：卸载后重新挂载（localStorage 持久保留）
    first.unmount()
    cleanup()
    document.body.innerHTML = ''
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const reopened = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await clickWhenReady(user, reopened, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(2))
    expect(creditPayload(1).idempotency_key).toBe(keyBeforeRefresh)
    expect(creditPayload(1).amount_micros).toBe(5_000_000)
  })

  it('closing while the request is in flight resumes the frozen op after reopen', async () => {
    const user = userEvent.setup()
    let resolveInFlight: (value: any) => void = () => {}
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockImplementation(
      () => new Promise((resolve) => { resolveInFlight = resolve }),
    )
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    // 请求还在途中就关闭弹窗
    await user.click(modal.getByRole('button', { name: '取 消' }))
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const reopened = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    // 恢复冻结 payload 预填，确认按钮仍为 loading（防止请求中重复提交）
    expect(reopened.getByRole('spinbutton')).toHaveValue('5.00')
    expect(reopened.getByRole('textbox', { name: '备注' })).toHaveValue('合同预付款')
    expect(reopened.getByRole('button', { name: /确认充值|按原值重发/ }).className).toContain('ant-btn-loading')
    const stored = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    expect(stored['tenant-a:anon:credit'].idempotency_key).toBe(creditPayload(0).idempotency_key)
    // 响应返回后入账成功，待确认操作被清除
    resolveInFlight(response({ ok: true }))
    await waitFor(() => {
      const ops = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
      expect(ops['tenant-a:anon:credit']).toBeUndefined()
    })
  })

  it('pending operations are isolated per tenant across switches', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockRejectedValue(new Error('network lost'))
    await renderPage()
    // 租户 A 打开充值弹窗后关闭（未提交），幂等键持久化为待确认操作
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    let modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await user.click(modal.getByRole('button', { name: '取 消' }))
    // 切换到租户 B：是另一个作用域，拿到不同幂等键
    fireEvent.mouseDown(screen.getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByText('YY集团', { selector: '.ant-select-dropdown .ant-select-item-option-content' }))
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await clickWhenReady(user, modal, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    expect(creditPayload(0).tenant_id).toBe('tenant-b')
    const tenantBKey = creditPayload(0).idempotency_key
    // 切回租户 A：恢复 A 的待确认操作与原键
    fireEvent.mouseDown(screen.getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByText('XX科技', { selector: '.ant-select-dropdown .ant-select-item-option-content' }))
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await clickWhenReady(user, modal, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(2))
    expect(creditPayload(1).tenant_id).toBe('tenant-a')
    expect(creditPayload(1).idempotency_key).not.toBe(tenantBKey)
  })

  it('rejects blank reasons for credit and adjust without calling the API', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockResolvedValue(response({ ok: true }))
    const adjustSpy = vi.spyOn(api.billingAdminApi, 'adjust').mockResolvedValue(response({ ok: true }))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    let modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await pickCustomer(modal)
    await user.type(modal.getByRole('spinbutton'), '5')
    await user.type(modal.getByRole('textbox', { name: '备注' }), '   ')
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    expect(await screen.findByText('请填写充值原因')).toBeInTheDocument()
    expect(creditSpy).not.toHaveBeenCalled()
    await user.click(modal.getByRole('button', { name: '取 消' }))
    // 调账同样拒绝空白原因
    await user.click(await screen.findByRole('button', { name: '调账' }))
    modal = await openModalByTitle(sourceRegex(billingSourceLabels.adjust))
    await pickCustomer(modal)
    await user.type(modal.getByRole('spinbutton'), '-1')
    await user.type(modal.getByRole('textbox', { name: '调账原因' }), '   ')
    await user.click(modal.getByRole('button', { name: '确认调账' }))
    expect(await screen.findByText('请填写调账原因')).toBeInTheDocument()
    expect(adjustSpy).not.toHaveBeenCalled()
  })

  it('trims the frozen reason and rejects an empty key without calling the API', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockRejectedValue(new Error('network lost'))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await pickCustomer(modal)
    await user.type(modal.getByRole('spinbutton'), '5')
    await user.type(modal.getByRole('textbox', { name: '备注' }), '  合同预付款  ')
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    // 冻结时 trim：发送与持久化的 reason 都不带首尾空白
    expect(creditPayload(0).reason).toBe('合同预付款')
    const stored = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    expect(stored['tenant-a:anon:credit'].payload.reason).toBe('合同预付款')
    expect(stored['tenant-a:anon:credit'].idempotency_key).toBe(creditPayload(0).idempotency_key)
  })

  it('keeps the pending op for review after failures until a confirmed success', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit')
      .mockRejectedValueOnce(new Error('network lost'))
      .mockRejectedValueOnce(Object.assign(new Error('conflict'), { response: { status: 409 } }))
      .mockResolvedValue(response({ ok: true }))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    // 失败后冻结操作与幂等键必须保留（响应未知，服务端可能已入账）
    const readStored = () => JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    expect(readStored()['tenant-a:anon:credit'].idempotency_key).toBe(creditPayload(0).idempotency_key)
    // 冲突（409）同样保留核查，重试仍用同一键
    await clickWhenReady(user, modal, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(2))
    expect(readStored()['tenant-a:anon:credit'].idempotency_key).toBe(creditPayload(0).idempotency_key)
    expect(creditPayload(1).idempotency_key).toBe(creditPayload(0).idempotency_key)
    // 第三次成功：入账确认后清除
    await clickWhenReady(user, modal, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(3))
    await waitFor(() => expect(readStored()['tenant-a:anon:credit']).toBeUndefined())
  })

  it('stops the first submission when persisting the pending op fails', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockResolvedValue(response({ ok: true }))
    // jsdom 每次访问 window.sessionStorage 返回新对象，spy 拦截不可靠；
    // 用 getter 直接替换为抛错的假存储。还原必须放在 finally/afterEach，
    // 否则一旦断言失败，假存储会残留并毒化后续所有用例。
    const fakeStorage = { getItem: () => null, setItem: () => { throw new Error('storage unavailable') }, removeItem: () => {}, clear: () => {}, key: () => null, length: 0 }
    Object.defineProperty(window, 'sessionStorage', { get: () => fakeStorage, configurable: true })
    try {
      await renderPage()
      await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
      const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
      await fillCreditForm(user, modal)
      await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
      // 拦截原因以弹窗内的持久警示呈现（不是 3 秒即逝的 toast）：
      // 事后仍能证明这笔操作被拦下、没有离开本机。
      expect(await modal.findByText('本次提交已被拦截，未发送任何资金请求')).toBeInTheDocument()
      expect(modal.getByText(/待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试/)).toBeInTheDocument()
      expect(creditSpy).not.toHaveBeenCalled()
    } finally {
      restoreSessionStorage()
    }
    // 存储恢复后重试：同一幂等键原样发送并成功持久化。
    // 复用仍开着的弹窗（表单值还在）；重开会resetFields 把已填内容清掉。
    const stillOpen = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await clickWhenReady(user, stillOpen, /确认充值|按原值重发/)
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    // 重试按原表单值发送（租户/客户/金额/原因都来自冻结前填的内容）
    expect(creditPayload(0).reason).toBe('合同预付款')
    expect(creditPayload(0).tenant_id).toBe('tenant-a')
    expect(creditPayload(0).amount_micros).toBe(5_000_000)
    // 入账确认后待确认操作被清除，持久化里不再残留这条作用域
    await waitFor(() => {
      const stored = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
      expect(stored['tenant-a:anon:credit']).toBeUndefined()
    })
  })

  it('never lets a late success delete a newer op in the SAME tenant scope', async () => {
    const user = userEvent.setup()
    let resolveOld: (value: any) => void = () => {}
    // 第一笔挂起不返回；它的 success 会在很久之后才到
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit')
      .mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve }))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal, '5')
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    const oldKey = creditPayload(0).idempotency_key
    await waitFor(() => {
      const ops = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
      expect(ops['tenant-a:anon:credit'].idempotency_key).toBe(oldKey)
    })
    // 同一租户、同一作用域下出现了一笔**更晚创建**的待确认操作（键不同）。
    // 这在真实流程里会发生：旧请求还在途中，管理员清了缓存/换标签页重开，
    // 同一作用域被新的操作占用了。
    window.sessionStorage.setItem('billing-console-pending-wallet-ops-v2', JSON.stringify({
      'tenant-a:anon:credit': { idempotency_key: 'later-op-key', owner_user_id: 'anon', payload: { tenant_id: 'tenant-a', user_id: 'user-a', amount_micros: 9_000_000, reason: 'later' } },
    }))
    // 旧那笔的迟到 success 到达。作用域键与更晚那笔完全相同 —— 无条件
    // delete 会把更晚那笔的凭证删掉；必须按幂等键核对后才删。
    resolveOld(response({ ok: true }))
    await new Promise((r) => setTimeout(r, 1500))
    const opsAfter = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    expect(opsAfter['tenant-a:anon:credit'].idempotency_key).toBe('later-op-key')
    // 且不得被旧那笔的 payload 覆盖
    expect(opsAfter['tenant-a:anon:credit'].payload.amount_micros).toBe(9_000_000)
  })

  it('stops the submission when the pending-op storage cannot be READ, never overwriting it', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockResolvedValue(response({ ok: true }))
    const originalDescriptor = Object.getOwnPropertyDescriptor(window, 'sessionStorage')
      || Object.getOwnPropertyDescriptor(Object.getPrototypeOf(window), 'sessionStorage')
    try {
      // 存量里有一条别的租户的待确认操作
      window.sessionStorage.setItem('billing-console-pending-wallet-ops-v2', JSON.stringify({
        'tenant-b:anon:credit': { idempotency_key: 'other-tenant-key', owner_user_id: 'anon', payload: { tenant_id: 'tenant-b' } },
      }))
      // 读取抛错（隐私模式/配额/被禁用），写入正常
      Object.defineProperty(window, 'sessionStorage', {
        get: () => ({
          getItem: () => { throw new Error('storage read denied') },
          setItem: () => {},
          removeItem: () => {},
          clear: () => {},
          key: () => null,
          length: 0,
        }),
        configurable: true,
      })
      await renderPage()
      await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
      const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
      await fillCreditForm(user, modal)
      await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
      // 读不到持久化就无法保证幂等键可恢复：必须停发
      expect(await modal.findByText('本次提交已被拦截，未发送任何资金请求')).toBeInTheDocument()
      expect(creditSpy).not.toHaveBeenCalled()
    } finally {
      if (originalDescriptor) Object.defineProperty(window, 'sessionStorage', originalDescriptor)
    }
    // 关键：存量记录完好。若读取失败被当成空 map，就会用「空 map + 新 op」
    // 覆盖整个存储，把别的租户的凭证一并销毁。
    const after = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    expect(after['tenant-b:anon:credit'].idempotency_key).toBe('other-tenant-key')
  })

  it('disables the form and shows the frozen original values once payload is committed', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockRejectedValueOnce(new Error('network lost'))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    let modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    await user.click(modal.getByRole('button', { name: '取 消' }))
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    expect(await screen.findByText('已有待确认的原值，重试将原样重发')).toBeInTheDocument()
    expect(modal.getByRole('spinbutton')).toBeDisabled()
    expect(modal.getByRole('textbox', { name: '备注' })).toBeDisabled()
    expect((modal.getByRole('combobox').closest('.ant-select') as HTMLElement).className).toContain('ant-select-disabled')
    expect(screen.getByText(creditPayload(0).idempotency_key)).toBeInTheDocument()
  })

  it('a late success from the old tenant never clears or closes a new tenant op', async () => {
    const user = userEvent.setup()
    let resolveA: (value: any) => void = () => {}
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit')
      .mockImplementationOnce(() => new Promise((resolve) => { resolveA = resolve }))
      .mockResolvedValue(response({ ok: true }))
    await renderPage()
    // 租户 A 提交后请求挂起
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    const keyA = creditPayload(0).idempotency_key
    // 关闭弹窗（请求仍在途），切到租户 B 打开新弹窗
    await user.click(modal.getByRole('button', { name: '取 消' }))
    fireEvent.mouseDown(screen.getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByText('YY集团', { selector: '.ant-select-dropdown .ant-select-item-option-content' }))
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modalB = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modalB)
    // A 的迟到成功返回：不得清掉 B 的新操作、不得关掉 B 的弹窗
    resolveA(response({ ok: true }))
    await waitFor(() => {
      const stored = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
      expect(stored['tenant-a:anon:credit']).toBeUndefined()
    })
    const storedAfter = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    expect(storedAfter['tenant-b:anon:credit']).toBeTruthy()
    expect(storedAfter['tenant-b:anon:credit'].idempotency_key).not.toBe(keyA)
    // 弹窗 B 存活：确认充值按钮仍在文档中，未被迟到响应关闭
    expect(modalB.getByRole('button', { name: /确认充值|按原值重发/ })).toBeInTheDocument()
    // B 照常提交：键与 A 不同，租户为 B
    await user.click(modalB.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(2))
    expect(creditPayload(1).tenant_id).toBe('tenant-b')
    expect(creditPayload(1).idempotency_key).not.toBe(keyA)
  })

  it('blocks and preserves a stored op whose frozen payload belongs to another tenant', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockResolvedValue(response({ ok: true }))
    // 模拟存储残留：tenant-a 作用域下挂着一个冻结租户为 tenant-b 的脏操作
    window.sessionStorage.setItem('billing-console-pending-wallet-ops-v2', JSON.stringify({
      'tenant-a:anon:credit': { idempotency_key: 'console-credit:stale-key', payload: { tenant_id: 'tenant-b', user_id: 'user-a', amount_micros: 9_000_000, reason: '跨租户脏数据' } },
    }))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    // 脏操作被丢弃：不预填冻结 payload，表单为空
    expect(modal.getByRole('spinbutton')).toHaveValue('')
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    expect(creditSpy).not.toHaveBeenCalled()
    expect(JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')['tenant-a:anon:credit'].idempotency_key).toBe('console-credit:stale-key')
  })

  it.each(['{broken', '[]', 'null', '"text"', '{}broken'])('blocks malformed storage %s without minting a key or changing bytes', async (raw) => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockResolvedValue(response({ ok: true }))
    const uuidSpy = vi.spyOn(crypto, 'randomUUID')
    window.sessionStorage.setItem('billing-console-pending-wallet-ops-v2', raw)
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    expect(await modal.findByText('本次提交已被拦截，未发送任何资金请求')).toBeInTheDocument()
    expect(creditSpy).not.toHaveBeenCalled()
    expect(uuidSpy).not.toHaveBeenCalled()
    expect(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2')).toBe(raw)
  })

  it('refuses a different key written between opening and submission', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockResolvedValue(response({ ok: true }))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    const raw = JSON.stringify({ 'tenant-a:anon:credit': { idempotency_key: 'different-key', owner_user_id: 'anon', payload: null } })
    window.sessionStorage.setItem('billing-console-pending-wallet-ops-v2', raw)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    expect(await modal.findByText('本次提交已被拦截，未发送任何资金请求')).toBeInTheDocument()
    expect(creditSpy).not.toHaveBeenCalled()
    expect(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2')).toBe(raw)
  })

  it('keeps a confirmed operation and its frozen key when local compare-delete fails', async () => {
    const user = userEvent.setup()
    let resolve: (value: any) => void = () => {}
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockImplementation(() => new Promise((done) => { resolve = done }))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    const key = creditPayload(0).idempotency_key
    const original = window.sessionStorage
    const raw = original.getItem('billing-console-pending-wallet-ops-v2')
    Object.defineProperty(window, 'sessionStorage', { configurable: true, get: () => ({
      getItem: (name: string) => original.getItem(name),
      setItem: () => { throw new Error('delete persistence denied') },
    }) })
    try {
      resolve(response({ ok: true }))
      expect(await modal.findByText('已成功入账但本地记录未清除')).toBeInTheDocument()
      expect(modal.getByText(key)).toBeInTheDocument()
      expect(original.getItem('billing-console-pending-wallet-ops-v2')).toBe(raw)
      expect(modal.getByRole('spinbutton')).toBeDisabled()
    } finally { restoreSessionStorage() }
  })

  it('rejects a stored frozen payload changed under the same idempotency key', async () => {
    const user = userEvent.setup()
    const creditSpy = vi.spyOn(api.billingAdminApi, 'credit').mockRejectedValue(new Error('response unknown'))
    await renderPage()
    await user.click(await screen.findByRole('button', { name: sourceRegex(billingSourceLabels.credit) }))
    const modal = await openModalByTitle(sourceRegex(billingSourceLabels.credit))
    await fillCreditForm(user, modal)
    await user.click(modal.getByRole('button', { name: /确认充值|按原值重发/ }))
    await waitFor(() => expect(creditSpy).toHaveBeenCalledTimes(1))
    const stored = JSON.parse(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2') || '{}')
    stored['tenant-a:anon:credit'].payload.amount_micros = 99_000_000
    const raw = JSON.stringify(stored)
    window.sessionStorage.setItem('billing-console-pending-wallet-ops-v2', raw)
    await clickWhenReady(user, modal, /确认充值|按原值重发/)
    expect(await modal.findByText('本次提交已被拦截，未发送任何资金请求')).toBeInTheDocument()
    expect(creditSpy).toHaveBeenCalledTimes(1)
    expect(window.sessionStorage.getItem('billing-console-pending-wallet-ops-v2')).toBe(raw)
  })

  it('adjustment storage write failure prevents any network request', async () => {
    const user = userEvent.setup()
    const adjustSpy = vi.spyOn(api.billingAdminApi, 'adjust').mockResolvedValue(response({ ok: true }))
    const fakeStorage = { getItem: () => null, setItem: () => { throw new Error('denied') }, clear: () => {} }
    Object.defineProperty(window, 'sessionStorage', { get: () => fakeStorage, configurable: true })
    try {
      await renderPage()
      await user.click(await screen.findByRole('button', { name: '调账' }))
      const modal = await openModalByTitle(sourceRegex(billingSourceLabels.adjust))
      await pickCustomer(modal)
      await user.type(modal.getByRole('spinbutton'), '-1')
      await user.type(modal.getByRole('textbox', { name: '调账原因' }), 'reviewed')
      await user.click(modal.getByRole('button', { name: '确认调账' }))
      expect(await modal.findByText('本次提交已被拦截，未发送任何资金请求')).toBeInTheDocument()
      expect(adjustSpy).not.toHaveBeenCalled()
    } finally { restoreSessionStorage() }
  })
})
