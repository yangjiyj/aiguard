import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import CurrencySwitch from '../components/billing/CurrencySwitch'
import { billingEmployeeApi } from '../services/api'
import { useCurrencyStore } from '../stores/currency'
afterEach(() => vi.restoreAllMocks())
test('先预览影响，再二次确认执行，使用预览令牌', async () => {
 const call = vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValueOnce({ data: { data: { confirm_token: 'token', wallets: [{ currency: 'CNY', count: 2, zero_balance_count: 1 }], active_prices: [], upstream_rates: [], fixed_costs: [], reservations: 0, monthly_grants: 1 } } } as any).mockResolvedValueOnce({ data: { data: { executed: true } } } as any)
 render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 fireEvent.click(screen.getByText('切换系统币种…'))
 fireEvent.click(screen.getByText('预览影响'))
 await screen.findByText(/CNY：2 个钱包/)
 expect(call).toHaveBeenCalledWith('t1', { currency: 'USD', preview: true })
 fireEvent.click(screen.getByText('继续切换'))
 await screen.findByText('确认切换系统币种')
 fireEvent.click(screen.getByText('确认切换'))
 await waitFor(() => expect(call).toHaveBeenCalledWith('t1', { currency: 'USD', preview: false, confirm_token: 'token' }))
 await waitFor(() => expect(useCurrencyStore.getState().tenantCurrency).toBe('USD'))
})

test('钱包存在预占时显示数量并禁止继续切换', async () => {
 vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValue({ data: { data: { confirm_token: 'token', wallets: [], active_prices: [], upstream_rates: [], fixed_costs: [], reservations: 0, reserved_wallets: 2, monthly_grants: 0 } } } as any)
 render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 fireEvent.click(screen.getByText('切换系统币种…'))
 fireEvent.click(screen.getByText('预览影响'))
 expect(await screen.findByText(/有预占的钱包：2 个/)).toBeInTheDocument()
 expect(screen.getByText('继续切换').closest('button')).toBeDisabled()
})

// ---- 未定价清单 / 遗留孤儿价格（后端契约：unpriced_models、legacy_orphan_prices、confirm_unpriced）----
const previewData = (extra: Record<string, unknown> = {}) => ({ data: { data: { confirm_token: 'token', wallets: [], active_prices: [], upstream_rates: [], fixed_costs: [], reservations: 0, monthly_grants: 0, ...extra } } } as any)
const unpricedModels = [
 { model_name: 'glm-5.2', customer_group: 'default', currencies: ['CNY'] },
 { model_name: 'gpt-x', customer_group: 'vip', currencies: ['CNY', 'USD'] },
]
const ackLabel = '我已知晓这些模型切换后无法计费，仍要切换'
const openAndPreview = async () => {
 fireEvent.click(screen.getByText('切换系统币种…'))
 fireEvent.click(screen.getByText('预览影响'))
}

test('有未定价清单时展示清单，未勾选确认前禁止继续，勾选后执行请求带 confirm_unpriced', async () => {
 const call = vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValueOnce(previewData({ unpriced_models: unpricedModels })).mockResolvedValueOnce({ data: { data: { executed: true } } } as any)
 render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 await openAndPreview()
 expect(await screen.findByText(/以下 2 个模型切换后将变为未定价/)).toBeInTheDocument()
 expect(screen.getByText('glm-5.2（客户组 default）· 现有价格币种 CNY')).toBeInTheDocument()
 expect(screen.getByText('gpt-x（客户组 vip）· 现有价格币种 CNY、USD')).toBeInTheDocument()
 const next = screen.getByText('继续切换').closest('button')!
 expect(next).toBeDisabled()
 fireEvent.click(screen.getByRole('checkbox', { name: ackLabel }))
 expect(screen.getByText('继续切换').closest('button')).toBeEnabled()
 fireEvent.click(screen.getByText('继续切换'))
 await screen.findByText('确认切换系统币种')
 fireEvent.click(screen.getByText('确认切换'))
 await waitFor(() => expect(call).toHaveBeenCalledTimes(2))
 expect(call.mock.calls[1]).toStrictEqual(['t1', { currency: 'USD', preview: false, confirm_token: 'token', confirm_unpriced: true }])
})

test('无未定价清单（含空数组与旧后端缺字段）时不显示确认勾选，执行请求不带 confirm_unpriced', async () => {
 const call = vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValueOnce(previewData({ unpriced_models: [], legacy_orphan_prices: { pairs: 0, rows: 0 } })).mockResolvedValueOnce({ data: { data: { executed: true } } } as any)
 render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 await openAndPreview()
 await screen.findByText('继续切换')
 expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
 expect(screen.queryByText(/变为未定价/)).not.toBeInTheDocument()
 expect(screen.queryByText(/遗留价格/)).not.toBeInTheDocument()
 expect(screen.getByText('继续切换').closest('button')).toBeEnabled()
 fireEvent.click(screen.getByText('继续切换'))
 await screen.findByText('确认切换系统币种')
 fireEvent.click(screen.getByText('确认切换'))
 await waitFor(() => expect(call).toHaveBeenCalledTimes(2))
 expect(call.mock.calls[1]).toStrictEqual(['t1', { currency: 'USD', preview: false, confirm_token: 'token' }])
})

test('旧后端不返回两个新字段时行为同现状', async () => {
 vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValue(previewData())
 render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 await openAndPreview()
 await screen.findByText('继续切换')
 expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
 expect(screen.queryByText(/遗留价格/)).not.toBeInTheDocument()
 expect(screen.getByText('继续切换').closest('button')).toBeEnabled()
})

test('已删除模型的遗留价格只显示条数，不阻止继续也不需勾选', async () => {
 vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValue(previewData({ unpriced_models: [], legacy_orphan_prices: { pairs: 41, rows: 43 } }))
 render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 await openAndPreview()
 expect(await screen.findByText('已删除模型的遗留价格：41 个模型/客户组（43 行价格），切换时照常作废，不影响计费')).toBeInTheDocument()
 expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
 expect(screen.getByText('继续切换').closest('button')).toBeEnabled()
})

test('重新打开对话框后确认勾选被重置', async () => {
 vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValue(previewData({ unpriced_models: unpricedModels }))
 render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 await openAndPreview()
 fireEvent.click(await screen.findByRole('checkbox', { name: ackLabel }))
 expect(screen.getByText('继续切换').closest('button')).toBeEnabled()
 fireEvent.click(screen.getByRole('button', { name: /取\s*消/ }))
 await openAndPreview()
 const box = await screen.findByRole('checkbox', { name: ackLabel })
 expect(box).not.toBeChecked()
 expect(screen.getByText('继续切换').closest('button')).toBeDisabled()
})

test('换租户后确认勾选被重置', async () => {
 vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValue(previewData({ unpriced_models: unpricedModels }))
 const view = render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 await openAndPreview()
 fireEvent.click(await screen.findByRole('checkbox', { name: ackLabel }))
 view.rerender(<CurrencySwitch tenantID="t2" currency="CNY" onSuccess={vi.fn()} />)
 await openAndPreview()
 expect(await screen.findByRole('checkbox', { name: ackLabel })).not.toBeChecked()
 expect(screen.getByText('继续切换').closest('button')).toBeDisabled()
})

test('执行返回 409 需确认未定价时给出中文提示', async () => {
 const conflict = { response: { status: 409, data: { error: { code: 'currency_switch_unpriced_confirm_required', message: 'unpriced confirm required', unpriced_models: unpricedModels } } } }
 vi.spyOn(billingEmployeeApi, 'switchCurrency').mockResolvedValueOnce(previewData({ unpriced_models: unpricedModels })).mockRejectedValueOnce(conflict)
 render(<CurrencySwitch tenantID="t1" currency="CNY" onSuccess={vi.fn()} />)
 await openAndPreview()
 fireEvent.click(await screen.findByRole('checkbox', { name: ackLabel }))
 fireEvent.click(screen.getByText('继续切换'))
 await screen.findByText('确认切换系统币种')
 fireEvent.click(screen.getByText('确认切换'))
 expect(await screen.findByText('切换后有模型将变为未定价，请在预览中勾选确认后重试')).toBeInTheDocument()
})
