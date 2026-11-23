import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { message } from 'antd'
import EmployeeAllowancesPanel from '../components/billing/EmployeeAllowancesPanel'
import UpstreamRatesPanel from '../components/billing/UpstreamRatesPanel'
import { billingEmployeeApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import monthlySource from '../components/billing/EmployeeAllowancesPanel.tsx?raw'

const uiLiteral = (pattern: RegExp) => {
  const match = monthlySource.match(pattern)
  if (!match) throw new Error('Production monthly-wallet label not found')
  return match[1]
}
const monthlyUI = {
  defaultAmount: uiLiteral(/<AllowanceAmountInput aria-label="([^"]+)" disabled=/),
  saveDefault: uiLiteral(/disabled=\{!tenantID \|\| unavailable\}>([^<]+)<\/Button>/),
  edit: uiLiteral(/<Button type="link"[^\n]+>([^<]+)<\/Button>/),
  personalAmount: uiLiteral(/<AllowanceAmountInput aria-label="([^"]+)" prefix=/),
  inherit: uiLiteral(/<Switch aria-label="([^"]+)" checked=\{inherit\}/),
  invalid: uiLiteral(/setEditError\('([^']+)'\); return \}/),
  unavailable: uiLiteral(/type="error" message="([^"]+)"/),
}
const confirmDialog = (dialog: HTMLElement) => dialog.querySelector('.ant-modal-footer .ant-btn-primary') as HTMLElement

const response = (data: any) => ({ data: { data } } as any)
const cfg = { currency: 'USD', timezone: 'UTC', default_monthly_micros: 1000000000 }
const alice = { user_id: 'alice-id', username: 'Alice', department_name: 'Engineering', monthly_micros: 1000000000, effective_micros: 1000000000, used_micros: 999999999, reserved_micros: 999999999, currency: 'USD', monthly_status: { granted_micros: 1000000000, remaining_micros: 800000000, reserved_micros: 300000000, expires_at: '2026-11-01T00:00:00Z' } }
const bob = { ...alice, user_id: 'bob-id', username: 'Bob', monthly_micros: null }
let cache: QueryClient
const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={cache}>{children}</QueryClientProvider>

beforeEach(() => {
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  vi.spyOn(billingEmployeeApi, 'settings').mockResolvedValue(response(cfg))
  vi.spyOn(billingEmployeeApi, 'list').mockResolvedValue(response([alice, bob]))
  vi.spyOn(billingEmployeeApi, 'saveSettings').mockResolvedValue(response(cfg))
  vi.spyOn(billingEmployeeApi, 'saveAllowances').mockResolvedValue(response({ updated: 1 }))
  vi.spyOn(billingEmployeeApi, 'upstreamRates').mockResolvedValue(response([]))
  vi.spyOn(billingEmployeeApi, 'upstreamModels').mockResolvedValue(response([{ provider_id: 'channel-a', provider_name: '供应商 A', model_name: 'model-a' }]))
  vi.spyOn(billingEmployeeApi, 'saveUpstreamRate').mockResolvedValue(response({}))
})
afterEach(() => { cache.clear(); cleanup(); message.destroy(); vi.restoreAllMocks() })

describe('monthly wallet funding controls', () => {
  it('saves a preset in the declared currency and shows real gift money instead of allowance subtraction', async () => {
    const user = userEvent.setup()
    render(<EmployeeAllowancesPanel tenantID="tenant-a" section="all" />, { wrapper })
    await waitFor(() => expect(screen.getByLabelText(monthlyUI.defaultAmount)).toHaveValue('1000.00'))
    await user.click(screen.getByRole('button', { name: '500' }))
    await user.click(screen.getByRole('button', { name: monthlyUI.saveDefault }))
    await waitFor(() => expect(billingEmployeeApi.saveSettings).toHaveBeenCalledWith('tenant-a', { currency: 'USD', timezone: 'UTC', default_monthly_micros: 500000000 }))
    // Default panel and employee panel are separate horizontal tabs.
    render(<EmployeeAllowancesPanel tenantID="tenant-a" section="employees" />, { wrapper })
    const row = (await screen.findByText('Alice')).closest('tr')!
    expect(within(row).getAllByText('USD 1000.000')).toHaveLength(2)
    expect(within(row).getByText('USD 500.000')).toBeInTheDocument()
    expect(within(row).queryByText('USD 0.000')).not.toBeInTheDocument()
  })
  it('restores inheritance with NULL and blocks an empty selected-user amount', async () => {
    const user = userEvent.setup()
    render(<EmployeeAllowancesPanel tenantID="tenant-a" section="employees" />, { wrapper })
    const row = (await screen.findByText('Alice')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: monthlyUI.edit }))
    const dialog = screen.getByRole('dialog')
    await user.clear(within(dialog).getByLabelText(monthlyUI.personalAmount))
    await user.click(confirmDialog(dialog))
    expect(billingEmployeeApi.saveAllowances).not.toHaveBeenCalled()
    expect(screen.getByText(monthlyUI.invalid)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('switch', { name: monthlyUI.inherit }))
    await user.click(confirmDialog(dialog))
    await waitFor(() => expect(billingEmployeeApi.saveAllowances).toHaveBeenCalledWith('tenant-a', ['alice-id'], null))
  })
  it('clears the old selection and editor when switching tenants', async () => {
    const user = userEvent.setup()
    vi.mocked(billingEmployeeApi.list).mockImplementation(tenant => Promise.resolve(response(tenant === 'tenant-a' ? [alice] : [bob])))
    const view = render(<EmployeeAllowancesPanel tenantID="tenant-a" section="employees" />, { wrapper })
    await user.click(within((await screen.findByText('Alice')).closest('tr')!).getByRole('button', { name: monthlyUI.edit }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    view.rerender(<EmployeeAllowancesPanel tenantID="tenant-b" section="employees" />)
    await screen.findByText('Bob')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await user.click(within(screen.getByText('Bob').closest('tr')!).getByRole('button', { name: monthlyUI.edit }))
    const dialog = screen.getByRole('dialog')
    await user.click(within(dialog).getByRole('switch', { name: monthlyUI.inherit }))
    await user.click(within(dialog).getByRole('button', { name: '100' }))
    await user.click(confirmDialog(dialog))
    await waitFor(() => expect(billingEmployeeApi.saveAllowances).toHaveBeenCalledWith('tenant-b', ['bob-id'], 100000000))
  })
  it('does not overwrite settings with defaults after a load failure', async () => {
    vi.mocked(billingEmployeeApi.settings).mockRejectedValue(new Error('offline'))
    render(<EmployeeAllowancesPanel tenantID="tenant-a" section="defaults" />, { wrapper })
    await screen.findByText(monthlyUI.unavailable)
    expect(screen.getByRole('button', { name: monthlyUI.saveDefault })).toBeDisabled()
  })
})

describe('upstream channel cost controls', () => {
  it('loads channel model identities separately and edits token rates with their currency', async () => {
    const user = userEvent.setup()
    vi.mocked(billingEmployeeApi.upstreamRates).mockResolvedValue(response([{ provider_id: 'channel-a', provider_name: '供应商 A', model_name: 'model-a', currency: 'USD', input_per_million_micros: 1500000, cached_input_per_million_micros: 300007, cache_write_per_million_micros: 2000000, output_per_million_micros: 9000000,
      extensions: { source: 'finance-import', image_per_image_micros: 500007, reasoning_per_million_micros: 12000009, image_input_per_million_micros: 1800000, cached_image_input_per_million_micros: 250000, newapi_fixed_quantity: true, tool_prices_per_thousand_micros: { web_search: 10000000 } } }]))
    render(<UpstreamRatesPanel tenantID="tenant-a" models={[]} />, { wrapper })
    await user.click(within((await screen.findByText('model-a')).closest('tr')!).getByRole('button', { name: '编辑' }))
    const dialog = screen.getByRole('dialog')
    const inputs = within(dialog).getAllByRole('spinbutton')
    // Focusing and blurring a rounded display must preserve its original stored precision.
    expect(within(dialog).getByLabelText('成本缓存命中')).toHaveValue('0.30')
    expect(within(dialog).getByLabelText('成本图片价格')).toHaveValue('0.50')
    await user.click(within(dialog).getByLabelText('成本缓存命中'))
    await user.tab()
    await user.click(within(dialog).getByLabelText('成本图片价格'))
    await user.tab()
    await user.click(within(dialog).getByRole('combobox', { name: '成本图片计价单位' }))
    await user.click(screen.getByText('每千张', { selector: '.ant-select-item-option-content' }))
    expect(within(dialog).getByLabelText('成本图片价格')).toHaveValue('500.01')
    await user.click(within(dialog).getByRole('combobox', { name: '成本图片计价单位' }))
    await user.click(screen.getByText('每张', { selector: '.ant-select-item-option-content' }))
    expect(within(dialog).getByLabelText('成本图片价格')).toHaveValue('0.50')
    await user.clear(inputs[0])
    await user.type(inputs[0], '2.12')
    await user.click(within(dialog).getByRole('button', { name: /OK|确 ?定/ }))
    await waitFor(() => expect(billingEmployeeApi.saveUpstreamRate).toHaveBeenCalledWith('tenant-a', expect.objectContaining({ provider_id: 'channel-a', model_name: 'model-a', currency: 'USD', input_per_million_micros: 2120000, cached_input_per_million_micros: 300007, cache_write_per_million_micros: 2000000, output_per_million_micros: 9000000 })))
    expect(billingEmployeeApi.upstreamModels).toHaveBeenCalledWith('tenant-a')
    expect(vi.mocked(billingEmployeeApi.saveUpstreamRate).mock.calls[0][1].extensions).toMatchObject({ source: 'finance-import', image_per_image_micros: 500007, reasoning_per_million_micros: 12000009, image_input_per_million_micros: 1800000, cached_image_input_per_million_micros: 250000, newapi_fixed_quantity: true, tool_prices_per_thousand_micros: { web_search: 10000000 } })
  })
  it('automatically chooses thousand-image units for tiny existing costs and preserves the exact stored amount', async () => {
    const user = userEvent.setup()
    vi.mocked(billingEmployeeApi.upstreamRates).mockResolvedValue(response([{ provider_id: 'channel-a', provider_name: '供应商 A', model_name: 'model-a', currency: 'USD', input_per_million_micros: 0, cached_input_per_million_micros: 0, cache_write_per_million_micros: 0, output_per_million_micros: 0, extensions: { image_per_image_micros: 5007, request_per_call_micros: 3007 } }]))
    render(<UpstreamRatesPanel tenantID="tenant-a" />, { wrapper })
    await user.click(within((await screen.findByText('model-a')).closest('tr')!).getByRole('button', { name: '编辑' }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('每千张', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    expect(within(dialog).getByLabelText('成本图片价格')).toHaveValue('5.01')
    expect(within(dialog).getByLabelText('成本固定费用')).toHaveValue('3.01')
    await user.click(within(dialog).getByLabelText('成本图片价格'))
    await user.tab()
    await user.click(within(dialog).getByRole('button', { name: /OK|确 ?定/ }))
    await waitFor(() => expect(billingEmployeeApi.saveUpstreamRate).toHaveBeenCalled())
    expect(vi.mocked(billingEmployeeApi.saveUpstreamRate).mock.calls[0][1].extensions).toMatchObject({ image_per_image_micros: 5007, request_per_call_micros: 3007 })
  })
  it('disables editing when the channel model catalog failed instead of submitting incomplete identities', async () => {
    vi.mocked(billingEmployeeApi.upstreamModels).mockRejectedValue(new Error('offline'))
    render(<UpstreamRatesPanel tenantID="tenant-a" />, { wrapper })
    await screen.findByText('渠道模型加载失败')
    expect(screen.getByRole('button', { name: '录入采购成本' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '重试模型加载' })).toBeInTheDocument()
  })
})

describe('系统币种切换入口仅对 platform_admin 开放', () => {
  afterEach(() => { useAuthStore.setState({ user: null }) })
  it.each(['admin', 'tenant_owner', 'tenant_admin'])('%s 看不到「切换系统币种…」', async role => {
    useAuthStore.setState({ user: { id: 'u1', username: 'u1', role, tenant_id: 'tenant-a' } as any })
    render(<EmployeeAllowancesPanel tenantID="tenant-a" section="defaults" />, { wrapper })
    // 设置加载完成（保存按钮解禁）后，入口仍不应出现
    await waitFor(() => expect(screen.getByRole('button', { name: monthlyUI.saveDefault })).toBeEnabled())
    expect(screen.queryByText('切换系统币种…')).not.toBeInTheDocument()
    expect(screen.queryByText('系统币种')).not.toBeInTheDocument()
  })
  it('platform_admin 能看到「切换系统币种…」', async () => {
    useAuthStore.setState({ user: { id: 'u1', username: 'u1', role: 'platform_admin', tenant_id: 'tenant-a' } as any })
    render(<EmployeeAllowancesPanel tenantID="tenant-a" section="defaults" />, { wrapper })
    expect(await screen.findByText('切换系统币种…')).toBeInTheDocument()
  })
})
