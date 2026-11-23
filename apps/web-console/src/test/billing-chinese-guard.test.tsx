import usageSource from '../pages/Usage.tsx?raw'
import budgetsSource from '../pages/billing/Budgets.tsx?raw'
import pricingSource from '../pages/billing/Pricing.tsx?raw'
import statementsSource from '../pages/billing/Statements.tsx?raw'
import upstreamSource from '../components/billing/UpstreamRatesPanel.tsx?raw'
import fixedSource from '../components/billing/ChannelFixedCostsPanel.tsx?raw'
import pricingSectionSource from '../components/billing/sections/usePricingSection.tsx?raw'
import { literal, sourceRegex } from './billingSourceLabels'
import { BILLING_SECTION_LABELS as labels } from '../components/billing/sectionLabels'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { ConfigProvider } from 'antd'
import zhCN from 'antd/es/locale/zh_CN'
import BillingOverview from '../pages/billing/Overview'
import BillingBudgets from '../pages/billing/Budgets'
import BillingPricing from '../pages/billing/Pricing'
import BillingStatements from '../pages/billing/Statements'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'

// 中文化守护：计费各页面空态与有数据态都不能露出英文枚举、表名、技术 id、英文分页/空态文案。
// 规则：DOM 文本里形如 /[a-z_]{4,}/ 的小写英文片段必须在白名单里（模型名、渠道名、产品名等专有名词）。
const ALLOWED = new Set([
  // 测试数据里的模型 / 渠道 / 产品专有名词
  'deepseek', 'chat', 'chatgpt', 'gpt', 'luna', 'glm', 'qwen', 'turbo', 'openai', 'anthropic', 'claude', 'sonnet', 'mini',
  // 单位与通用缩写（小写形式出现在模型名里）
  'token', 'tokens',
])
// 整词匹配：Token、Excel、Asia/Shanghai 这类首字母大写的专有名词不算；只抓全小写的裸枚举 / 字段名 / 表名。
const LEAK = /(?<![A-Za-z0-9_])[a-z_]{4,}(?![A-Za-z0-9_])/g

function leaks(root: HTMLElement): string[] {
  const found = new Set<string>()
  const scan = (text: string | null) => {
    for (const match of (text || '').matchAll(LEAK)) {
      const word = match[0]
      if (!ALLOWED.has(word.replace(/_/g, '')) && !ALLOWED.has(word)) found.add(word)
    }
  }
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
  while (walker.nextNode()) {
    const parent = walker.currentNode.parentElement
    if (parent && (parent.closest('code') || parent.closest('style') || parent.closest('script'))) continue
    scan(walker.currentNode.textContent)
  }
  // 图标的 aria-label（如 check-circle）是 antd 内部图标名，不是文案；只查占位符和悬浮标题。
  root.querySelectorAll('[placeholder],[title]').forEach((el) => {
    if (el.closest('[role=img]')) return
    for (const attr of ['placeholder', 'title']) scan(el.getAttribute(attr))
  })
  return [...found].sort()
}

const response = (data: any) => ({ data: { data } } as any)
const cursorPage = (rows: any[]) => ({ data: { data: rows, meta: { has_more: false, next_cursor: '' } } } as any)
const node = (kind: string, id: string, name: string, budget: number | null, used: number | null, status: string, children?: any[]) =>
  ({ kind, id, name, budget_micros: budget, used_micros: used, remaining_micros: budget !== null && used !== null ? Math.max(0, budget - used) : null, status, currency: 'CNY', children })
const rate = { currency: 'CNY', input_per_million_micros: 2_000_000, cached_input_per_million_micros: 0, cache_write_per_million_micros: 0, output_per_million_micros: 8_000_000, extensions: {} }

function mockAll(populated: boolean) {
  useAuthStore.setState({ token: 't', isAuthenticated: true, user: { id: 'admin', username: '管理员', role: 'platform_admin', tenant_id: 'tenant-a' } as any })
  const rows = <T,>(items: T[]) => (populated ? items : [])
  vi.spyOn(api.tenantApi, 'list').mockResolvedValue({ data: [{ id: 'tenant-a', name: '测试单位' }] } as any)
  vi.spyOn(api.billingAdminApi, 'runtime').mockResolvedValue(response({ mode: 'metering', description: '仅计量，不扣余额', prepaid_tools_visible: false }))
  vi.spyOn(api.billingAdminApi, 'models').mockResolvedValue(response(rows([{ model_name: 'deepseek-chat', model_label: 'deepseek-chat', provider_name: '官方直连', provider_type: 'deepseek', status: 'active' }])))
  vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue(cursorPage([]))
  vi.spyOn(api.billingAdminApi, 'customerGroups').mockResolvedValue(response([]))
  vi.spyOn(api.billingAdminApi, 'ledger').mockResolvedValue(cursorPage(rows([
    { id: 'l1', created_at: '2026-10-11T01:00:00Z', username: '张三', currency: 'CNY', event_type: 'settle', balance_delta_micros: -1_000_000, reserved_delta_micros: 0, balance_after_micros: 9_000_000, request_id: '请求一' },
    { id: 'l2', created_at: '2026-10-11T02:00:00Z', username: '李四', currency: 'CNY', event_type: 'adjustment', balance_delta_micros: -500_000, reserved_delta_micros: 0, balance_after_micros: -500_000, request_id: '', metadata: { overdraft: true } },
  ])))
  vi.spyOn(api.billingAdminApi, 'prices').mockResolvedValue(response([]))
  vi.spyOn(api.billingAdminApi, 'redemptions').mockResolvedValue(response([]))
  vi.spyOn(api.billingAdminApi, 'tariffs').mockResolvedValue(response(rows([{ id: 'plan-1', name: '工作日峰谷', version: 2, status: 'active', timezone: 'Asia/Shanghai', rules: [
    { id: 'r1', code: 'rule-1', name: '工作日高峰', model_name: 'deepseek-chat', band: 'peak', weekdays: [1, 2, 3, 4, 5], start_minute: 540, end_minute: 1080, multiplier_ppm: 1_200_000 },
    { id: 'r2', code: 'rule-2', name: '节假日', model_name: 'deepseek-chat', band: 'valley', weekdays: [1], special_date: '2026-10-01T00:00:00Z', start_minute: 0, end_minute: 1440, multiplier_ppm: 700_000 },
  ] }])))
  vi.spyOn(api.billingAdminApi, 'previewTariff').mockResolvedValue(response(populated ? { band: 'peak', rule_name: '工作日高峰', multiplier_ppm: 1_200_000 } : null))
  vi.spyOn(api.billingAdminApi, 'monthlyStatement').mockResolvedValue(response({ month: '2026-10', timezone: 'Asia/Shanghai', currency: 'CNY',
    total: { requests: populated ? 3 : 0, total_tokens: 100, billed_micros: 1_000_000, billed_requests: 3, unbilled_requests: 0, unpriced_requests: 0, usage_unknown_requests: 0 },
    departments: rows([{ department_id: 'd1', department_name: '研发部', requests: 3, total_tokens: 100, billed_micros: 1_000_000, billed_requests: 3, unbilled_requests: 0, unpriced_requests: 0, usage_unknown_requests: 0, employees: [] }]) }))
  vi.spyOn(api.billingEmployeeApi, 'fixedCosts').mockResolvedValue(response([]))
  vi.spyOn(api.billingEmployeeApi, 'upstreamRates').mockResolvedValue(response(rows([{ provider_id: 'p1', provider_name: '官方直连', model_name: 'deepseek-chat', ...rate }])))
  vi.spyOn(api.billingEmployeeApi, 'upstreamModels').mockResolvedValue(response(rows([{ provider_id: 'p1', provider_name: '官方直连', model_name: 'deepseek-chat' }])))
  vi.spyOn(api.billingEmployeeApi, 'budgetTree').mockResolvedValue(response(populated
    ? node('organization', 'tenant-a', '测试单位', 100_000_000, 10_000_000, 'normal', [node('department', 'd1', '研发部', 5_000_000, 4_500_000, 'warning', [node('employee', 'u1', '张三', 1_000_000, 1_000_000, 'exhausted')])])
    : node('organization', 'tenant-a', '测试单位', null, null, 'unlimited', [])))
  vi.spyOn(api.billingEmployeeApi, 'settings').mockResolvedValue(response({ currency: 'CNY', timezone: 'Asia/Shanghai', default_monthly_micros: null }))
  vi.spyOn(api.billingEmployeeApi, 'list').mockResolvedValue(response(rows([{ user_id: 'u1', username: '张三', department_name: '研发部', monthly_micros: 1_000_000, effective_micros: 1_000_000, used_micros: 1_000_000, reserved_micros: 0, currency: 'CNY' }])))
  vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: rows([{ id: 'd1', name: '研发部' }]) } } as any)
  vi.spyOn(api.contentAuditApi, 'listUsers').mockResolvedValue({ data: { data: [] } } as any)
  vi.spyOn(api.keyApi, 'list').mockResolvedValue({ data: [] } as any)
  vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: [] } as any)
  vi.spyOn(api.policyApi, 'getQuota').mockResolvedValue({ data: {} } as any)
  const usage = { requests: populated ? 120 : 0, input_tokens: populated ? 1000 : 0, output_tokens: populated ? 200 : 0, total_cost: populated ? 3.5 : 0 }
  vi.spyOn(api.usageApi, 'summary').mockResolvedValue({ data: usage } as any)
  vi.spyOn(api.usageApi, 'costCoverage').mockResolvedValue({ data: { total_requests: usage.requests, priced_requests: usage.requests, unpriced_requests: 0, coverage_rate: populated ? 1 : 0, unpriced_model_count: 0 } } as any)
  for (const key of ['byProject', 'byModel', 'byUser', 'byKey', 'byProvider', 'recommendations'] as const) vi.spyOn(api.usageApi, key).mockResolvedValue({ data: [] } as any)
  vi.spyOn(api.billingAnalyticsApi, 'summary').mockResolvedValue({ data: { requests: usage.requests, priced_requests: usage.requests, unpriced_requests: 0, prompt_tokens: 1000, cached_input_tokens: 0, cache_write_input_tokens: 0, output_tokens: 200, reasoning_tokens: 0, total_tokens: populated ? 1200 : 0, billable_micros: populated ? 3_500_000 : 0, upstream_cost_micros: 0, upstream_cost_known_requests: 0, currency: 'CNY' } } as any)
  vi.spyOn(api.billingAnalyticsApi, 'breakdown').mockResolvedValue({ data: rows([{ id: 'm1', name: 'deepseek-chat', requests: 120, priced_requests: 120, total_tokens: 1200, billable_micros: 3_500_000, upstream_cost_micros: 0, cost_share: 1 }]) } as any)
  vi.spyOn(api.billingAnalyticsApi, 'series').mockResolvedValue({ data: rows([{ bucket: '2026-10-10T16:00:00Z', requests: 120, total_tokens: 1200, billable_micros: 3_500_000 }]) } as any)
  vi.spyOn(api.billingAnalyticsApi, 'timeProfile').mockResolvedValue({ data: [] } as any)
  vi.spyOn(api.billingAnalyticsApi, 'departmentProviderMatrix').mockResolvedValue({ data: [] } as any)
}

const pageTitle = (source: string) => source.match(/<(?:EnterprisePageHeader|BillingConsoleHeader)[\s\S]*?title="([^"]+)"/)?.[1] || (labels as Record<string, string>)[literal(source, /title=\{labels\.([a-zA-Z]+)\}/)]
const pages: Array<[string, () => JSX.Element, string]> = [
  ['overview', () => <BillingOverview />, pageTitle(usageSource)],
  ['wallet', () => <BillingBudgets />, pageTitle(budgetsSource)],
  ['pricing', () => <BillingPricing />, pageTitle(pricingSource)],
  ['statements', () => <BillingStatements />, pageTitle(statementsSource)],
]

describe('计费页面中文化守护', () => {
  let client: QueryClient
  beforeEach(() => { client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }) })
  afterEach(() => { vi.restoreAllMocks(); cleanup(); document.body.innerHTML = '' })

  for (const populated of [false, true]) {
    for (const [name, page, marker] of pages) {
      it(`${name}（${populated ? '有数据' : '空态'}）不露英文枚举`, async () => {
        mockAll(populated)
        const user = userEvent.setup()
        render(<ConfigProvider locale={zhCN}><MemoryRouter><QueryClientProvider client={client}>{page()}</QueryClientProvider></MemoryRouter></ConfigProvider>)
        expect(await screen.findByText(marker)).toBeInTheDocument()
        await waitFor(() => expect(document.querySelector('.ant-spin-spinning')).toBeNull())
        // 依次切换页签，覆盖每个分区
        const tabs = screen.queryAllByRole('tab')
        for (const tab of tabs) {
          await user.click(tab)
          await waitFor(() => expect(document.querySelector('.ant-spin-spinning')).toBeNull())
          expect(leaks(document.body), `切到「${tab.textContent}」`).toEqual([])
        }
        expect(leaks(document.body)).toEqual([])
        expect(document.body.textContent).not.toMatch(/No data|\/ page|Expand row|HTTP \d{3}|undefined|NaN/)
      }, 30_000)
    }
  }

  it('守护规则本身能抓到裸英文枚举、表名和英文空态', () => {
    const el = document.createElement('div')
    el.innerHTML = '<span>状态：unpriced</span><span>billing_usage_facts</span><span>No data</span><span>deepseek-chat · Token · Asia/Shanghai</span>'
    expect(leaks(el)).toEqual(['billing_usage_facts', 'data', 'unpriced'])
  })

  it('offers tariff and cost entry actions from empty pricing sections', async () => {
    mockAll(false)
    const user = userEvent.setup()
    render(<ConfigProvider locale={zhCN}><MemoryRouter><QueryClientProvider client={client}><BillingPricing /></QueryClientProvider></MemoryRouter></ConfigProvider>)
    await user.click(await screen.findByRole('tab', { name: labels.tariffs }))
    const createTariff = literal(pricingSectionSource, /setTariffOpen\(true\) \}\}>([^<]+)<\/Button><\/Empty>/)
    expect(await screen.findByRole('button', { name: sourceRegex(createTariff) })).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: labels.upstream }))
    const addCost = literal(upstreamSource, /emptyText:[^\n]*edit\(\)\}>([^<]+)<\/Button>/)
    expect(screen.getByRole('button', { name: addCost })).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: labels.fixed }))
    const addFixed = literal(fixedSource, /extra=\{<Button[^\n]*edit\(\)\}>([^<]+)<\/Button>/)
    expect(await screen.findByRole('button', { name: addFixed })).toBeInTheDocument()
    expect(leaks(document.body)).toEqual([])
  }, 30_000)
})
