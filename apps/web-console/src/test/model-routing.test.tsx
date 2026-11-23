import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import ModelRouting from '../pages/ModelRouting'
import { modelRoutingApi } from '../services/api'

const { authRole } = vi.hoisted(() => ({ authRole: { value: undefined as string | undefined } }))
vi.mock('../stores/auth', () => ({ useAuthStore: (selector: (state: { user?: { role?: string } }) => unknown) => selector({ user: authRole.value ? { role: authRole.value } : undefined }) }))
vi.mock('../services/api', () => ({
  modelRoutingApi: {
    overview: vi.fn(), status: vi.fn(), providers: vi.fn(), searchModels: vi.fn(), validate: vi.fn(), saveDefault: vi.fn(), saveOverride: vi.fn(), deleteOverride: vi.fn(), deleteDefault: vi.fn(),
  },
}))

const defaultConfig = {
  strategy: 'priority' as const,
  cost_basis: 'none' as const,
  providers: [
    { route_ref: 'rt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', display_name: '火线宝上游', enabled: true, priority: 1, weight: 60 },
    { route_ref: 'rt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', display_name: '政务云上游', enabled: true, priority: 2, weight: 40 },
  ],
}
const overview = {
  default_rule: { config: defaultConfig, config_version: 3, enabled: true },
  model_exceptions: [{ model_name: 'qwen-max', config: { ...defaultConfig, strategy: 'weighted' as const }, config_version: 2, enabled: true }],
  multi_route_model_count: 2, unhealthy_route_count: 0, today_fallback_count: 0, outbound_route_available: true, legacy_report: [],
}
const statusModels = [
  {
    model_name: 'qwen-max', state: 'configured' as const, route_count: 2, configured_candidate_count: 2, eligible_candidate_count: 2, config_version: 2,
    routes: [
      { route_ref: 'rt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', provider_name: '火线宝上游', avg_ttft_ms: 820, samples_30m: 12, failures_30m: 0, health_state: 'healthy' as const, capability_state: 'supported' as const, input_per_million: 2.1, output_per_million: 4.2 },
      { route_ref: 'rt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', provider_name: '政务云上游', avg_ttft_ms: null, samples_30m: 0, failures_30m: 0, health_state: 'unknown' as const, capability_state: 'unknown' as const },
    ],
  },
  {
    model_name: 'deepseek-r1', state: 'pending' as const, route_count: 2, configured_candidate_count: 2, eligible_candidate_count: 2, config_version: 0,
    routes: [
      { route_ref: 'rt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', provider_name: '火线宝上游', avg_ttft_ms: 650, samples_30m: 9, failures_30m: 0, health_state: 'healthy' as const, capability_state: 'supported' as const },
      { route_ref: 'rt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', provider_name: '政务云上游', avg_ttft_ms: 700, samples_30m: 4, failures_30m: 0, health_state: 'healthy' as const, capability_state: 'unknown' as const },
    ],
  },
]

function renderPage(initialEntry = '/') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const LocationProbe = () => <span data-testid="location">{useLocation().pathname}</span>
  return render(<MemoryRouter initialEntries={[initialEntry]}><QueryClientProvider client={client}><ModelRouting /><LocationProbe /></QueryClientProvider></MemoryRouter>)
}

describe('ModelRouting — 同名模型多上游负载配置', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authRole.value = 'platform_admin'
    vi.mocked(modelRoutingApi.overview).mockResolvedValue(overview)
    vi.mocked(modelRoutingApi.status).mockResolvedValue({ models: statusModels, next_cursor: '' })
    vi.mocked(modelRoutingApi.providers).mockResolvedValue({ providers: defaultConfig.providers.map(({ route_ref, display_name }) => ({ route_ref, display_name })) })
    vi.mocked(modelRoutingApi.validate).mockResolvedValue({ valid: true, scope: 'override', model_name: 'deepseek-r1', provider_count: 2, provider_names: ['火线宝上游', '政务云上游'], warnings: [] })
    vi.mocked(modelRoutingApi.saveDefault).mockResolvedValue(overview.default_rule)
    vi.mocked(modelRoutingApi.saveOverride).mockResolvedValue(overview.model_exceptions[0])
    vi.mocked(modelRoutingApi.deleteOverride).mockResolvedValue({ deleted: true, model_name: 'qwen-max' })
    vi.mocked(modelRoutingApi.deleteDefault).mockResolvedValue({ deleted: true })
  })

  it('明确说明只展示同名模型的多上游路径', async () => {
    renderPage()
    expect((await screen.findAllByText('多上游模型')).length).toBeGreaterThan(0)
    expect(screen.getByText(/同一个模型接入多个上游/)).toBeInTheDocument()
    expect(screen.queryByText('无可用线路')).not.toBeInTheDocument()
    expect(screen.queryByText('需要处理')).not.toBeInTheDocument()
    expect(screen.queryByText('无需配置')).not.toBeInTheDocument()
  })

  it('请求接口时只查询至少两个上游的模型', async () => {
    renderPage()
    await waitFor(() => expect(modelRoutingApi.status).toHaveBeenCalledWith(expect.objectContaining({ min_route_count: 2 })))
  })

  it('列表直接展示上游数和负载方式', async () => {
    renderPage()
    expect(await screen.findByText('qwen-max')).toBeInTheDocument()
    expect(screen.getByText('deepseek-r1')).toBeInTheDocument()
    expect(screen.getAllByText('2 条路径')).toHaveLength(2)
    expect(screen.getByText('按权重分流')).toBeInTheDocument()
  })

  it('展开可看到每个真实上游且不把未知健康误报为异常', async () => {
    const user = userEvent.setup()
    renderPage()
    const row = (await screen.findByText('qwen-max')).closest('tr')!
    await user.click(row.querySelector('.ant-table-row-expand-icon')!)
    expect(await screen.findByText('火线宝上游')).toBeInTheDocument()
    expect(screen.getByText('政务云上游')).toBeInTheDocument()
    expect(screen.getByText('待产生调用数据')).toBeInTheDocument()
    expect(screen.queryByText('无可用线路')).not.toBeInTheDocument()
  })

  it('系统默认方式可配置并由未单独配置的模型继承', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: '配置系统默认' }))
    expect(await screen.findByText('配置系统默认负载方式')).toBeInTheDocument()
    expect(screen.getByText(/适用于所有未单独配置的多上游模型/)).toBeInTheDocument()
    expect(screen.getByText(/以后新增的多上游模型也会自动继承/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '检查配置' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '保存配置' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '保存配置' }))
    await waitFor(() => expect(modelRoutingApi.saveDefault).toHaveBeenCalledWith(3, expect.objectContaining({ strategy: 'priority' })))
  })

  it('配置抽屉提供六种真实生效的负载方式', async () => {
    const user = userEvent.setup()
    renderPage()
    const row = (await screen.findByText('deepseek-r1')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '配置负载' }))
    expect(await screen.findByText('配置多路径负载 · deepseek-r1')).toBeInTheDocument()
    for (const name of ['主备切换', '按权重分流', '稳定优先', '速度优先', '成本优先', '综合均衡']) {
      expect(screen.getByRole('radio', { name: new RegExp(name) })).toBeInTheDocument()
    }
    expect(screen.getByText(/不会把请求切换成其他模型/)).toBeInTheDocument()
  })

  it('按权重分流可分别设置每个上游的权重', async () => {
    const user = userEvent.setup()
    renderPage()
    const row = (await screen.findByText('deepseek-r1')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '配置负载' }))
    const weighted = screen.getByRole('radio', { name: /按权重分流/ })
    await user.click(weighted.closest('label')!)
    expect(screen.getByRole('spinbutton', { name: '火线宝上游权重' })).toBeInTheDocument()
    expect(screen.getByRole('spinbutton', { name: '政务云上游权重' })).toBeInTheDocument()
    expect(screen.getByText(/无需强制合计为 100/)).toBeInTheDocument()
  })

  it('保存前必须检查且保存到该模型', async () => {
    const user = userEvent.setup()
    renderPage()
    const row = (await screen.findByText('deepseek-r1')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '配置负载' }))
    const save = screen.getByRole('button', { name: '保存配置' })
    expect(save).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '检查配置' }))
    await waitFor(() => expect(save).toBeEnabled())
    await user.click(save)
    await waitFor(() => expect(modelRoutingApi.saveOverride).toHaveBeenCalledWith('deepseek-r1', 0, expect.objectContaining({ strategy: 'priority' })))
  })

  it('单独配置可恢复系统默认', async () => {
    const user = userEvent.setup()
    renderPage()
    const row = (await screen.findByText('qwen-max')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '恢复默认' }))
    await waitFor(() => expect(modelRoutingApi.deleteOverride).toHaveBeenCalledWith('qwen-max', expect.anything()))
  })

  it('页面不暴露内部 route_ref 标识', async () => {
    const { container } = renderPage()
    await screen.findByText('qwen-max')
    expect(container.textContent || '').not.toContain('rt_aaaa')
    expect(container.textContent || '').not.toContain('provider_id')
  })

  it('默认路由引用已删除上游时显示修复引导且可跳转', async () => {
    const user = userEvent.setup()
    vi.mocked(modelRoutingApi.overview).mockResolvedValue({
      ...overview,
      outbound_route_available: false,
      default_rule: { config: { strategy: 'priority', cost_basis: 'none', providers: [] }, config_version: 9, enabled: true, invalid: true, invalid_reason: 'configured_route_removed' },
    })
    vi.mocked(modelRoutingApi.status).mockResolvedValue({ models: [], next_cursor: '' })
    renderPage('/model-routing')
    expect(await screen.findByText('默认路由已失效')).toBeInTheDocument()
    expect(screen.queryByText('模型路由加载失败')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '前往模型上游' }))
    expect(screen.getByTestId('location')).toHaveTextContent('/providers')
  })

  it('默认路由失效时可在页面直接清除默认路由', async () => {
    const user = userEvent.setup()
    vi.mocked(modelRoutingApi.overview).mockResolvedValue({
      ...overview,
      default_rule: { config: { strategy: 'priority', cost_basis: 'none', providers: [] }, config_version: 9, enabled: true, invalid: true, invalid_reason: 'configured_route_removed' },
    })
    vi.mocked(modelRoutingApi.status).mockResolvedValue({ models: [], next_cursor: '' })
    renderPage('/model-routing')
    expect(await screen.findByText('默认路由已失效')).toBeInTheDocument()
    expect(screen.getByText(/单上游模型会继续直接调用/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '清除默认路由' }))
    await user.click(await screen.findByRole('button', { name: /^清\s*除$/ }))
    await waitFor(() => expect(modelRoutingApi.deleteDefault).toHaveBeenCalledTimes(1))
  })

  it('历史遗留的模型级规则出现在待处理区域并可清除', async () => {
    const user = userEvent.setup()
    vi.mocked(modelRoutingApi.overview).mockResolvedValue({
      ...overview,
      model_exceptions: [{ model_name: 'legacy-model', config: { ...defaultConfig, providers: [] }, config_version: 1, enabled: true, invalid: true, invalid_reason: 'configured_route_removed' }],
    })
    renderPage('/model-routing')
    expect(await screen.findByText('待处理的模型级规则')).toBeInTheDocument()
    expect(screen.getByText('legacy-model')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '清除规则' }))
    await user.click(await screen.findByRole('button', { name: /^清\s*除$/ }))
    await waitFor(() => expect(modelRoutingApi.deleteOverride).toHaveBeenCalledWith('legacy-model', expect.anything()))
  })

  it('没有有效模型或出站线路时页面仍可打开并引导恢复', async () => {
    vi.mocked(modelRoutingApi.overview).mockResolvedValue({ ...overview, default_rule: null, outbound_route_available: false })
    vi.mocked(modelRoutingApi.status).mockResolvedValue({ models: [], next_cursor: '' })
    renderPage('/model-routing')
    expect(await screen.findByText('当前没有可出站的模型线路')).toBeInTheDocument()
    expect(screen.getByText(/请先恢复或新增模型上游并同步至少一个可调用模型/)).toBeInTheDocument()
    expect(screen.queryByText('模型路由加载失败')).not.toBeInTheDocument()
  })
})
