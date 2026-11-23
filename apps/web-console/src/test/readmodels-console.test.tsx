import { billingSourceLabels, sourceRegex } from './billingSourceLabels'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ServiceHealth from '../pages/ServiceHealth'
import { BillingWalletTestHarness } from './BillingWalletTestHarness'
import * as api from '../services/api'

const response = (data: any) => ({ data: { data } } as any)
// 列表端点走游标分页协议：响应必须带 has_more/next_cursor，
// 否则前端会如实显示「未启用游标分页」而不是假装已到最后一页
const cursorPage = (rows: any[], hasMore: boolean, nextCursor: string) =>
  ({ data: { data: rows, meta: { has_more: hasMore, next_cursor: nextCursor } } } as any)

describe('ServiceHealth page（读模型）', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    cleanup()
    document.body.innerHTML = ''
  })

  const renderPage = () => render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <ServiceHealth />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('renders each component status truthfully (unknown is never healthy)', async () => {
    vi.spyOn(api.serviceHealthApi, 'readModel').mockResolvedValue(response({
      components: [
        { component: 'control-plane', status: 'healthy', database: 'ok', redis: 'ok', evidence: 'local ping', observed_at: '2026-10-02T05:00:00Z' },
        { component: 'gateway-core', status: 'healthy', http_status: 200, latency_ms: 3, evidence: 'probe', observed_at: '2026-10-02T05:00:00Z' },
        { component: 'judge', status: 'unknown', fault_events_24h: null, evidence: 'no endpoint', observed_at: '2026-10-02T05:00:00Z' },
        { component: 'audit-pipeline', status: 'processing', requests_24h: 10, pending_24h: 2, oldest_pending_age_seconds: 120, evidence: 'audit outcomes', observed_at: '2026-10-02T05:00:00Z' },
        { component: 'billing-compensation', status: 'degraded', stale_reserved_count: 4, evidence: 'reservations', observed_at: '2026-10-02T05:00:00Z' },
      ],
      upstream_quality_note: 'provider metrics served elsewhere',
      generated_at: '2026-10-02T05:00:00Z',
    }) as any)
    renderPage()
    // Keep the original status checks while using administrator-facing names.
    expect(await screen.findByRole('heading', { name: '\u7ba1\u7406\u540e\u7aef' })).toBeInTheDocument()
    expect(screen.getAllByText('\u6b63\u5e38').length).toBe(2)
    expect(screen.getAllByText('\u5f85\u76d1\u6d4b').length).toBeGreaterThan(0)
    expect(screen.getByText('处理中')).toBeInTheDocument()
    expect(screen.getByText('\u5f02\u5e38')).toBeInTheDocument()
  })


  it('shows effective profile, C2 metrics and visible cascade/degradation warnings', async () => {
    vi.spyOn(api.serviceHealthApi, 'readModel').mockResolvedValue(response({
      components: [
        { component: 'control-plane', status: 'healthy', database: 'ok', redis: 'ok', evidence: 'local ping', observed_at: '2026-10-02T05:00:00Z' },
        { component: 'gateway-core', status: 'healthy', http_status: 200, latency_ms: 3, evidence: 'probe', observed_at: '2026-10-02T05:00:00Z' },
        { component: 'security-engine', status: 'healthy', http_status: 200, latency_ms: 5, evidence: 'probe', observed_at: '2026-10-02T05:00:00Z',
          engine_resource_profile: 'xlarge-cpu64', engine_web_concurrency: '16', engine_judge_global_concurrency: '96',
          engine_metrics_scope: 'cluster', judge_calls_per_request_avg: 1.4, fingerprint_hit_rate: 0.82,
          engine_tier1_inference_workers: '8', engine_tier1_inference_capacity: '256',
          engine_tier1_concurrency_status: 'within_limit', engine_tier1_live_provider: 'cuda',
          engine_tier1_replicas: '3', engine_tier1_scale_mode: 'cpu',
          engine_tier1_live_threads: 4, engine_tier1_live_batch_windows: 16, engine_tier1_live_reachable: true,
          engine_tier1_live_inference_workers: 12, engine_tier1_live_inference_capacity: 192,
          engine_tier1_live_uvicorn_workers: 3, engine_tier1_capacity_matches_profile: false,
          engine_cascade_warnings: ['tier1_cascade_disabled: low<0.05'],
          engine_degradation_reasons: ['file_id_registry_unavailable'] },
        { component: 'judge', status: 'unknown', evidence: 'no endpoint', observed_at: '2026-10-02T05:00:00Z' },
        { component: 'audit-pipeline', status: 'processing', requests_24h: 10, pending_24h: 2, oldest_pending_age_seconds: 120, evidence: 'audit outcomes', observed_at: '2026-10-02T05:00:00Z' },
        { component: 'billing-compensation', status: 'degraded', stale_reserved_count: 4, evidence: 'reservations', observed_at: '2026-10-02T05:00:00Z' },
      ],
      generated_at: '2026-10-02T05:00:00Z',
    }) as any)
    renderPage()
    expect(await screen.findByText('Tier-1 级联已关闭或处于降级状态')).toBeInTheDocument()
    expect(screen.getByText('检测降级（审计可见）')).toBeInTheDocument()
    expect(screen.getByText('tier1_cascade_disabled: low<0.05')).toBeInTheDocument()
    expect(screen.getByText('file_id_registry_unavailable')).toBeInTheDocument()
    expect(screen.getByText('生效资源档位')).toBeInTheDocument()
    expect(screen.getByText('xlarge-cpu64')).toBeInTheDocument()
    expect(screen.getByText('每请求判官调用')).toBeInTheDocument()
    expect(screen.getByText('1.4 \u6b21')).toBeInTheDocument()
    expect(screen.getByText('指纹命中率')).toBeInTheDocument()
    expect(screen.getByText('82.0%')).toBeInTheDocument()
    // R3: the tier1 container's own shape must be visible, so an install can no
    // longer show 4x4 while the sidecar really runs 1x1.
    expect(screen.getByText('within_limit')).toBeInTheDocument()
    expect(screen.getByText('cuda')).toBeInTheDocument()
    expect(screen.getByText('256')).toBeInTheDocument()
    // S1: 实测池与档位的对比必须可见，否则 2x16 被按成 8x256 时没人看得见。
    expect(screen.getByText('Tier-1 实测推理进程')).toBeInTheDocument()
    expect(screen.getByText('12 个')).toBeInTheDocument()
    expect(screen.getByText('192 路')).toBeInTheDocument()
    expect(screen.getByText('Tier-1 容量与档位一致')).toBeInTheDocument()
    expect(screen.getByText('否')).toBeInTheDocument()
    // U2: 扩容拓扑必须可见，否则扩过容的机器升级后悄悄回到单副本没人发现。
    expect(screen.getByText('Tier-1 副本数（配置）')).toBeInTheDocument()
    expect(screen.getByText('3 个')).toBeInTheDocument()
    expect(screen.getByText('Tier-1 扩容模式')).toBeInTheDocument()
  })

  it('shows a permission explanation on 403 instead of a generic failure', async () => {
    vi.spyOn(api.serviceHealthApi, 'readModel').mockRejectedValue({ response: { status: 403 } } as any)
    renderPage()
    expect(await screen.findByText('\u670d\u52a1\u72b6\u6001\u6682\u65f6\u65e0\u6cd5\u83b7\u53d6')).toBeInTheDocument()
    expect(screen.getByText('服务健康为平台管理员专用视图，当前账号无权限查看。')).toBeInTheDocument()
  })
})

describe('wallet ledger tab（读模型）', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    window.sessionStorage.clear()
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue({ data: [{ id: 'tenant-a', name: 'XX科技' }] } as any)
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
    window.sessionStorage.clear()
  })

  const renderPage = () => render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <BillingWalletTestHarness />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('loads more customers through the server cursor and stops without has_more', async () => {
    const user = userEvent.setup()
    const customersSpy = vi.spyOn(api.billingAdminApi, 'customers')
      .mockResolvedValueOnce({
        data: {
          data: [{ user_id: 'user-a', username: 'Alice', email: 'alice@example.com', customer_group: 'default',
            customer_group_name: '默认客户组', customer_group_status: 'active',
            balance_micros: 5_000_000, reserved_micros: 1_000_000, available_micros: 4_000_000, wallet_id: 'wallet-a' }],
          meta: { has_more: true, next_cursor: 'cursor-2' },
        },
      } as any)
      .mockResolvedValue({ data: { data: [], meta: { has_more: false, next_cursor: '' } } } as any)
    renderPage()
    await user.click(await screen.findByRole('tab', { name: sourceRegex(billingSourceLabels.accounts) }))
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    const nextButton = () => screen.getByRole('button', { name: '下一页' })
    expect(nextButton()).toBeEnabled()
    await user.click(nextButton())
    await waitFor(() => expect(customersSpy).toHaveBeenCalledTimes(2))
    // 第二页请求携带上一页返回的游标
    expect(customersSpy).toHaveBeenNthCalledWith(2, 'tenant-a', 'cursor-2', 100)
    // 第二页无 has_more：下一页禁用，并如实标注已到最后一页
    await waitFor(() => expect(nextButton()).toBeDisabled())
    expect(screen.getByText(/已到最后一页/)).toBeInTheDocument()
  })
})
