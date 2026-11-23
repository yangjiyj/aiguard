import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ServiceHealth from '../pages/ServiceHealth'
import { serviceHealthApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

const text = {
  control: '\u7ba1\u7406\u540e\u7aef', gateway: '\u8bf7\u6c42\u7f51\u5173', engine: '\u5b89\u5168\u68c0\u6d4b\u5f15\u64ce',
  judge: '\u8bed\u4e49\u5b89\u5168\u5224\u5b98', audit: '\u5ba1\u8ba1\u5904\u7406', billing: '\u8ba1\u8d39\u8865\u507f\u4efb\u52a1',
  healthy: '\u6b63\u5e38', pending: '\u5f85\u76d1\u6d4b', cleanPending: '\u65e0\u79ef\u538b\uff0c\u4efb\u52a1\u72b6\u6001\u5f85\u76d1\u6d4b',
  diagnostics: '\u8bca\u65ad\u6307\u6807', technical: '\u6280\u672f\u8be6\u60c5', modelQuality: '\u6a21\u578b\u8fd0\u8425',
  noEvidence: '\u6682\u65e0\u7ec4\u4ef6\u8bc1\u636e', noObservation: '\u672a\u83b7\u53d6\u89c2\u6d4b\u7ed3\u679c',
  failed: '\u8bc1\u636e\u67e5\u8be2\u5931\u8d25', stale: '\u4efb\u52a1\u72b6\u6001\u5df2\u8fc7\u671f',
  second: '\u79d2', millisecond: '\u6beb\u79d2', none: '\u65e0', unknown: '\u672a\u83b7\u53d6',
  current: '\u5f53\u524d\u72b6\u6001',
  notRequired: '\u5f53\u524d\u8ba1\u8d39\u6a21\u5f0f\u4e0d\u9700\u8981\u8d39\u7528\u8865\u507f\u4efb\u52a1\u3002',
  billingDisabled: '\u8ba1\u8d39\u672a\u542f\u7528\uff0c\u5f53\u524d\u4e0d\u8fd0\u884c\u8d39\u7528\u8865\u507f\u4efb\u52a1\u3002',
  requests: '\u8bf7\u6c42\u8bb0\u5f55', judgeAvailable: '\u5224\u5b98\u53ef\u7528',
  reportFresh: '\u8fd0\u884c\u62a5\u544a\u6709\u6548', reportAvailable: '\u8fd0\u884c\u62a5\u544a\u53ef\u7528',
  databaseFailed: '\u6570\u636e\u5e93\u8fde\u63a5\u5931\u8d25\uff0c\u8bf7\u68c0\u67e5\u6570\u636e\u5e93\u670d\u52a1\u3002',
  cacheFailed: '\u7f13\u5b58\u8fde\u63a5\u5931\u8d25\uff0c\u8bf7\u68c0\u67e5\u7f13\u5b58\u670d\u52a1\u3002',
  auditStale: '\u5ba1\u8ba1\u8bb0\u5f55\u7b49\u5f85\u5904\u7406\u5df2\u8d85\u8fc7\u9608\u503c\uff0c\u8bf7\u68c0\u67e5\u5ba1\u8ba1\u5199\u5165\u3002',
}

const stamp = '2026-10-05T10:00:00Z'
const response = (components: Record<string, unknown>[], extra = {}) => ({ data: { data: { components, generated_at: stamp, ...extra } } } as any)
const component = (name: string, status = 'healthy', extra = {}) => ({ component: name, status, observed_at: stamp, ...extra })

describe('ServiceHealth administrator conclusions', () => {
  let client: QueryClient
  const renderPage = () => render(<MemoryRouter><QueryClientProvider client={client}><ServiceHealth /></QueryClientProvider></MemoryRouter>)

  beforeEach(() => {
    client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    useAuthStore.setState({ user: { id: 'health-admin', username: 'health-admin', role: 'platform_admin' } })
  })

  afterEach(() => {
    cleanup()
    client.clear()
    vi.restoreAllMocks()
    useAuthStore.setState({ user: null })
  })

  it('names the six components and gives clean backlog no worker health claim', async () => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([
      component('control-plane', 'healthy', { database: 'ok', redis: 'ok' }), component('gateway-core'), component('security-engine'),
      component('judge', 'unknown', { fault_events_24h: 0 }), component('audit-pipeline', 'healthy', { requests_24h: 7, pending_24h: 0 }),
      component('billing-compensation', 'unknown', { backlog_status: 'clean', worker_status: 'unknown', stale_reserved_count: 0, expired_unreleased_lease_count: 0 }),
    ], { upstream_quality_note: 'internal English debugging note' }))
    renderPage()
    for (const name of [text.control, text.gateway, text.engine, text.judge, text.audit, text.billing]) {
      expect(await screen.findByRole('heading', { name })).toBeInTheDocument()
    }
    const judge = screen.getByRole('region', { name: text.judge })
    expect(within(judge).getByText(text.pending)).toBeInTheDocument()
    expect(within(judge).queryByText(text.healthy)).not.toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: text.billing })).getByText(text.cleanPending)).toBeInTheDocument()
    expect(screen.queryByText('internal English debugging note')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: text.modelQuality })).toHaveAttribute('href', '/model-operations?tab=quality')
  })

  it('shows Chinese diagnostic units, distinguishes absent age from unknown, and never echoes arbitrary fields', async () => {
    const user = userEvent.setup()
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([
      component('gateway-core', 'healthy', { http_status: 200, latency_ms: 3, target_url: 'http://private.example:8080', evidence: 'secret-token-123' }),
      component('billing-compensation', 'unknown', { backlog_status: 'clean', worker_status: 'unknown', stale_reserved_count: 0, oldest_stale_age_seconds: null, expired_unreleased_lease_count: 0, worker_last_completed_at: null }),
      component('audit-pipeline', 'processing', { requests_24h: 7, pending_24h: 2, oldest_pending_age_seconds: 120 }),
    ]))
    renderPage()
    const gateway = await screen.findByRole('region', { name: text.gateway })
    await user.click(within(gateway).getByText(text.diagnostics))
    expect(within(gateway).getByText('3 ' + text.millisecond)).toBeInTheDocument()
    await user.click(within(gateway).getByText(text.technical))
    expect(screen.queryByText('http://private.example:8080')).not.toBeInTheDocument()
    expect(screen.queryByText('secret-token-123')).not.toBeInTheDocument()
    const audit = screen.getByRole('region', { name: text.audit })
    await user.click(within(audit).getByText(text.diagnostics))
    expect(within(audit).getByText('120 ' + text.second)).toBeInTheDocument()
    const billing = screen.getByRole('region', { name: text.billing })
    await user.click(within(billing).getByText(text.diagnostics))
    expect(within(billing).getAllByText(text.none).length).toBeGreaterThan(0)
    expect(within(billing).getAllByText(text.unknown).length).toBeGreaterThan(0)
  })

  it.each(['degraded', 'processing', 'stale', 'unknown', 'disabled'])('does not call %s worker healthy on a clean backlog', async (status) => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([
      component('billing-compensation', status === 'degraded' ? 'degraded' : 'unknown', { backlog_status: 'clean', worker_status: status }),
    ]))
    renderPage()
    const billing = await screen.findByRole('region', { name: text.billing })
    expect(within(billing).queryByText(text.healthy)).not.toBeInTheDocument()
    if (status === 'stale') expect(within(billing).getByText(text.stale)).toBeInTheDocument()
  })

  it('honors actual worker evidence without promoting unknown overall status', async () => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([
      component('billing-compensation', 'healthy', { backlog_status: 'clean', worker_status: 'healthy', worker_last_completed_at: stamp, worker_running: false }),
    ]))
    renderPage()
    const billing = await screen.findByRole('region', { name: text.billing })
    expect(within(billing).getByRole('status', { name: text.current })).toHaveTextContent(text.healthy)
  })

  it('keeps judge health tied to runtime status while a separate fault-count query fails', async () => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([
      component('judge', 'healthy', { runtime_fresh: true, judge_operational: true, judge_window_attempts: 8, fault_events_24h: null, fault_evidence_reason_code: 'evidence_query_failed' }),
    ]))
    renderPage()
    const judge = await screen.findByRole('region', { name: text.judge })
    expect(within(judge).getByRole('status', { name: text.current })).toHaveTextContent(text.healthy)
    expect(within(judge).queryByText(text.failed)).not.toBeInTheDocument()
  })

  it('does not promote unknown overall health from a healthy worker substatus', async () => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([
      component('billing-compensation', 'unknown', { backlog_status: 'clean', worker_status: 'healthy' }),
    ]))
    renderPage()
    const billing = await screen.findByRole('region', { name: text.billing })
    expect(within(billing).getByRole('status', { name: text.current })).toHaveTextContent(text.pending)
  })

  it.each(['disabled', 'unknown'])('explains metering/not_required without claiming billing itself is disabled (%s)', async (status) => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([
      component('billing-compensation', status, { billing_mode: 'metering', backlog_status: 'disabled', worker_status: 'disabled', worker_reason_code: 'not_required' }),
    ]))
    renderPage()
    const billing = await screen.findByRole('region', { name: text.billing })
    expect(within(billing).getByText(text.notRequired)).toBeInTheDocument()
    expect(within(billing).queryByText(text.billingDisabled)).not.toBeInTheDocument()
  })

  it('leaves absent observations and query failures unresolved even when numeric evidence is zero', async () => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([
      component('gateway-core', 'unknown', { observed_at: null }),
      component('judge', 'unknown', { reason_code: 'evidence_query_failed', fault_events_24h: 0 }),
      component('billing-compensation', 'unknown', { reason_code: 'evidence_query_failed', stale_reserved_count: 0 }),
    ]))
    renderPage()
    expect(await screen.findByText(text.noObservation)).toBeInTheDocument()
    expect(screen.getAllByText(text.failed)).toHaveLength(2)
    expect(screen.queryByText(text.healthy)).not.toBeInTheDocument()
  })

  it('reports missing component data without a fabricated six-row healthy view', async () => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([]))
    renderPage()
    expect(await screen.findByText(text.noEvidence)).toBeInTheDocument()
    expect(screen.queryByText(text.healthy)).not.toBeInTheDocument()
  })

  it('hides operational links from roles without access', async () => {
    useAuthStore.setState({ user: { id: 'auditor', username: 'auditor', role: 'auditor' } })
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([component('gateway-core')]))
    renderPage()
    await screen.findByRole('heading', { name: text.gateway })
    expect(screen.queryByRole('link', { name: text.modelQuality })).not.toBeInTheDocument()
  })

  it('opens request audit evidence rather than administrator operation logs', async () => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([component('audit-pipeline', 'healthy', { requests_24h: 7, pending_24h: 0 })]))
    renderPage()
    const audit = await screen.findByRole('region', { name: text.audit })
    expect(within(audit).getByRole('link', { name: text.requests })).toHaveAttribute('href', '/audit/access-retention?view=requests')
  })

  it('distinguishes judge availability from report freshness', async () => {
    const user = userEvent.setup()
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([component('judge', 'degraded', { runtime_fresh: true, judge_operational: false })]))
    renderPage()
    const judge = await screen.findByRole('region', { name: text.judge })
    await user.click(within(judge).getByText(text.diagnostics))
    expect(within(judge).getByText(text.judgeAvailable)).toBeInTheDocument()
    expect(within(judge).getByText(text.reportFresh)).toBeInTheDocument()
    expect(within(judge).queryByText(text.reportAvailable)).not.toBeInTheDocument()
  })

  it.each([
    ['error', 'ok', text.databaseFailed], ['ok', 'error', text.cacheFailed],
  ])('identifies the failed management dependency (%s/%s)', async (database, redis, explanation) => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([component('control-plane', 'degraded', { database, redis })]))
    renderPage()
    const control = await screen.findByRole('region', { name: text.control })
    expect(within(control).getByText(explanation)).toBeInTheDocument()
  })

  it('explains an aged audit backlog as pending writes rather than a generic fault', async () => {
    vi.spyOn(serviceHealthApi, 'readModel').mockResolvedValue(response([component('audit-pipeline', 'degraded', { requests_24h: 7, pending_24h: 2, oldest_pending_age_seconds: 4000, processing_threshold_seconds: 3600 })]))
    renderPage()
    const audit = await screen.findByRole('region', { name: text.audit })
    expect(within(audit).getByText(text.auditStale)).toBeInTheDocument()
  })
})
