import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import PlatformDashboard from '../pages/PlatformDashboard'
import { licenseApi, productApi, statsApi } from '../services/api'
import { agentEndpointApi } from '../services/agentEndpoint'

const renderDashboard = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><PlatformDashboard product={{ profile: 'agent-platform', name: 'JJDGuard Agent Platform' }} /></MemoryRouter></QueryClientProvider>)

beforeEach(() => {
  vi.restoreAllMocks()
  vi.spyOn(productApi, 'get').mockResolvedValue({ data: { product_profile: 'agent-platform', product_name: 'JJDGuard Agent Platform' } } as any)
  vi.spyOn(licenseApi, 'status').mockResolvedValue({ data: { valid: false, features: [] } } as any)
  vi.spyOn(agentEndpointApi, 'overview').mockResolvedValue({ endpoints_total: 3, endpoints_active: 2, endpoints_stale: 1, sessions_active: 1, events_24h: 8, assets_present: 2, endpoints_revoked: 0 })
  vi.spyOn(agentEndpointApi, 'sessions').mockResolvedValue({ items: [{ blocked_count: 2, would_block_count: 1 }], total: 1, page: 1, page_size: 200 } as any)
  vi.spyOn(agentEndpointApi, 'todayEvents').mockResolvedValue({ items: [], total: 7, page: 1, page_size: 1 })
  vi.spyOn(agentEndpointApi, 'endpoints').mockImplementation(async params => ({ items: params.page_size === 1 ? [] : [{ id: 'ep-1', hostname: 'host-1', product: 'claude-code', last_policy_version: 4, health: { queue_events: 2, dropped_events: 0 } }], total: params.page_size === 1 ? (params.product === 'claude-code' ? 1 : 0) : 1, page: 1, page_size: params.page_size ?? 200 } as any))
  vi.spyOn(agentEndpointApi, 'currentPolicyBundle').mockResolvedValue({ id: 'bundle-4', version: 4, checksum: 'sum', created_by: 'admin', created_at: '2026-09-23T00:00:00Z' })
  vi.spyOn(statsApi, 'getOverview').mockResolvedValue({ data: {} } as any)
})

describe('平台首页', () => {
  it('无授权仅显示占位，不请求任意端侧接口或网关统计', async () => {
    renderDashboard()
    expect(await screen.findByText('当前未授权 agent_security；端侧态势暂不可用')).toBeInTheDocument()
    expect(screen.getByText('最近 10 条端侧告警')).toBeInTheDocument()
    expect(agentEndpointApi.overview).not.toHaveBeenCalled()
    expect(agentEndpointApi.sessions).not.toHaveBeenCalled()
    expect(agentEndpointApi.todayEvents).not.toHaveBeenCalled()
    expect(agentEndpointApi.endpoints).not.toHaveBeenCalled()
    expect(agentEndpointApi.currentPolicyBundle).not.toHaveBeenCalled()
    expect(statsApi.getOverview).not.toHaveBeenCalled()
  })

  it('已授权使用真实端侧数据，告警及风险排序标注缺口', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: { valid: true, features: ['agent_security'] } } as any)
    renderDashboard()
    await waitFor(() => expect(screen.getByText(/版本 4 · 发布于/)).toBeInTheDocument())
    expect(screen.getByText('今日端侧事件')).toBeInTheDocument()
    expect(screen.getByText('今日新会话累计阻断')).toBeInTheDocument()
    expect(screen.getByText('今日新会话累计收敛')).toBeInTheDocument()
    expect(screen.getByText('Top 风险端点')).toBeInTheDocument()
    expect(screen.getByText('暂不可用；请从关联会话查看告警。')).toBeInTheDocument()
    expect(agentEndpointApi.todayEvents).toHaveBeenCalledWith(expect.any(String), expect.any(String))
    expect(statsApi.getOverview).not.toHaveBeenCalled()
  })

  it('今日会话超过接口单页上限时不冒充全量阻断数', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: { valid: true, features: ['agent_security'] } } as any)
    vi.mocked(agentEndpointApi.sessions).mockResolvedValue({ items: [{ blocked_count: 2, would_block_count: 1 }], total: 201, page: 1, page_size: 200 } as any)
    renderDashboard()
    expect((await screen.findAllByText('超过 200 条会话，无法准确汇总')).length).toBe(2)
  })
})
