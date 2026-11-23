import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import SecurityOperationsOverview from '../pages/SecurityOperationsOverview'
import * as api from '../services/api'
import { alertOccurrencesApi } from '../services/alertOccurrences'
import { agentEndpointApi } from '../services/agentEndpoint'

// 客户现场回归：网关版默认不开「智能体端点」功能（AGENT_ENDPOINT_ENABLED 为空，接口 404），
// 合规总览却始终请求 /agent/overview 并显示一整块灰卡和「智能体端点统计暂不可用」，像系统坏了。
// 未授权 agent_security 或后端未开启该功能（404）时整块不显示；只有真正出错才提示。
describe('SecurityOperationsOverview 智能体端点安全卡片', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.restoreAllMocks()
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({ data: { timezone: 'Asia/Shanghai' } } as any)
    vi.spyOn(alertOccurrencesApi, 'summary').mockResolvedValue({ data: { count_unit: 'triage_cases', total: 0, categories: [] } } as any)
    vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({ data: { data: { total: 1, subjects: 1, category_count: 1, severity: [], categories: [] } } } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({ data: { summary: { total: 1 } } } as any)
  })
  const renderPage = () => render(<QueryClientProvider client={queryClient}><MemoryRouter><SecurityOperationsOverview /></MemoryRouter></QueryClientProvider>)

  it('未授权 agent_security 时不显示卡片，也不请求端点接口', async () => {
    vi.spyOn(api.licenseApi, 'status').mockResolvedValue({ data: { valid: true, features: ['agent_audit'] } } as any)
    const overview = vi.spyOn(agentEndpointApi, 'overview')
    renderPage()
    await waitFor(() => expect(screen.getByText('涉及主体')).toBeTruthy())
    await waitFor(() => expect(api.licenseApi.status).toHaveBeenCalled())
    expect(screen.queryByText('智能体端点安全')).toBeNull()
    expect(screen.queryByText(/智能体端点统计暂不可用/)).toBeNull()
    expect(overview).not.toHaveBeenCalled()
  })

  it('已授权但后端未开启端点功能（404）时不显示卡片', async () => {
    vi.spyOn(api.licenseApi, 'status').mockResolvedValue({ data: { valid: true, features: ['agent_security'] } } as any)
    vi.spyOn(agentEndpointApi, 'overview').mockRejectedValue({ response: { status: 404 } })
    renderPage()
    await waitFor(() => expect(agentEndpointApi.overview).toHaveBeenCalled())
    await waitFor(() => expect(screen.queryByText('智能体端点安全')).toBeNull())
    expect(screen.queryByText(/智能体端点统计暂不可用/)).toBeNull()
  })

  it('已授权且接口真正出错时显示卡片和错误提示', async () => {
    vi.spyOn(api.licenseApi, 'status').mockResolvedValue({ data: { valid: true, features: ['agent_security'] } } as any)
    vi.spyOn(agentEndpointApi, 'overview').mockRejectedValue({ response: { status: 500 } })
    renderPage()
    expect(await screen.findByText(/智能体端点统计暂不可用/)).toBeTruthy()
    expect(screen.getByText('智能体端点安全')).toBeTruthy()
  })

  it('已授权且接口正常时显示数据', async () => {
    vi.spyOn(api.licenseApi, 'status').mockResolvedValue({ data: { valid: true, features: ['agent_security'] } } as any)
    vi.spyOn(agentEndpointApi, 'overview').mockResolvedValue({ endpoints_total: 7, endpoints_active: 5, endpoints_stale: 2, sessions_active: 3, events_24h: 9, assets_present: 4 } as any)
    renderPage()
    expect(await screen.findByText('智能体端点安全')).toBeTruthy()
    expect(screen.queryByText(/智能体端点统计暂不可用/)).toBeNull()
  })
})
