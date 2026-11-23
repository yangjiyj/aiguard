import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ModelManagement from '../pages/ModelManagement'
import * as api from '../services/api'

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return { ...actual, message: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }
})

const ok = (body: any) => ({ data: body, status: 200, statusText: 'OK', headers: {}, config: {} } as any)

describe('ModelManagement 已移除非核心列', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.fxApi, 'current').mockResolvedValue(ok({ data: { rate: 7.24 } }))
    vi.spyOn(api.providerApi, 'list').mockResolvedValue(ok({
      data: [{ id: 'prov_1', name: 'P', provider_type: 'openai', base_url: 'x', has_credential: true, status: 'active', callable: true, availability_state: 'callable' }],
    }))
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <ModelManagement />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  it('移除上游模型 ID 和测评状态列，且不请求测评状态', async () => {
    const evalStatus = vi.spyOn(api.modelApi, 'evalStatus').mockResolvedValue(ok({
      data: [{
        model_id: 'model_a',
        status: 'high_risk',
        has_high_risk: true,
        report_url: 'https://lse.example.com/report',
      }],
    }))
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({
      data: [{
        id: 'model_a',
        provider_id: 'prov_1',
        model_name: 'gpt-x',
        upstream_model_id: 'provider-gpt-x',
        status: 'active', callable: true, availability_state: 'callable',
        pricing_json: { input: 1, output: 2 },
      }],
    }))

    renderPage()

    expect((await screen.findAllByText('gpt-x')).length).toBeGreaterThan(0)
    expect(screen.queryAllByText('上游模型ID')).toHaveLength(0)
    expect(screen.queryAllByText('测评状态')).toHaveLength(0)
    expect(screen.queryAllByText('provider-gpt-x')).toHaveLength(0)
    expect(screen.queryAllByText('有高危发现')).toHaveLength(0)
    expect(screen.queryAllByText('查看报告')).toHaveLength(0)
    expect(evalStatus).not.toHaveBeenCalled()
  })
})
