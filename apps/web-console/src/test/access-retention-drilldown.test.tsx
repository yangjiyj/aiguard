import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import AccessRetention from '../pages/AccessRetention'
import * as api from '../services/api'

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      warning: vi.fn(),
      error: vi.fn(),
    },
  }
})
function LocationProbe() {
  const location = useLocation()
  return <output data-testid="retention-location">{location.pathname}{location.search}</output>
}

const summary = {
  total: 2,
  normal_count: 1,
  risk_count: 1,
  blocked_count: 0,
  llm_count: 2,
  ai_ide_count: 0,
  normal_public_count: 0,
  retained_content_count: 2,
  forward_count: 0,
  reverse_count: 0,
  device_count: 0,
  agent_request_count: 0,
  identified_agent_count: 0,
  unidentified_agent_count: 0,
  unique_model_count: 1,
  evidence_quality: {
    complete_count: 1,
    request_only_count: 1,
    response_only_count: 0,
    metadata_only_count: 0,
  },
  timeline: [],
  top_risk_categories: [],
  top_providers: [],
  top_targets: [],
  top_agents: [],
}

const records = [
  {
    request_id: 'req/risk &1',
    created_at: '2026-08-07T09:30:00Z',
    source_ip: '10.10.10.8',
    target_host: 'api.example.com',
    target_path: '/v1/chat/completions',
    method: 'POST',
    provider: 'example',
    provider_cn: 'Example',
    product: 'example_api',
    product_cn: 'Example API',
    access_type: 'llm',
    endpoint_kind: 'api',
    path_template: '/v1/chat/completions',
    status: 'success',
    status_code: 200,
    response_bytes: 4096,
    tls_inspected: true,
    retention_level: 'content',
    content_retained: true,
    risk_state: 'risk',
    risk_reasons: ['bank_card_cn'],
    action_taken: 'audit',
    security_event_count: 1,
  },
  {
    request_id: 'req_normal_001',
    created_at: '2026-08-07T09:31:00Z',
    source_ip: '10.10.10.9',
    target_host: 'api.example.com',
    target_path: '/v1/chat/completions',
    method: 'POST',
    provider: 'example',
    provider_cn: 'Example',
    product: 'example_api',
    product_cn: 'Example API',
    access_type: 'llm',
    endpoint_kind: 'api',
    path_template: '/v1/chat/completions',
    status: 'success',
    status_code: 200,
    response_bytes: 4096,
    tls_inspected: true,
    retention_level: 'content',
    content_retained: true,
    risk_state: 'normal',
    action_taken: 'allow',
    security_event_count: 0,
  },
]

describe('AccessRetention drilldowns', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
    vi.spyOn(api.llmProviderCatalogApi, 'list').mockResolvedValue({
      data: { data: [], providers: [] },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: records, total: records.length, summary },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [], total: 0 },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: { summary },
    } as any)
  })

  const renderPage = (initialPath: string) => render(
    <MemoryRouter initialEntries={[initialPath]}>
      <QueryClientProvider client={queryClient}>
        <AccessRetention />
      </QueryClientProvider>
      <LocationProbe />
    </MemoryRouter>,
  )

  it('filters attention in one click and preserves the filter in the URL', async () => {
    const user = userEvent.setup()
    const list = api.accessRetentionApi.list as ReturnType<typeof vi.fn>
    renderPage('/')

    await user.click(await screen.findByRole('button', { name: '筛选需关注留证记录' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ risk_state: 'attention' })))
    const params = new URLSearchParams(screen.getByTestId('retention-location').textContent?.split('?')[1] || '')
    expect(params.get('risk_state')).toBe('attention')
    expect(params.get('view')).toBe('requests')
    expect(params.get('tab')).toBe('details')
  })

  it('restores an attention filter from a shared URL', async () => {
    const list = api.accessRetentionApi.list as ReturnType<typeof vi.fn>
    renderPage('/?view=requests&risk_state=attention')

    await waitFor(() => expect(list).toHaveBeenCalledWith(expect.objectContaining({ risk_state: 'attention' })))
  })

  it('only exposes an alert link for a non-normal retained record', async () => {
    const user = userEvent.setup()
    renderPage('/?view=requests')

    const alertButton = await screen.findByRole('button', { name: '查看告警' })
    expect(screen.getAllByRole('button', { name: '查看告警' })).toHaveLength(1)
    await user.click(alertButton)

    const params = new URLSearchParams(screen.getByTestId('retention-location').textContent?.split('?')[1] || '')
    expect(screen.getByTestId('retention-location')).toHaveTextContent('/security/alerts?')
    expect(params.get('request_id')).toBe('req/risk &1')
  })
})
