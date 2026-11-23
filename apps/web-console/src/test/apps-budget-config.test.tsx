import appsSource from '../pages/Apps.tsx?raw'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Apps from '../pages/Apps'
import * as api from '../services/api'

const walletLinkLabel = appsSource.match(/href=\{'\/cost\/budgets[^>]+>\s*([^<]+)\s*<\/Button>/)?.[1].trim()
if (!walletLinkLabel) throw new Error('Production wallet link label not found')

describe('Apps budget and quota configuration', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: { data: [{ id: 'proj_001', name: '客服助手', code: 'support', status: 'active', environment: 'production' }] } } as any)
    vi.spyOn(api.projectApi, 'get').mockResolvedValue({ data: { data: { id: 'proj_001', name: '客服助手', model_whitelist: [], quota_limits: {} } } } as any)
    vi.spyOn(api.projectApi, 'listUsers').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.projectApi, 'updateModelConfig').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.modelApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.policyApi, 'getQuota').mockResolvedValue({ data: { project_id: 'proj_001', daily_token_limit: 1000, monthly_token_limit: 30000, monthly_budget_limit: 200, rpm_limit: 60, tpm_limit: 12000, concurrency_limit: 5, overage_action: 'rate_limit' } } as any)
    vi.spyOn(api.policyApi, 'setQuota').mockResolvedValue({ data: {} } as any)
  })

  const renderApps = (initialEntries = ['/apps']) => render(
    <MemoryRouter initialEntries={initialEntries}>
      <QueryClientProvider client={queryClient}>
        <Apps />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('uses the customer-facing 应用管理 title', async () => {
    renderApps()

    expect(await screen.findByText('应用管理')).toBeInTheDocument()
    expect(screen.queryByText('应用接入')).not.toBeInTheDocument()
  })

  it('links to the single project quota editor without duplicating quota fields', async () => {
    renderApps()

    fireEvent.click(await screen.findByText('客服助手'))
    const quotaLinkText = await screen.findByText(walletLinkLabel)
    expect(quotaLinkText.closest('a')).toHaveAttribute('href', '/cost/budgets?scope_type=project&scope_id=proj_001')
    expect(screen.queryByText('月费用预算（元）')).not.toBeInTheDocument()
    expect(screen.queryByText('超额处理动作')).not.toBeInTheDocument()
    expect(screen.getByText('模型白名单')).toBeInTheDocument()
    expect(screen.getAllByText('所属部门').length).toBeGreaterThan(0)
    expect(api.policyApi.getQuota).not.toHaveBeenCalled()
    expect(api.policyApi.setQuota).not.toHaveBeenCalled()
  }, 20000)

  it('opens the project drawer from project_id URL parameters', async () => {
    renderApps(['/apps?project_id=proj_001'])

    expect((await screen.findByText(walletLinkLabel)).closest('a')).toHaveAttribute(
      'href',
      '/cost/budgets?scope_type=project&scope_id=proj_001',
    )
    await waitFor(() => expect(api.projectApi.get).toHaveBeenCalledWith('proj_001'))
  })
})
