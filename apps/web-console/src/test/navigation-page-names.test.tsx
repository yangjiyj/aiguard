import type { ReactElement } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import McpPolicies from '../pages/McpPolicies'
import { UsageTab } from '../components/team-tabs/UsageTab'
import apiClient, { mcpPolicyApi, mcpServerApi, orgApi } from '../services/api'

vi.mock('../pages/McpRedlineSettings', () => ({ default: () => null }))

function renderPage(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>)
}

describe('approved navigation page names', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('uses the MCP policy name in both its page and creation dialog', async () => {
    vi.spyOn(mcpPolicyApi, 'list').mockResolvedValue({ data: { data: [] } } as never)
    vi.spyOn(mcpPolicyApi, 'shadowCheck').mockResolvedValue({ data: { warnings: [] } } as never)
    vi.spyOn(mcpServerApi, 'list').mockResolvedValue({ data: { servers: [] } } as never)
    vi.spyOn(apiClient, 'get').mockResolvedValue({ data: {} } as never)
    renderPage(<McpPolicies />)
    expect(await screen.findByRole('heading', { name: 'MCP \u8c03\u7528\u7b56\u7565' })).toBeInTheDocument()
    await userEvent.click(screen.getAllByRole('button', { name: /\u65b0\u5efa\u7b56\u7565$/ })[0])
    expect(within(await screen.findByRole('dialog')).getByText('\u65b0\u5efa MCP \u8c03\u7528\u7b56\u7565')).toBeInTheDocument()
  })

  it('names department usage by its business scope and preserves the data request', async () => {
    const getUsage = vi.spyOn(orgApi, 'getUsage').mockResolvedValue({ data: {} } as never)
    renderPage(<UsageTab teamId="team/scoped" />)
    expect(await screen.findByText('\u90e8\u95e8\u7528\u91cf')).toBeInTheDocument()
    expect(getUsage).toHaveBeenCalledWith('team/scoped', '30d')
  })
})
