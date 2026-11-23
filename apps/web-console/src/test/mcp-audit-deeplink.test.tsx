import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import McpAudit from '../pages/McpAudit'

const api = vi.hoisted(() => ({
  listAudit: vi.fn(),
  listServers: vi.fn(),
}))

vi.mock('../services/api', () => ({
  mcpAuditApi: { list: api.listAudit },
  mcpServerApi: { list: api.listServers },
}))

describe('MCP audit approval deep link', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.listServers.mockResolvedValue({ data: { servers: [] } })
    api.listAudit.mockResolvedValue({
      data: {
        data: [{
          id: 'tc-confirmed',
          request_id: 'req_mcp_confirmation_1',
          session_id: 'agent-session',
          tenant_id: 'tenant_default',
          user_id: 'admin',
          tool_name: 'demo__read_report',
          tool_type: 'mcp',
          risk_level: 'medium',
          parameters: { path: '/safe/report.txt' },
          result: 'result observed',
          status: 'success',
          raw_decision: 'confirm',
          effective_decision: 'allow',
          mode: 'strict',
          effective_reason: 'human_confirmation_approved_once',
          event_kind: 'execution_forwarded',
          execution_observed: true,
          result_observed: true,
          created_at: '2026-07-11T10:00:00Z',
        }],
        total: 1,
      },
    })
  })

  it('sends request_id to the server and opens the exact audit record', async () => {
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/mcp-gateway/audit?request_id=req_mcp_confirmation_1']}>
          <Routes>
            <Route path="/mcp-gateway/audit" element={<McpAudit />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(await screen.findByRole('heading', { name: 'MCP \u8c03\u7528\u5ba1\u8ba1' })).toBeInTheDocument()
    await waitFor(() => expect(api.listAudit).toHaveBeenCalled())
    const params = api.listAudit.mock.calls[0][0]
    expect(params.request_id).toBe('req_mcp_confirmation_1')
    expect(await screen.findByText('MCP 调用详情')).toBeInTheDocument()
    expect(screen.getAllByText('req_mcp_confirmation_1').length).toBeGreaterThan(0)
  })
})
