import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import McpAudit from '../pages/McpAudit'
import { formatAgentType } from '../utils/agents'

const api = vi.hoisted(() => ({
  listAudit: vi.fn(),
  listServers: vi.fn(),
}))

vi.mock('../services/api', () => ({
  mcpAuditApi: { list: api.listAudit },
  mcpServerApi: { list: api.listServers },
}))

describe('MCP audit agent column', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.listServers.mockResolvedValue({ data: { servers: [] } })
    api.listAudit.mockResolvedValue({
      data: {
        data: [{
          id: 'tc-agent-label',
          request_id: 'req_mcp_agent_label',
          session_id: 'agent-session',
          tenant_id: 'tenant_default',
          user_id: 'admin',
          tool_name: 'demo__read_report',
          tool_type: 'mcp',
          agent_type: 'workbuddy',
          risk_level: 'medium',
          parameters: {},
          result: 'ok',
          status: 'success',
          raw_decision: 'allow',
          effective_decision: 'allow',
          mode: 'strict',
          created_at: '2026-07-11T10:00:00Z',
        }],
        total: 1,
      },
    })
  })

  it('renders the registry label instead of the raw agent_type value', async () => {
    const label = formatAgentType('workbuddy')
    expect(label).not.toBe('workbuddy')
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter initialEntries={['/mcp-gateway/audit']}>
          <Routes>
            <Route path="/mcp-gateway/audit" element={<McpAudit />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )
    await waitFor(() => expect(api.listAudit).toHaveBeenCalled())
    expect((await screen.findAllByText(label)).length).toBeGreaterThan(0)
    expect(screen.queryByText('workbuddy')).not.toBeInTheDocument()
  })
})
