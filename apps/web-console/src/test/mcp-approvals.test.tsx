import type { ReactElement } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import McpApprovals from '../pages/McpApprovals'

const mocks = vi.hoisted(() => ({
  settingsGet: vi.fn(),
  listConfirmations: vi.fn(),
  resolveConfirmation: vi.fn(),
  listExceptions: vi.fn(),
  createException: vi.fn(),
  deleteException: vi.fn(),
  success: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
  error: vi.fn(),
}))

vi.mock('../services/api', () => ({
  default: { get: mocks.settingsGet },
  mcpApprovalApi: {
    list: mocks.listConfirmations,
    resolve: mocks.resolveConfirmation,
  },
  agentGuardApi: {
    listExceptions: mocks.listExceptions,
    createException: mocks.createException,
    deleteException: mocks.deleteException,
  },
}))

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return {
    ...actual,
    message: {
      success: mocks.success,
      info: mocks.info,
      warning: mocks.warning,
      error: mocks.error,
    },
  }
})

const executedRecord = {
  id: 'agcf-executed',
  request_id: 'req-original',
  trace_id: 'trace-1',
  tool_name: 'demo__read_report',
  raw_decision: 'confirm',
  effective_decision: 'confirm',
  status: 'approved',
  timeout_action: 'block',
  reason: 'policy_requires_confirmation',
  source: 'mcp',
  expires_at: '2026-07-11T10:10:00Z',
  created_at: '2026-07-11T10:00:00Z',
  mcp_execution: {
    confirmation_id: 'agcf-executed',
    execution_status: 'executed',
    evidence_status: 'complete',
    audit_request_id: 'req_mcp_confirmation_1',
    result_available: true,
  },
}

const pendingRecord = {
  ...executedRecord,
  id: 'agcf-pending',
  status: 'pending',
  mcp_execution: {
    confirmation_id: 'agcf-pending',
    execution_status: 'pending',
    evidence_status: 'pending',
  },
}

function LocationProbe() {
  const location = useLocation()
  return <div data-testid="location">{location.pathname + location.search}</div>
}

function renderPage(ui: ReactElement = <McpApprovals />) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/mcp-gateway/approvals']}>
        <Routes>
          <Route path="/mcp-gateway/approvals" element={<>{ui}<LocationProbe /></>} />
          <Route path="/mcp-gateway/audit" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('MCP approval execution truth', () => {
  it('uses the approved MCP-specific approval page name', async () => {
    renderPage()
    expect(await screen.findByRole('heading', { name: 'MCP \u5ba1\u6279\u4e0e\u4f8b\u5916' })).toBeInTheDocument()
  })

  beforeEach(() => {
    vi.clearAllMocks()
    mocks.settingsGet.mockResolvedValue({ data: { security_execution_mode: { configured_mode: 'protect', effective_mode: 'protect', locked: false, source: 'admin_settings', runtime_verified: true, runtime_status: 'verified' } } })
    mocks.listExceptions.mockResolvedValue({ data: { data: [] } })
    mocks.listConfirmations.mockResolvedValue({ data: { data: [executedRecord] } })
  })

  it('loads approval history by default and links only complete execution evidence', async () => {
    renderPage()

    expect(await screen.findByText('已执行 · 结果可取 · 留证完成')).toBeInTheDocument()
    expect(mocks.listConfirmations).toHaveBeenCalledWith({ source: 'mcp' })
    await userEvent.click(screen.getByRole('button', { name: '查看执行审计' }))
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/mcp-gateway/audit?request_id=req_mcp_confirmation_1',
    )
  })

  it('does not report approval HTTP success as execution success when evidence failed', async () => {
    mocks.listConfirmations.mockResolvedValue({ data: { data: [pendingRecord] } })
    mocks.resolveConfirmation.mockResolvedValue({
      data: {
        ...pendingRecord,
        status: 'approved',
        mcp_execution: {
          confirmation_id: pendingRecord.id,
          execution_status: 'executed',
          evidence_status: 'failed',
          audit_error_code: 'tool_log_persist_failed',
        },
      },
    })
    renderPage()

    expect(await screen.findByText('等待执行')).toBeInTheDocument()
    const openApproval = await screen.findByText('批准', { selector: 'button span' })
    await userEvent.click(openApproval.closest('button')!)
    const confirmApproval = await screen.findByText('批准本次 MCP 工具调用?')
    await userEvent.click(confirmApproval.closest('.ant-popover')!.querySelector('.ant-btn-primary')!)

    await waitFor(() => expect(mocks.resolveConfirmation).toHaveBeenCalledTimes(1))
    expect(mocks.warning).toHaveBeenCalledWith('MCP 工具已执行，但留证失败；请立即核查')
    expect(mocks.success).not.toHaveBeenCalledWith('确认请求已处理')
  })

  it('makes unknown terminal state explicit and never offers an audit link without complete evidence', async () => {
    mocks.listConfirmations.mockResolvedValue({
      data: {
        data: [{
          ...executedRecord,
          id: 'agcf-unknown',
          mcp_execution: {
            confirmation_id: 'agcf-unknown',
            execution_status: 'unknown',
            evidence_status: 'failed',
            error_code: 'upstream_outcome_unknown',
          },
        }],
      },
    })
    renderPage()

    expect(await screen.findByText('结果不确定 · 禁止自动重试')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '查看执行审计' })).not.toBeInTheDocument()
  })
})
