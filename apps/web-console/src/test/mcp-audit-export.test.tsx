import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import McpAudit from '../pages/McpAudit'

// W1 1.13：导出按钮走服务端全量导出，透传当前筛选（去掉分页），支持 csv / xlsx。
const api = vi.hoisted(() => ({
  listAudit: vi.fn(),
  listServers: vi.fn(),
  exportAudit: vi.fn(),
}))

vi.mock('../services/api', () => ({
  mcpAuditApi: { list: api.listAudit },
  mcpAuditExportApi: { export: api.exportAudit },
  mcpServerApi: { list: api.listServers },
}))

const renderPage = (entry = '/mcp-gateway/audit') => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/mcp-gateway/audit" element={<McpAudit />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('MCP audit server-side export', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.listServers.mockResolvedValue({ data: { servers: [] } })
    api.listAudit.mockResolvedValue({
      data: {
        data: [{ id: 'tc-1', request_id: 'req-1', tool_name: 'fs__read', tool_type: 'mcp', created_at: '2026-07-11T10:00:00Z' }],
        total: 230,
      },
    })
    api.exportAudit.mockResolvedValue({ data: new Blob(['x']), headers: { 'x-export-row-count': '230', 'x-export-truncated': 'false' } })
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn(() => 'blob:mock') })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })

  it('exports csv through the server with current filters and without paging params', async () => {
    renderPage('/mcp-gateway/audit?request_id=req-1')
    await waitFor(() => expect(api.listAudit).toHaveBeenCalled())
    fireEvent.click(await screen.findByRole('button', { name: /CSV/ }))
    await waitFor(() => expect(api.exportAudit).toHaveBeenCalledTimes(1))
    const [format, params] = api.exportAudit.mock.calls[0]
    expect(format).toBe('csv')
    expect(params.request_id).toBe('req-1')
    expect(params.from).toBeTruthy()
    expect(params.to).toBeTruthy()
    expect(params).not.toHaveProperty('limit')
    expect(params).not.toHaveProperty('offset')
  })

  it('exports xlsx through the server', async () => {
    renderPage()
    await waitFor(() => expect(api.listAudit).toHaveBeenCalled())
    fireEvent.click(await screen.findByRole('button', { name: /XLSX/ }))
    await waitFor(() => expect(api.exportAudit).toHaveBeenCalledTimes(1))
    expect(api.exportAudit.mock.calls[0][0]).toBe('xlsx')
  })

  it('does not call the server when there is nothing to export', async () => {
    api.listAudit.mockResolvedValue({ data: { data: [], total: 0 } })
    renderPage()
    await waitFor(() => expect(api.listAudit).toHaveBeenCalled())
    fireEvent.click(await screen.findByRole('button', { name: /CSV/ }))
    await new Promise((r) => setTimeout(r, 20))
    expect(api.exportAudit).not.toHaveBeenCalled()
  })
})
