import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import McpRedlineSettings from '../pages/McpRedlineSettings'
import { REDLINE_LABELS } from '../pages/McpRedlineLabels'

const mocks = vi.hoisted(() => ({
  list: vi.fn(),
  update: vi.fn(),
  success: vi.fn(),
  error: vi.fn(),
}))

// 2.9.22 起红线可加例外，组件会读智能体工具例外计数；这里保留真实模块，只替换红线与例外接口。
vi.mock('../services/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../services/api')>()),
  mcpRedlineApi: { list: mocks.list, update: mocks.update },
  agentGuardApi: { listExceptions: vi.fn().mockResolvedValue({ data: { data: [] } }), createException: vi.fn() },
}))

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: mocks.success, error: mocks.error } }
})

function renderPanel(canEdit = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <McpRedlineSettings canEdit={canEdit} />
    </QueryClientProvider>,
  )
}

describe('MCP redline settings (W1 1.11)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.list.mockResolvedValue({
      data: { items: [
        { rule_name: 'cloud_metadata', action: 'alert' },
        { rule_name: 'reverse_shell', action: 'block' },
      ] },
    })
    mocks.update.mockResolvedValue({ data: { items: [] } })
  })

  it('shows every rule with its current action and block count', async () => {
    renderPanel()
    expect(await screen.findByText(REDLINE_LABELS.cloud_metadata.title)).toBeInTheDocument()
    expect(screen.getByText(REDLINE_LABELS.reverse_shell.title)).toBeInTheDocument()
    expect(screen.getByText('阻断 1 / 2')).toBeInTheDocument()
  })

  it('sends only the changed rule when switching to block', async () => {
    renderPanel()
    await screen.findByText(REDLINE_LABELS.cloud_metadata.title)
    const select = screen.getAllByRole('combobox')[0]
    fireEvent.mouseDown(select)
    const options = await screen.findAllByText('阻断')
    fireEvent.click(options[options.length - 1])
    await waitFor(() => expect(mocks.update).toHaveBeenCalledWith({ cloud_metadata: 'block' }))
    await waitFor(() => expect(mocks.success).toHaveBeenCalled())
  })

  it('disables editing for read-only members', async () => {
    renderPanel(false)
    await screen.findByText(REDLINE_LABELS.cloud_metadata.title)
    const combos = screen.getAllByRole('combobox')
    combos.forEach((combo) => expect(combo).toBeDisabled())
  })
})
