import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AgentGuard from '../pages/AgentGuard'
import { agentGuardApi } from '../services/api'

// Labels were extracted from the existing component and checked by code point.
const labels = {
  add: '\u65b0\u589e\u653e\u884c',
  save: '\u521b\u5efa\u4f8b\u5916',
  reason: '\u5ba1\u6279\u539f\u56e0',
  rule: '\u5173\u8054\u89c4\u5219',
}

function LocationProbe() {
  return <div data-testid="search">{useLocation().search}</div>
}

describe('controlled exception rule scope', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(agentGuardApi, 'listExceptions').mockResolvedValue({ data: { data: [] } } as never)
    vi.spyOn(agentGuardApi, 'listConfirmations').mockResolvedValue({ data: { data: [] } } as never)
    vi.spyOn(agentGuardApi, 'createException').mockResolvedValue({ data: { id: 'exception-valid' } } as never)
  })

  function renderPage() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    return render(<QueryClientProvider client={queryClient}><MemoryRouter><AgentGuard /></MemoryRouter></QueryClientProvider>)
  }

  for (const invalid of ['', ' \t ']) {
    it(`rejects blank rule before saving ${JSON.stringify(invalid)}`, async () => {
      const user = userEvent.setup()
      renderPage()
      await user.click(screen.getByRole('button', { name: labels.add }))
      await user.type(screen.getByLabelText(labels.reason), 'Approved partner upload')
      if (invalid) await user.type(screen.getByLabelText(labels.rule), invalid)
      await user.click(screen.getByRole('button', { name: labels.save }))
      // 报错改为中文。
      expect(await screen.findByText('请输入关联规则')).toBeInTheDocument()
      expect(agentGuardApi.createException).not.toHaveBeenCalled()
    })
  }

  it('saves a concrete rule with the controlled exception', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('button', { name: labels.add }))
    await user.type(screen.getByLabelText(labels.reason), 'Approved partner upload')
    await user.type(screen.getByLabelText(labels.rule), 'secret_high_confidence')
    // 非全租户范围时“具体对象”必填（新建默认范围是指定应用）。
    await user.type(screen.getByLabelText('具体对象'), 'project-1')
    await user.click(screen.getByRole('button', { name: labels.save }))
    await waitFor(() => expect(agentGuardApi.createException).toHaveBeenCalledWith(expect.objectContaining({ rule_id: 'secret_high_confidence', reason: 'Approved partner upload', scope_ref: 'project-1' })))
  })

  it('非全租户范围不填具体对象时不保存', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('button', { name: labels.add }))
    await user.type(screen.getByLabelText(labels.reason), 'Approved partner upload')
    await user.type(screen.getByLabelText(labels.rule), 'secret_high_confidence')
    await user.click(screen.getByRole('button', { name: labels.save }))
    expect(await screen.findByText('请输入具体对象')).toBeInTheDocument()
    expect(agentGuardApi.createException).not.toHaveBeenCalled()
  })

  it('从阻断记录跳来时预填放行例外，并从地址栏去掉预填参数', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/security/agents/advanced?tab=exceptions&rule=blocked_loopback_or_private_ip&target=mcp__devhub__get_mr']}><AgentGuard /><LocationProbe /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByLabelText(labels.rule)).toHaveValue('blocked_loopback_or_private_ip')
    expect(screen.getByLabelText('目标匹配')).toHaveValue('mcp__devhub__get_mr')
    expect(screen.getByText('全租户')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('search')).toHaveTextContent('?tab=exceptions'))
    expect(screen.getByTestId('search').textContent).not.toMatch(/rule=|target=/)
  })
})
