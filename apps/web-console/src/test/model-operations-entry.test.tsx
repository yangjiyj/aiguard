import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import ModelManagement from '../pages/ModelManagement'
import Providers from '../pages/Providers'

const http = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn(), interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } }))
vi.mock('axios', () => ({ default: { create: () => http } }))
const config = { version: 1, enabled: false, interval_seconds: 300, concurrency: 2, timeout_seconds: 15, max_targets: 50, max_output_tokens: 128, protocols: ['chat', 'responses', 'messages'], failure_threshold: 3 }
const providers = [{ id: 'p1', name: '渠道 A', provider_type: 'anthropic', status: 'active', has_credential: true }, { id: 'p2', name: '渠道 B', provider_type: 'openai', status: 'active', has_credential: true }]
const models = [{ id: 'm1', provider_id: 'p1', model_name: 'claude-test', status: 'active', callable: true, availability_state: 'callable', protocols: ['anthropic_messages'] }, { id: 'm2', provider_id: 'p1', model_name: 'chat-test', status: 'active', callable: true, availability_state: 'callable' }, { id: 'm3', provider_id: 'p2', model_name: 'retained-model', status: 'disabled' }]
const Location = () => { const location = useLocation(); return <output data-testid="location">{location.pathname}{location.search}</output> }
let client: QueryClient
const renderPage = (page: React.ReactNode, path: string) => render(<MemoryRouter initialEntries={[path]}><QueryClientProvider client={client}>{page}<Location /></QueryClientProvider></MemoryRouter>)
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  vi.clearAllMocks(); sessionStorage.clear()
  http.get.mockImplementation((url: string) => Promise.resolve({ data: url === '/providers' ? { data: providers } : url === '/models' ? { data: models } : url === '/model-operations/config' ? config : url.startsWith('/model-operations/jobs/') ? { job_id: 'job-1', state: 'completed', total: 1, completed: 1, items: [{ id: 'r1', invocation_id: 'job-1', model_id: 'm1', model_name: 'claude-test', protocol: 'messages', success: true, body_validated: true, http_status: 200, latency_ms: 12 }] } : { items: [] } }))
  http.post.mockResolvedValue({ data: { job_id: 'job-1', state: 'queued', total: 1, completed: 0, items: [] } })
})
afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks(); sessionStorage.clear() })

describe('model validation entry points', () => {
  it('starts a single model verification from the actual management row without changing routing or enablement', async () => {
    renderPage(<ModelManagement />, '/models')
    await userEvent.click(await screen.findByRole('button', { name: '验证 claude-test' }))
    await userEvent.click(screen.getByRole('checkbox', { name: '确认本次上游请求费用' }))
    await waitFor(() => expect(screen.getByRole('button', { name: /开始验证/ })).toBeEnabled())
    await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText('验证完成：1 项通过，0 项失败')
    expect(http.post.mock.calls[0][1].model_ids).toEqual(['m1'])
    expect(http.patch).not.toHaveBeenCalled()
    expect(http.put).not.toHaveBeenCalled()
  })

  it('uses the real selected model rows for batch verification', async () => {
    renderPage(<ModelManagement />, '/models')
    await screen.findByRole('button', { name: '验证 claude-test' })
    const rowCheckboxes = screen.getAllByRole('checkbox').filter((element) => element.closest('tbody'))
    for (const checkbox of rowCheckboxes) await userEvent.click(checkbox)
    await userEvent.click(screen.getByRole('button', { name: /批量验证/ }))
    expect(screen.getByText('已选模型：claude-test、chat-test')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('checkbox', { name: '确认本次上游请求费用' }))
    await waitFor(() => expect(screen.getByRole('button', { name: /开始验证/ })).toBeEnabled())
    await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await waitFor(() => expect(http.post.mock.calls[0][1].model_ids).toEqual(['m1', 'm2']))
    expect(http.patch).not.toHaveBeenCalled()
  })

  it('selects a specific registered model from an upstream and keeps other upstreams out', async () => {
    renderPage(<Providers />, '/providers?provider_id=p1')
    await userEvent.click(await screen.findByRole('button', { name: '验证上游 渠道 A' }))
    await userEvent.click(await screen.findByRole('combobox', { name: '待验证模型' }))
    await userEvent.click(await screen.findByText('claude-test'))
    expect(screen.queryByText('retained-model')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('checkbox', { name: '确认本次上游请求费用' }))
    await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await waitFor(() => expect(http.post.mock.calls[0][1].model_ids).toEqual(['m1']))
    expect(http.patch).not.toHaveBeenCalled()
  })

  it('preserves the model and provider identity in the operations link and shows retained model links', async () => {
    renderPage(<ModelManagement />, '/models?model_id=m3')
    await screen.findByRole('button', { name: '验证 retained-model' })
    const row = screen.getByRole('button', { name: '运营 retained-model' }).closest('tr')!
    expect(within(row).getByRole('switch')).not.toBeChecked()
    await userEvent.click(within(row).getByRole('button', { name: '运营 retained-model' }))
    expect(screen.getByTestId('location')).toHaveTextContent('/model-operations?model_id=m3&provider_id=p2&return_to=%2Fmodels')
  })
})
