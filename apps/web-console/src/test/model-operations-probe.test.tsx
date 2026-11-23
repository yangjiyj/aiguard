import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ModelProbeDialog, { type ProbeModel } from '../components/ModelProbeDialog'
import { useAuthStore } from '../stores/auth'

const http = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } }))
vi.mock('axios', () => ({ default: { create: () => http } }))
const ok = (data: unknown) => ({ data })
const config = { version: 1, enabled: false, interval_seconds: 300, concurrency: 2, timeout_seconds: 15, max_targets: 50, max_output_tokens: 128, protocols: ['chat', 'responses', 'messages'], failure_threshold: 3 }
const models = [{ id: 'm1', provider_id: 'p1', model_name: 'claude-test', protocols: ['anthropic_messages'] }, { id: 'm2', provider_id: 'p1', model_name: 'chat-test' }]
const record = { id: 'r1', invocation_id: 'job-1', model_id: 'm1', model_name: 'claude-test', provider_id: 'p1', provider_name: '渠道 A', upstream_model_id: 'claude-real', protocol: 'messages', source: 'manual', success: true, http_status: 200, body_validated: true, latency_ms: 187, error_kind: '', created_at: '2026-10-04T00:00:00Z' }
const queued = { job_id: 'job-1', state: 'queued', total: 1, completed: 0, items: [] }
const completed = { ...queued, state: 'completed', completed: 1, items: [record] }
const storageKey = 'jjdguard:model-probe:t1:u1'
let client: QueryClient
const renderProbe = (items: ProbeModel[] = models.slice(0, 1), allowSelection = false) => render(<QueryClientProvider client={client}><ModelProbeDialog open models={items} allowSelection={allowSelection} onClose={vi.fn()} /></QueryClientProvider>)
const confirm = async () => { await waitFor(() => expect(http.get).toHaveBeenCalledWith('/model-operations/config')); await userEvent.click(screen.getByRole('checkbox', { name: '确认本次上游请求费用' })); await waitFor(() => expect(screen.getByRole('button', { name: /开始验证/ })).toBeEnabled()) }
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  vi.clearAllMocks(); sessionStorage.clear()
  useAuthStore.setState({ user: { id: 'u1', tenant_id: 't1', role: 'platform_admin' } as any })
  http.get.mockImplementation((url: string) => Promise.resolve(ok(url === '/model-operations/config' ? config : completed)))
  http.post.mockResolvedValue(ok(queued))
})
afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks(); sessionStorage.clear() })

describe('model operations paid probe jobs', () => {
  it('gates a real single-model submission on cost confirmation and pins the config version', async () => {
    renderProbe()
    expect(screen.getByRole('button', { name: /开始验证/ })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    expect(http.post).not.toHaveBeenCalled()
    await confirm()
    await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText('验证完成：1 项通过，0 项失败')
    expect(http.post).toHaveBeenCalledWith('/model-operations/test', { model_ids: ['m1'], confirm_cost: true, expected_config_version: 1, idempotency_key: expect.stringMatching(/^[a-f0-9]{32}$/) })
    expect(screen.getByText('Claude Messages')).toBeInTheDocument()
    expect(screen.getByText('已验证')).toBeInTheDocument()
    expect(screen.getByText('0.19 s')).toBeInTheDocument()
  })

  it('shows each batch result and refuses to call a 200 response with invalid body successful', async () => {
    http.get.mockImplementation((url: string) => Promise.resolve(ok(url === '/model-operations/config' ? config : { ...completed, total: 2, completed: 2, items: [record, { ...record, id: 'r2', model_id: 'm2', model_name: 'chat-test', protocol: 'chat', success: true, body_validated: false, error_kind: 'invalid_body' }] })))
    renderProbe(models)
    await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText('验证完成：1 项通过，1 项失败')
    expect(screen.getByText('验证失败')).toBeInTheDocument()
    expect(screen.getByText('invalid_body')).toBeInTheDocument()
    expect(http.post.mock.calls[0][1].model_ids).toEqual(['m1', 'm2'])
  })

  it('freezes the idempotency key and payload after an uncertain submission', async () => {
    http.post.mockRejectedValueOnce(new Error('socket closed')).mockResolvedValueOnce(ok(queued))
    renderProbe(); await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText(/提交结果尚未确认；重试将使用同一请求标识/)
    expect(screen.getByRole('combobox', { name: '验证协议' })).toBeDisabled()
    const first = http.post.mock.calls[0][1]
    await userEvent.click(screen.getByRole('button', { name: /重试提交/ }))
    await screen.findByText('验证完成：1 项通过，0 项失败')
    expect(http.post.mock.calls[1][1]).toEqual(first)
  })

  it('restores the saved task by GET without charging a new POST', async () => {
    sessionStorage.setItem(storageKey, JSON.stringify({ key: 'saved-key-123', modelIds: ['m1'], expectedVersion: 1, maxOutputTokens: 128, jobId: 'job-1' }))
    renderProbe()
    await screen.findByText('验证完成：1 项通过，0 项失败')
    expect(http.get).toHaveBeenCalledWith('/model-operations/jobs/job-1')
    expect(http.post).not.toHaveBeenCalled()
  })

  it('cancels the actual backend job and reports cancellation as incomplete', async () => {
    let job = { ...queued, state: 'running' }
    http.get.mockImplementation((url: string) => Promise.resolve(ok(url === '/model-operations/config' ? config : job)))
    http.post.mockImplementation((url: string) => {
      if (url.endsWith('/cancel')) { job = { ...queued, state: 'cancelled' }; return Promise.resolve(ok(job)) }
      return Promise.resolve(ok(queued))
    })
    renderProbe(); await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await userEvent.click(await screen.findByRole('button', { name: /取消验证/ }))
    await screen.findByText('已取消 · 已完成 0 / 1')
    expect(http.post).toHaveBeenCalledWith('/model-operations/jobs/job-1/cancel')
    expect(screen.queryByText(/验证完成：/)).not.toBeInTheDocument()
  })

  it('preserves selected models after a budget conflict and requires fresh confirmation', async () => {
    let current = config
    http.get.mockImplementation((url: string) => Promise.resolve(ok(url === '/model-operations/config' ? current : completed)))
    http.post.mockImplementationOnce(() => { current = { ...config, version: 2, max_output_tokens: 256 }; return Promise.reject({ response: { status: 409, data: { error: { code: 'config_conflict' } } } }) }).mockResolvedValue(ok(queued))
    renderProbe(); await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText(/费用预算配置已变更/)
    expect(screen.getByText('已选模型：claude-test')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '确认本次上游请求费用' })).not.toBeChecked()
    expect(screen.getByRole('button', { name: /开始验证/ })).toBeDisabled()
    await screen.findByText(/每请求输出上限 256 Token/)
    await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText('验证完成：1 项通过，0 项失败')
    expect(http.post.mock.calls[1][1].expected_config_version).toBe(2)
  })

  it('follows a conflicting existing task without another submission', async () => {
    http.get.mockImplementation((url: string) => Promise.resolve(ok(url === '/model-operations/config' ? config : { ...completed, job_id: 'job-existing', items: [{ ...record, invocation_id: 'job-existing' }] })))
    http.post.mockRejectedValue({ response: { status: 409, data: { error: { code: 'active_job', message: '已有验证任务', details: { job_id: 'job-existing' } } } } })
    renderProbe(); await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await userEvent.click(await screen.findByRole('button', { name: '跟进已有验证' }))
    await screen.findByText('验证完成：1 项通过，0 项失败')
    expect(http.get).toHaveBeenCalledWith('/model-operations/jobs/job-existing')
    expect(http.post).toHaveBeenCalledTimes(1)
  })

  it('shows permission denial and never claims validation completed', async () => {
    http.post.mockRejectedValue({ response: { status: 403, data: {} } })
    renderProbe(); await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText('当前账号无模型运营权限')
    expect(screen.queryByText(/验证完成：/)).not.toBeInTheDocument()
  })

  it('blocks over-limit actual protocol requests before POST', async () => {
    renderProbe(Array.from({ length: 51 }, (_, index) => ({ id: `m${index}`, model_name: `model-${index}` })))
    await screen.findByText('每次最多 50 个协议请求，请减少模型或协议')
    await userEvent.click(screen.getByRole('checkbox', { name: '确认本次上游请求费用' }))
    expect(screen.getByRole('button', { name: /开始验证/ })).toBeDisabled()
    expect(http.post).not.toHaveBeenCalled()
  })

  it('does not turn an empty completed response or read failure into a green success', async () => {
    http.get.mockImplementation((url: string) => Promise.resolve(ok(url === '/model-operations/config' ? config : { ...completed, items: [] })))
    renderProbe(); await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText('结果不完整，请检查探测历史')
    expect(screen.queryByText(/验证完成：/)).not.toBeInTheDocument()
  })

  it('refuses evidence from a previous invocation even when count and success match', async () => {
    http.get.mockImplementation((url: string) => Promise.resolve(ok(url === '/model-operations/config' ? config : { ...completed, items: [{ ...record, invocation_id: 'old-job' }] })))
    renderProbe(); await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText('结果不完整，请检查探测历史')
    expect(screen.queryByText(/验证完成：/)).not.toBeInTheDocument()
  })

  it('counts skipped targets as unexecuted and keeps them out of successful evidence', async () => {
    http.get.mockImplementation((url: string) => Promise.resolve(ok(url === '/model-operations/config' ? config : { ...completed, total: 2, items: [{ ...record, success: false, body_validated: false, http_status: 403, error_kind: 'unauthorized' }], skipped: [{ ...record, id: undefined, model_id: 'm2', model_name: 'chat-test', reason: 'provider_auth_failed' }] })))
    renderProbe(models); await confirm(); await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
    await screen.findByText('验证完成：0 项通过，1 项失败，1 项未执行')
    expect(screen.getByText('同上游鉴权失败，后续请求已停止')).toBeInTheDocument()
    expect(screen.queryByText('验证通过')).not.toBeInTheDocument()
  })

  it('invalidates a fee confirmation when a background config refresh increases the budget', async () => {
    renderProbe(); await confirm()
    act(() => { client.setQueryData(['model-operations', 'config', storageKey], { ...config, version: 2, max_output_tokens: 256 }) })
    await screen.findByText(/每请求输出上限 256 Token/)
    expect(screen.getByRole('checkbox', { name: '确认本次上游请求费用' })).not.toBeChecked()
    expect(screen.getByRole('button', { name: /开始验证/ })).toBeDisabled()
    expect(http.post).not.toHaveBeenCalled()
  })
})


it('clears a definitively rejected target submission and allows a fresh selection', async () => {
  http.post.mockRejectedValueOnce({response:{status:404,data:{error:{code:'not_found',message:'model operations target not found or not owned'}}}}).mockResolvedValueOnce(ok(queued))
  renderProbe(); await confirm(); await userEvent.click(screen.getByRole('button',{name:/开始验证/}))
  await screen.findByText(/验证未发起：.*模型/)
  expect(screen.queryByText('提交结果尚未确认')).not.toBeInTheDocument()
  expect(screen.getByRole('combobox',{name:'验证协议'})).toBeEnabled()
  expect(sessionStorage.getItem(storageKey)).toBeNull()
  expect(screen.getByRole('checkbox',{name:'确认本次上游请求费用'})).not.toBeChecked()
  const first=http.post.mock.calls[0][1].idempotency_key
  await confirm(); await userEvent.click(screen.getByRole('button',{name:/开始验证/}))
  await screen.findByText('验证完成：1 项通过，0 项失败')
  expect(http.post.mock.calls[1][1].idempotency_key).not.toBe(first)
})


it.each(['gemini', 'vertex', 'bedrock'])('lets a %s model run one native Chat verification', async provider_type => {
 renderProbe([{ id: 'm1', model_name: 'native-fixture', provider_id: 'p1', provider_type }])
 expect(await screen.findByText(/Gemini \/ Vertex 使用 generateContent/)).toBeInTheDocument()
 await confirm()
 await userEvent.click(screen.getByRole('button', { name: /开始验证/ }))
 await waitFor(() => expect(http.post).toHaveBeenCalledWith('/model-operations/test', expect.objectContaining({ model_ids: ['m1'] })))
 expect(http.post.mock.calls[0][1].protocols).toBeUndefined()
})
