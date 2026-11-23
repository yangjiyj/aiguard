import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import userEvent from '@testing-library/user-event'
import Providers from '../pages/Providers'
import * as api from '../services/api'

const ok = (body: any) => ({ data: body, status: 200, statusText: 'OK', headers: {}, config: {} } as any)

const providerFixture = {
  id: 'prov_1',
  name: 'OpenAI 官方',
  provider_type: 'openai',
  base_url: 'https://api.openai.com',
  has_credential: true,
  credential_updated_at: '2026-07-30T16:00:00Z',
  status: 'active',
}

describe('Providers page', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.modelApi, 'catalogSyncState').mockResolvedValue(ok({ interval_seconds: 3600, status: 'never', result: {} }))
    vi.spyOn(api.providerApi, 'list').mockResolvedValue(ok({ data: [providerFixture], total: 1 }))
    vi.spyOn(api.providerApi, 'metrics').mockResolvedValue(ok({
      data: [
        { provider_id: 'prov_1', route_count: 3, avg_ttft_ms: 812, samples: 40, failing_route_count: 1, auth_failures: 5 },
      ],
      window_minutes: 30,
    }))
    vi.spyOn(api.providerApi, 'deleted').mockResolvedValue(ok({ items: [] }))
  })

  afterEach(() => {
    vi.restoreAllMocks()
    cleanup()
    document.body.innerHTML = ''
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <Providers />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  it('shows per-provider route metrics from the metrics API', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('OpenAI 官方')).toBeInTheDocument()
      expect(screen.getByText('0.81 s')).toBeInTheDocument()
    })
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('1 条')).toBeInTheDocument()
  })

  it('flags credentials with recent auth failures so admins notice a dead key', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/近期鉴权失败 5 次/)).toBeInTheDocument()
    })
  })

  it('formats credential update time instead of dumping the raw UTC string', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('OpenAI 官方')).toBeInTheDocument()
    })
    expect(screen.queryByText('2026-07-30T16:00:00Z')).not.toBeInTheDocument()
    expect(screen.getByText(/2026-07-3[01] \d{2}:00:00/)).toBeInTheDocument()
  })

  it('offers a 查看线路 entry into the routing page scoped to this provider', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: '查看线路' })).toBeInTheDocument()
    })
  })

  it('points pricing and routing to the correct menus in the subtitle', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/模型管控 · 模型管理/)).toBeInTheDocument()
      expect(screen.getByText(/模型管控 · 模型路由/)).toBeInTheDocument()
    })
    expect(screen.queryByText(/备用路由/)).not.toBeInTheDocument()
    expect(screen.queryByText(/安全互联 · 模型管理/)).not.toBeInTheDocument()
  })

  it('degrades to placeholders when a provider has no recent traffic', async () => {
    vi.mocked(api.providerApi.metrics).mockResolvedValue(ok({ data: [], window_minutes: 30 }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('OpenAI 官方')).toBeInTheDocument()
    })
    expect(screen.queryByText(/近期鉴权失败/)).not.toBeInTheDocument()
  })

  it('shows complete-chat providers as not requiring model sync', async () => {
	vi.mocked(api.providerApi.list).mockResolvedValue(ok({ data: [{
		...providerFixture,
		id: 'prov_raw',
		name: '内部大模型',
		provider_type: 'custom',
		auth_mode: 'authorization_raw',
		base_url: 'http://upstream.internal/private/chat/V2',
	}], total: 1 }))
	vi.mocked(api.providerApi.metrics).mockResolvedValue(ok({ data: [], window_minutes: 30 }))
	renderPage()
	await waitFor(() => expect(screen.getByText('内部大模型')).toBeInTheDocument())
	expect(screen.getByText('无需同步')).toBeInTheDocument()
	expect(screen.queryByRole('button', { name: /同步模型/ })).not.toBeInTheDocument()
  })

	it('validates and creates a complete Chat endpoint with the required fields', async () => {
	const user = userEvent.setup()
	const create = vi.spyOn(api.providerApi, 'create').mockImplementation(() => new Promise(() => {}))
	renderPage()
	await waitFor(() => expect(screen.getByText('OpenAI 官方')).toBeInTheDocument())
	await user.click(screen.getByRole('button', { name: /添加渠道/ }))
	await user.click(screen.getByText('完整 Chat 接口'))

	await user.type(screen.getByLabelText('渠道名称'), '内部大模型')
	await user.type(screen.getByLabelText('完整 Chat URL'), 'http://10.10.20.30:19000/private/chat/V2')
	await user.type(screen.getByLabelText('Authorization 值'), 'raw-app-key')
	await user.type(screen.getByLabelText('模型 ID'), 'vendor-model-72b')
	await user.click(screen.getByRole('button', { name: '验证并接入' }))

	await waitFor(() => expect(create).toHaveBeenCalledWith({
		name: '内部大模型',
		provider_type: 'custom',
		base_url: 'http://10.10.20.30:19000/private/chat/V2',
		api_key: 'raw-app-key',
		auth_mode: 'authorization_raw',
		model_id: 'vendor-model-72b',
	}))
  })

  it('shows the backend 409 guidance when a referenced provider cannot be deleted', async () => {
    const user = userEvent.setup()
    vi.spyOn(api.providerApi, 'delete').mockRejectedValue({ response: { status: 409, data: { error: { code: 'provider_in_use', message: '该模型上游正在被已启用的模型路由引用，请先迁移、清理或禁用相关路由。' } } } })
    renderPage()
    await user.click(await screen.findByRole('button', { name: /删除/ }))
    const popconfirm = (await screen.findByText('删除此渠道?')).closest('.ant-popover-inner')
    expect(popconfirm).not.toBeNull()
    await user.click(within(popconfirm as HTMLElement).getByRole('button', { name: /删\s*除/ }))
    await waitFor(() => expect(api.providerApi.delete).toHaveBeenCalledWith('prov_1'))
    expect(await screen.findByText('该模型上游正在被已启用的模型路由引用，请先迁移、清理或禁用相关路由。')).toBeInTheDocument()
  })

  it('restores a deleted provider explicitly and shows the next recovery step', async () => {
    const user = userEvent.setup()
    vi.mocked(api.providerApi.deleted).mockResolvedValue(ok({ items: [{ id: 'prov_deleted', name: '验收上游', provider_type: 'openai', has_credential: true, status: 'deleted' }] }))
    vi.spyOn(api.providerApi, 'restore').mockResolvedValue(ok({ id: 'prov_deleted', name: '验收上游', provider_type: 'openai', has_credential: true, status: 'active' }))
    renderPage()
    expect(screen.queryByRole('button', { name: /恢复上游/ })).not.toBeInTheDocument()
    expect(api.providerApi.deleted).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '回收站' }))
    await user.click(await screen.findByRole('button', { name: /恢复上游/ }))
    await waitFor(() => expect(api.providerApi.restore).toHaveBeenCalledWith('prov_deleted'))
    expect(await screen.findByText('模型上游恢复成功，请同步模型并重新保存默认路由。')).toBeInTheDocument()
  })
})
