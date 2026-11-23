import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import axios from 'axios'
import { message } from 'antd'
import ModelManagement from '../pages/ModelManagement'
import { getModelBatchDeleteErrorMessage, validateModelBatchDeleteSelection } from '../utils/modelBatchDelete'
import * as api from '../services/api'

const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
  interceptors: {
    request: { use: vi.fn() },
    response: { use: vi.fn() },
  },
}))

vi.mock('axios', () => ({
  default: {
    create: vi.fn(() => mockApi),
  },
}))

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return { ...actual, message: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }
})

const withAvailability = (body: any): any => {
  if (Array.isArray(body)) return body.map(withAvailability)
  if (body && typeof body === 'object') {
    if (body.model_name && body.callable === undefined) return { ...body, callable: body.status === 'active', availability_state: body.status === 'active' ? 'callable' : 'disabled' }
    return Object.fromEntries(Object.entries(body).map(([key, value]) => [key, withAvailability(value)]))
  }
  return body
}
const ok = (body: any) => ({ data: withAvailability(body), status: 200, statusText: 'OK', headers: {}, config: {} } as any)

const deferred = <T,>() => {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

const modelFixtures = [
  { id: 'm1', provider_id: 'prov_1', model_name: 'active-model', pricing_json: { input: 1, output: 2 }, status: 'active' },
  { id: 'm2', provider_id: 'prov_1', model_name: 'retained-model', pricing_json: { input: 1, output: 2 }, status: 'disabled' },
]

const ModelLocation = () => {
  const location = useLocation()
  return <output data-testid="model-location">{location.pathname}{location.search}</output>
}

const modelOperationsLabel = '\u6a21\u578b\u8fd0\u8425'
const oldProtocolWarning = '\u8be5\u6a21\u578b\u672a\u767b\u8bb0\u5177\u4f53\u534f\u8bae\uff0c\u6682\u65e0\u8c03\u7528\u793a\u4f8b'
const oldProtocolRecreateAdvice = '\u6dfb\u52a0\u6a21\u578b\u65f6\u81ea\u52a8\u68c0\u6d4b\u672a\u4fdd\u5b58\u6210\u529f\u534f\u8bae\uff0c\u6216\u534f\u8bae\u4e3a\u7a7a\uff1b\u8bf7\u5148\u5728\u6dfb\u52a0\u6a21\u578b\u5904\u660e\u786e\u534f\u8bae\u540e\u63a5\u5165\u3002'

describe('ModelManagement integration drawer', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.fxApi, 'current').mockResolvedValue(ok({ data: { rate: 7.24 } }))
    vi.spyOn(api.modelApi, 'evalStatus').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.providerApi, 'list').mockResolvedValue(ok({
      data: [
        { id: 'prov_1', name: 'OpenAI 官方', provider_type: 'openai', base_url: 'https://api.openai.com', has_credential: true, status: 'active' },
      ],
    }))
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
          <ModelManagement />
          <ModelLocation />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  const openDrawer = async (model: any) => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [model] }))
    mockApi.get.mockImplementation((url: string) => {
      if (url === '/system/settings') return Promise.resolve(ok({ gateway_public_base_url: 'https://gw.example.com/v1', gateway_public_url_mode: 'configured' }))
      return Promise.reject(new Error(`unexpected GET ${url}`))
    })
    renderPage()
    await screen.findByText(model.model_label || model.model_name)
    await userEvent.click(screen.getByRole('button', { name: /接入/ }))
    await screen.findByText('调用地址')
  }

  it('只有已部署模型时不显示空的保留与全部记录分页', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [{id:'deployed-only',provider_id:'prov_1',model_name:'only-deployed-model',status:'active',callable:true}] }))
    renderPage()
    expect(await screen.findByText('only-deployed-model')).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /其他状态与保留/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /全部记录/ })).not.toBeInTheDocument()
    expect(screen.queryByText('其他状态与保留')).not.toBeInTheDocument()
  })

  it('探测结果只作建议：可调用模型旁显示验证建议', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [
      {id:'m-exp',provider_id:'prov_1',model_name:'gpt-6-luna',status:'active',callable:true,availability_state:'callable',advice:'expired'},
      {id:'m-un',provider_id:'prov_1',model_name:'claude-opus-5-5',status:'active',callable:true,availability_state:'callable',advice:'unverified'},
      {id:'m-ok',provider_id:'prov_1',model_name:'gpt-5.6-luna',status:'active',callable:true,availability_state:'callable',advice:''},
    ] }))
    renderPage()
    expect(await screen.findByText('gpt-6-luna')).toBeInTheDocument()
    expect(screen.getByText('验证已过期，建议重新验证')).toBeInTheDocument()
    expect(screen.getByText('未验证，建议验证')).toBeInTheDocument()
    expect(screen.getAllByText('可调用')).toHaveLength(3)
    expect(document.body.textContent).toContain('当前可调用模型：3')
  })

  it('shows the backend reason when an unverified model cannot be enabled', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [{id:'image-pending',provider_id:'prov_1',model_name:'gpt-image-2',status:'pending',callable:false,availability_state:'pending_admission'}] }))
    vi.spyOn(api.modelApi, 'updateStatus').mockRejectedValue({response:{status:409,data:{error:{code:'model_not_available',message:'上游已下架该模型，无法启用'}}}})
    mockApi.get.mockResolvedValue(ok({}))
    renderPage()
    await userEvent.click(await screen.findByRole('tab',{name:/其他状态与保留 1/}))
    await userEvent.click(await screen.findByRole('switch'))
    await waitFor(()=>expect(message.error).toHaveBeenCalledWith('上游已下架该模型，无法启用'))
  })

  it('reads registered protocol flags from the model capabilities returned by the API', async () => {
    await openDrawer({ id: 'm1', provider_id: 'prov_1', model_name: 'gw-model', model_label: 'GW Model', status: 'active', capabilities: { protocols: { chat_completions: true, images: true, gemini: true, stream: true, metadata: true, unknown_protocol: true } } })
    // 展示网关公开地址，绝不展示上游供应商地址
    expect(screen.getByText('https://gw.example.com/v1')).toBeInTheDocument()
    expect(screen.queryByText('https://api.openai.com')).not.toBeInTheDocument()
    // 只有模型实际支持的协议才出现示例端点：chat_completions 有，images 没有
    expect(screen.getByText('https://gw.example.com/v1/chat/completions')).toBeInTheDocument()
    expect(screen.queryByText('https://gw.example.com/v1/images')).not.toBeInTheDocument()
    // Registered configuration does not establish current upstream availability.
    expect(screen.queryByText(/已支持协议：图像生成/)).not.toBeInTheDocument()
    expect(screen.getByText(/Gemini/)).toBeInTheDocument()
    expect(screen.queryByText(/unknown_protocol|metadata|stream/)).not.toBeInTheDocument()
    // curl 示例引用密钥环境变量，且模型名来自当前记录
    const example = screen.getByDisplayValue(/curl -sS/)
    expect((example as HTMLTextAreaElement).value).toContain('Authorization: Bearer $AIGUARD_API_KEY')
    expect((example as HTMLTextAreaElement).value).toContain('"model": "gw-model"')
    expect((example as HTMLTextAreaElement).value).not.toMatch(/sk-[A-Za-z0-9]/)
    expect(screen.getAllByDisplayValue(/curl -sS/)).toHaveLength(1)
  })

  it('maps native Responses and Anthropic flags to their existing gateway endpoints', async () => {
    await openDrawer({ id: 'm1', provider_id: 'prov_1', model_name: 'native-model', status: 'active', capabilities: { protocols: { responses_native: true, anthropic_messages: true, chat_completions: false } } })

    expect(screen.getByText('https://gw.example.com/v1/responses')).toBeInTheDocument()
    expect(screen.getByText('https://gw.example.com/v1/messages')).toBeInTheDocument()
    expect(screen.queryByText('https://gw.example.com/v1/chat/completions')).not.toBeInTheDocument()
    expect(screen.getAllByDisplayValue(/curl -sS/)).toHaveLength(2)
    for (const example of screen.getAllByDisplayValue(/curl -sS/)) {
      expect((example as HTMLTextAreaElement).value).toContain('"model": "native-model"')
    }
  })

  it('expands the gateway key environment variable in the copied curl command', async () => {
    await openDrawer({ id: 'm1', provider_id: 'prov_1', model_name: 'gw-model', status: 'active', capabilities: { protocols: { chat_completions: true } } })
    const example = screen.getByDisplayValue(/curl -sS/) as HTMLTextAreaElement
    const { execFileSync } = await vi.importActual<{
      execFileSync: (file: string, args: string[], options: { env: Record<string, string>; encoding: 'utf8' }) => string
    }>('node:child_process')
    const args = execFileSync('/bin/sh', ['-c', `curl() { printf '%s\\n' "$@"; }; ${example.value}`], {
      env: { PATH: '/usr/bin:/bin', AIGUARD_API_KEY: 'fixture-gateway-key' },
      encoding: 'utf8',
    }).split('\n')

    expect(args).toContain('Authorization: Bearer fixture-gateway-key')
    expect(args).not.toContain('Authorization: Bearer $AIGUARD_API_KEY')
  })

  it('keeps embeddings examples grounded in the registered boolean flag', async () => {
    await openDrawer({ id: 'm1', provider_id: 'prov_1', model_name: 'embedding-model', status: 'active', capabilities: { protocols: { embeddings: true, responses_native: false } } })

    expect(screen.getByText('https://gw.example.com/v1/embeddings')).toBeInTheDocument()
    expect(screen.queryByText('https://gw.example.com/v1/responses')).not.toBeInTheDocument()
    expect(screen.getAllByDisplayValue(/curl -sS/)).toHaveLength(1)
  })

  it.each([
    ['missing', undefined],
    ['null capabilities', null],
    ['empty capabilities', {}],
    ['empty protocol map', { protocols: {} }],
    ['null protocol map', { protocols: null }],
    ['string protocol map', { protocols: 'chat_completions' }],
    ['array protocol map', { protocols: ['chat_completions', 'responses_native'] }],
    ['disabled protocol flags', { protocols: { chat_completions: false, responses_native: false, anthropic_messages: false, embeddings: false, images: false, gemini: false } }],
    ['malformed flag values', { protocols: { chat_completions: 'true', responses_native: 1, anthropic_messages: {}, embeddings: [], images: 'true', gemini: 1 } }],
    ['metadata and unrecognized flags', { protocols: { stream: true, metadata: true, responses: true, unknown_protocol: true } }],
  ])('does not invent examples from %s', async (_name, capabilities) => {
    await openDrawer({ id: 'm1', provider_id: 'prov_1', model_name: 'gw-model', status: 'active', capabilities, protocols: ['chat_completions', 'responses'] })

    expect(screen.getByText('https://gw.example.com/v1')).toBeInTheDocument()
    expect(screen.queryByDisplayValue(/curl -sS/)).not.toBeInTheDocument()
    expect(screen.queryByText(/unknown_protocol|metadata|responses_native/)).not.toBeInTheDocument()
    expect(screen.queryByText(oldProtocolWarning)).not.toBeInTheDocument()
    expect(screen.queryByText(oldProtocolRecreateAdvice)).not.toBeInTheDocument()
    const drawer = document.querySelector('.ant-drawer-body') as HTMLElement
    expect(within(drawer).getByRole('button', { name: modelOperationsLabel })).toBeInTheDocument()
  })

  it('uses the current ingress including its actual port when no fixed URL is configured', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [{ id: 'm1', provider_id: 'prov_1', model_name: 'gw-model', status: 'active', capabilities: { protocols: { chat_completions: true } } }] }))
    mockApi.get.mockImplementation((url: string) => {
      if (url === '/system/settings') return Promise.resolve(ok({}))
      return Promise.reject(new Error(`unexpected GET ${url}`))
    })
    renderPage()
    await screen.findByText('gw-model')
    await userEvent.click(screen.getByRole('button', { name: /接入/ }))
    expect(await screen.findByText(window.location.origin + '/v1')).toBeInTheDocument()
    expect(screen.getByText(window.location.origin + '/v1/chat/completions')).toBeInTheDocument()
  })

  it('keeps unregistered models visible and links to existing operations without probing or recreating them', async () => {
    await openDrawer({ id: 'm1', provider_id: 'prov_1', model_name: 'gw-model', status: 'active' })
    const drawer = document.querySelector('.ant-drawer-body') as HTMLElement
    expect(within(drawer).getByText('gw-model')).toBeInTheDocument()
    expect(within(drawer).getByText('https://gw.example.com/v1')).toBeInTheDocument()
    expect(within(drawer).queryByText(oldProtocolWarning)).not.toBeInTheDocument()
    expect(within(drawer).queryByText(oldProtocolRecreateAdvice)).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue(/curl -sS/)).not.toBeInTheDocument()

    await userEvent.click(within(drawer).getByRole('button', { name: modelOperationsLabel }))
    const destination = new URL(screen.getByTestId('model-location').textContent || '', 'https://console.example.com')
    expect(destination.pathname).toBe('/model-operations')
    expect(destination.searchParams.get('model_id')).toBe('m1')
    expect(destination.searchParams.get('provider_id')).toBe('prov_1')
    expect(destination.searchParams.get('return_to')).toBe('/models')
    expect(mockApi.post).not.toHaveBeenCalled()
    expect(mockApi.put).not.toHaveBeenCalled()
    expect(mockApi.patch).not.toHaveBeenCalled()
    expect(mockApi.delete).not.toHaveBeenCalled()
  })
})

describe('modelApi.batchDelete', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('posts all selected model IDs to the batch endpoint exactly once', async () => {
    mockApi.post.mockResolvedValueOnce(ok({ requested: 2, deleted: 1, disabled: 1, failed: 0 }))
    const batchDelete = (api.modelApi as any).batchDelete

    expect(batchDelete).toBeTypeOf('function')
    if (typeof batchDelete !== 'function') return

    await batchDelete(['m1', 'm2'])

    expect(axios.create().post).toHaveBeenCalledTimes(1)
    expect(axios.create().post).toHaveBeenCalledWith('/models/batch-delete', { model_ids: ['m1', 'm2'] })
  })
})

describe('ModelManagement page', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.fxApi, 'current').mockResolvedValue(ok({ data: { rate: 7.24 } }))
    vi.spyOn(api.modelApi, 'evalStatus').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.providerApi, 'list').mockResolvedValue(ok({
      data: [
        { id: 'prov_1', name: 'OpenAI 官方', provider_type: 'openai', base_url: 'https://api.openai.com', has_credential: true, status: 'active' },
      ],
    }))
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
          <ModelManagement />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  const mockBatchDelete = (implementation: (ids: string[]) => Promise<any>) =>
    vi.spyOn(api.modelApi, 'batchDelete').mockImplementation(implementation)

  const rowSelectionCheckboxes = () =>
    screen.getAllByRole('checkbox').filter((checkbox) => checkbox.closest('tbody'))

  it('does not expose legacy model pricing fields or actions', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [{ id: 'm1', provider_id: 'prov_1', model_name: 'price-model', model_label: 'Price Model', pricing_json: { input: 2, output: 8 }, status: 'active' }] }))
    renderPage()
    await screen.findByText('Price Model')
    expect(screen.queryByText('输入价格')).not.toBeInTheDocument()
    expect(screen.queryByText('输出价格')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '定价' })).not.toBeInTheDocument()
  })

  it('directs pricing ownership to the billing center', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [{ id: 'm1', provider_id: 'prov_1', model_name: 'active-model', status: 'active' }] }))
    renderPage()
    expect(await screen.findByText(/价格只在“价格与成本”配置/)).toBeInTheDocument()
    expect(screen.queryByText('已定价模型')).not.toBeInTheDocument()
    expect(screen.queryByText('仅看未定价')).not.toBeInTheDocument()
  })

  it('does not mount a model price editor', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [{ id: 'm1', provider_id: 'prov_1', model_name: 'active-model', status: 'active' }] }))
    renderPage()
    await screen.findByText('active-model')
    expect(screen.queryByLabelText(/输入价格/)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/输出价格/)).not.toBeInTheDocument()
  })

  it('defaults to current callable models and separates retained stale models', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({
      data: [
        { id: 'm1', provider_id: 'prov_1', model_name: 'active-model', pricing_json: { input: 1, output: 2 }, status: 'active' },
        { id: 'm2', provider_id: 'prov_1', model_name: 'stale-model', pricing_json: { input: 1, output: 2 }, status: 'disabled' },
      ],
    }))
    renderPage()

    await waitFor(() => {
      expect(screen.getAllByText('active-model').length).toBeGreaterThan(0)
      expect(screen.queryByText('stale-model')).not.toBeInTheDocument()
      expect(screen.getByText('当前可调用模型')).toBeInTheDocument()
      expect(screen.getByText('其他状态与保留')).toBeInTheDocument()
    })

    await userEvent.click(screen.getByRole('tab', { name: /其他状态与保留 1/ }))
    await waitFor(() => {
      expect(screen.getAllByText('stale-model').length).toBeGreaterThan(0)
    })
  })

  it('does not blank-screen on empty / null model list', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: null }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('模型管理')).toBeInTheDocument()
      expect(screen.queryByText('模型接入')).not.toBeInTheDocument()
    })
  })

  it('removes the 模型代理访问 entry (column + copy) — superseded by reverse proxy', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({
      data: [
        { id: 'm1', provider_id: 'prov_1', model_name: 'active-model', pricing_json: { input: 1, output: 2 }, status: 'active', proxy_config: { enabled: true } },
      ],
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getAllByText('active-model').length).toBeGreaterThan(0)
    })
    expect(screen.queryAllByText(/代理访问/)).toHaveLength(0)
  })
  it('enables row selection in every model view and clears it when switching tabs', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: modelFixtures }))
    renderPage()

    await screen.findAllByText('active-model')
    expect(rowSelectionCheckboxes()).toHaveLength(1)
    await userEvent.click(rowSelectionCheckboxes()[0])
    expect(screen.getByText('已选 1 / 当前视图 1')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: /其他状态与保留 1/ }))
    await screen.findAllByText('retained-model')
    expect(rowSelectionCheckboxes()).toHaveLength(1)
    expect(screen.getByText('已选 0 / 当前视图 1')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: /全部记录 2/ }))
    await screen.findAllByText('active-model')
    expect(rowSelectionCheckboxes()).toHaveLength(2)
    expect(screen.getByText('已选 0 / 当前视图 2')).toBeInTheDocument()
  })

  it('shows a clear mixed-status confirmation before one batch delete request', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: modelFixtures }))
    const batchDelete = mockBatchDelete(async () => ok({ requested: 2, deleted: 1, disabled: 1, failed: 0 }))
    const singleDelete = vi.spyOn(api.modelApi, 'delete').mockResolvedValue(ok({}))
    renderPage()

    await userEvent.click(await screen.findByRole('tab', { name: /全部记录 2/ }))
    await screen.findAllByText('active-model')
    for (const checkbox of rowSelectionCheckboxes()) await userEvent.click(checkbox)

    expect(screen.getByText('已选 2 / 当前视图 2')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /批量重新启用/ })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /批量删除/ }))

    expect(await screen.findByText(/确认处理选中的 2 个模型/)).toBeInTheDocument()
    expect(screen.getByText(/其中当前启用 1 个/)).toBeInTheDocument()
    expect(screen.getByText(/有历史引用.*自动停用保留.*不会删除历史记录/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '确认删除' }))

    await waitFor(() => {
      expect(batchDelete).toHaveBeenCalledTimes(1)
      expect(batchDelete).toHaveBeenCalledWith(['m1', 'm2'])
    })
    expect(singleDelete).not.toHaveBeenCalled()
  })

  it('clears selection, refreshes models, and reports exact backend totals after success', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: modelFixtures }))
    mockBatchDelete(async () => ok({ requested: 2, deleted: 1, disabled: 1, failed: 0 }))
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    renderPage()

    await userEvent.click(await screen.findByRole('tab', { name: /全部记录 2/ }))
    await screen.findAllByText('active-model')
    for (const checkbox of rowSelectionCheckboxes()) await userEvent.click(checkbox)
    await userEvent.click(screen.getByRole('button', { name: /批量删除/ }))
    await userEvent.click(await screen.findByRole('button', { name: '确认删除' }))

    await waitFor(() => {
      expect(message.success).toHaveBeenCalledWith('已处理 2 个：删除 1 个，停用保留 1 个，失败 0 个')
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ['models'] })
      expect(screen.getByText('已选 0 / 当前视图 2')).toBeInTheDocument()
    })
  })

  it('maps a real backend permission error to Chinese and keeps the selection for retry', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: modelFixtures }))
    const batchDelete = mockBatchDelete(async () => {
      throw {
        response: {
          status: 403,
          data: { error: { code: 'permission_denied', message: 'insufficient permissions for this operation' } },
        },
      }
    })
    renderPage()

    await screen.findAllByText('active-model')
    await userEvent.click(rowSelectionCheckboxes()[0])
    await userEvent.click(screen.getByRole('button', { name: /批量删除/ }))
    await userEvent.click(await screen.findByRole('button', { name: '确认删除' }))

    await waitFor(() => {
      expect(batchDelete).toHaveBeenCalledTimes(1)
      expect(message.error).toHaveBeenCalledWith('当前账号无批量删除权限，请联系管理员')
      expect(message.error).not.toHaveBeenCalledWith(expect.stringContaining('insufficient permissions'))
      expect(screen.getByText('已选 1 / 当前视图 1')).toBeInTheDocument()
    })
    expect(rowSelectionCheckboxes()[0]).toBeChecked()
  })

  it('maps every batch-delete backend error class to customer-facing Chinese', () => {
    const mapError = getModelBatchDeleteErrorMessage
    const cases: Array<[unknown, string]> = [
      [{ response: { status: 403, data: {} } }, '当前账号无批量删除权限，请联系管理员'],
      [{ response: { status: 500, data: { error: { code: 'permission_check_failed' } } } }, '当前账号无批量删除权限，请联系管理员'],
      [{ response: { status: 404, data: {} } }, '所选模型不存在或状态已变化，请刷新后重试'],
      [{ response: { status: 500, data: { error: { code: 'not_found' } } } }, '所选模型不存在或状态已变化，请刷新后重试'],
      [{ response: { status: 400, data: {} } }, '选择内容不符合要求，请刷新后分批重试'],
      [{ response: { status: 500, data: { error: { code: 'invalid_request' } } } }, '选择内容不符合要求，请刷新后分批重试'],
      [{ response: { status: 500, data: { error: { code: 'internal_error', message: 'database shard unavailable' } } } }, '批量删除失败，请稍后重试'],
    ]

    expect(mapError).toBeTypeOf('function')
    if (typeof mapError !== 'function') return
    for (const [error, expected] of cases) expect(mapError(error)).toBe(expected)
  })

  it('locks every conflicting model state control while batch delete is pending', async () => {
    const pendingDelete = deferred<any>()
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: modelFixtures }))
    const batchDelete = mockBatchDelete(() => pendingDelete.promise)
    const updateStatus = vi.spyOn(api.modelApi, 'updateStatus').mockResolvedValue(ok({}))
    const singleDelete = vi.spyOn(api.modelApi, 'delete').mockResolvedValue(ok({}))
    renderPage()

    await userEvent.click(await screen.findByRole('tab', { name: /其他状态与保留 1/ }))
    await screen.findAllByText('retained-model')
    await userEvent.click(rowSelectionCheckboxes()[0])
    await userEvent.click(screen.getByRole('button', { name: /批量删除/ }))
    await userEvent.click(await screen.findByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(batchDelete).toHaveBeenCalledWith(['m2']))

    const retainedRow = screen.getAllByText('retained-model')[0].closest('tr')
    expect(retainedRow).not.toBeNull()
    const row = within(retainedRow!)
    const batchEnableButton = screen.getByRole('button', { name: /批量重新启用/ })
    const rowCheckbox = row.getByRole('checkbox')
    const rowSwitch = row.getByRole('switch')
    const rowDeleteButton = row.getByRole('button', { name: /删除/ })

    await waitFor(() => {
      expect(batchEnableButton).toBeDisabled()
      expect(rowCheckbox).toBeDisabled()
      expect(rowSwitch).toBeDisabled()
      expect(rowDeleteButton).toBeDisabled()
    })
    expect(updateStatus).not.toHaveBeenCalled()
    expect(singleDelete).not.toHaveBeenCalled()
    expect(screen.getByText('已选 1 / 当前视图 1')).toBeInTheDocument()

    pendingDelete.resolve(ok({ requested: 1, deleted: 1, disabled: 0, failed: 0 }))
    await waitFor(() => {
      expect(message.success).toHaveBeenCalledWith('已处理 1 个：删除 1 个，停用保留 0 个，失败 0 个')
      expect(screen.getByText('已选 0 / 当前视图 1')).toBeInTheDocument()
    })
  })

  it('validates batch selection boundaries', () => {
    const validate = validateModelBatchDeleteSelection

    expect(validate).toBeTypeOf('function')
    if (typeof validate !== 'function') return

    expect(validate([])).toBeTruthy()
    expect(validate(['m1'])).toBeNull()
    expect(validate(Array.from({ length: 100 }, (_, index) => `m${index}`))).toBeNull()
    expect(validate(Array.from({ length: 101 }, (_, index) => `m${index}`))).toBe('每次最多处理 100 个，请分批操作')
  })

  it('blocks an actual 101-item UI selection and keeps it available for retry', async () => {
    const models = Array.from({ length: 101 }, (_, index) => ({
      id: `bulk-${index}`,
      provider_id: 'prov_1',
      model_name: `bulk-model-${index}`,
      pricing_json: { input: 1, output: 2 },
      status: 'active',
    }))
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: models }))
    const batchDelete = mockBatchDelete(async () => ok({ requested: 101, deleted: 101, disabled: 0, failed: 0 }))
    renderPage()

    await screen.findAllByText('bulk-model-0')
    const pageSizeSelector = document.querySelector<HTMLElement>('.ant-pagination-options .ant-select-selector')
    expect(pageSizeSelector).not.toBeNull()
    await userEvent.click(pageSizeSelector!)
    await userEvent.click(await screen.findByText('100 / page'))

    await waitFor(() => expect(rowSelectionCheckboxes()).toHaveLength(100), { timeout: 30_000 })
    const selectCurrentPage = screen.getAllByRole('checkbox').find((checkbox) => checkbox.closest('thead'))
    expect(selectCurrentPage).toBeDefined()
    await userEvent.click(selectCurrentPage!)
    await waitFor(() => expect(screen.getByText('已选 100 / 当前视图 101')).toBeInTheDocument())

    const nextPage = document.querySelector<HTMLElement>('.ant-pagination-next button')
    expect(nextPage).not.toBeNull()
    await userEvent.click(nextPage!)
    await waitFor(() => expect(rowSelectionCheckboxes()).toHaveLength(1))
    await userEvent.click(rowSelectionCheckboxes()[0])
    expect(screen.getByText('已选 101 / 当前视图 101')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /批量删除/ }))
    await userEvent.click(await screen.findByRole('button', { name: '确认删除' }))

    await waitFor(() => {
      expect(message.warning).toHaveBeenCalledWith('每次最多处理 100 个，请分批操作')
      expect(batchDelete).not.toHaveBeenCalled()
      expect(screen.getByText('已选 101 / 当前视图 101')).toBeInTheDocument()
    })
    expect(rowSelectionCheckboxes()[0]).toBeChecked()
  }, 60_000)

  it('keeps batch re-enable available and working in the retained view', async () => {
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: modelFixtures }))
    const updateStatus = vi.spyOn(api.modelApi, 'updateStatus').mockResolvedValue(ok({}))
    renderPage()

    await userEvent.click(await screen.findByRole('tab', { name: /其他状态与保留 1/ }))
    await screen.findAllByText('retained-model')
    await userEvent.click(rowSelectionCheckboxes()[0])
    await userEvent.click(screen.getByRole('button', { name: /批量重新启用/ }))
    await userEvent.click(await screen.findByRole('button', { name: 'OK' }))

    await waitFor(() => {
      expect(updateStatus).toHaveBeenCalledTimes(1)
      expect(updateStatus).toHaveBeenCalledWith('m2', 'active')
    })
  })

})
