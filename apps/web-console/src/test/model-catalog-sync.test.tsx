import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ModelCatalogSyncModal from '../components/providers/ModelCatalogSyncModal'
import * as api from '../services/api'

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      warning: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
    },
  }
})

const PROVIDER = { id: 'prov_catalog', name: 'NewAPI 上游' }
const OTHER_PROVIDER = { id: 'prov_catalog_2', name: '另一个上游' }

function okResponse<T>(data: T) {
  return { data, status: 200, statusText: 'OK', headers: {}, config: {} } as any
}

function previewPayload(
  candidates: Array<{ catalog_model_id: string; display_name?: string; current_status?: string }>,
  overrides: Record<string, unknown> = {}
) {
  return {
    provider_id: PROVIDER.id,
    candidates: candidates.map((candidate) => ({
      display_name: candidate.display_name ?? candidate.catalog_model_id,
      ...candidate,
    })),
    catalog_unavailable: false,
    catalog_truncated: false,
    current_active: 0,
    max_selection: 200,
    ...overrides,
  }
}

function renderModal(provider = PROVIDER, onClose = vi.fn()) {
  return render(
    <ModelCatalogSyncModal provider={provider} open onClose={onClose} onSynced={vi.fn()} />
  )
}

describe('通用模型目录同步弹窗：勾选语义', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(api.modelApi, 'catalogSyncState').mockResolvedValue(okResponse({ interval_seconds: 3600, status: 'never', result: {} }))
    vi.spyOn(api.modelApi, 'setCatalogSyncInterval').mockResolvedValue(okResponse({ interval_seconds: 0, status: 'never', result: {} }))
  })

  it('列出上游目录并标注每个候选当前的纳入状态', async () => {
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse(previewPayload([
      { catalog_model_id: 'gpt-4o', display_name: 'GPT-4o', current_status: 'active' },
      { catalog_model_id: 'claude-3', current_status: 'disabled' },
      { catalog_model_id: 'qwen-max' },
    ])))

    renderModal()

    expect(await screen.findByText('GPT-4o')).toBeInTheDocument()
    expect(screen.getByText('已纳入')).toBeInTheDocument()
    expect(screen.getByText('已停用')).toBeInTheDocument()
    expect(screen.getByText('未纳入')).toBeInTheDocument()
    expect(screen.getByText('已勾选 0/200')).toBeInTheDocument()
  })

  it('未勾选任何模型时不能提交', async () => {
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse(previewPayload([
      { catalog_model_id: 'gpt-4o' },
    ])))
    const sync = vi.spyOn(api.modelApi, 'sync').mockResolvedValue(okResponse({}))

    renderModal()

    const submit = await screen.findByRole('button', { name: /同步已选 0 个模型/ })
    expect(submit).toBeDisabled()
    expect(sync).not.toHaveBeenCalled()
  })

  it('勾选数量达到服务端上限时给出提示，且不再选中', async () => {
    const { message } = await import('antd')
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse(previewPayload([
      { catalog_model_id: 'gpt-4o' },
      { catalog_model_id: 'claude-3' },
      { catalog_model_id: 'qwen-max' },
    ], { max_selection: 2 })))

    renderModal()

    await userEvent.click(await screen.findByRole('checkbox', { name: '选择 gpt-4o' }))
    await userEvent.click(screen.getByRole('checkbox', { name: '选择 claude-3' }))
    await userEvent.click(screen.getByRole('checkbox', { name: '选择 qwen-max' }))

    expect(message.warning).toHaveBeenCalledWith('每次最多选择 2 个模型')
    expect(screen.getByRole('checkbox', { name: '选择 qwen-max' })).not.toBeChecked()
    expect(screen.getByText('已勾选 2/2')).toBeInTheDocument()
  })

  it('目录比单次上限大时，全选照样勾到上限并说清还剩多少', async () => {
    const { message } = await import('antd')
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse(previewPayload(
      Array.from({ length: 5 }, (_, index) => ({ catalog_model_id: `model-${index}` })),
      { max_selection: 3 }
    )))

    renderModal()

    await screen.findByRole('checkbox', { name: '选择 model-0' })
    await userEvent.click(screen.getByRole('checkbox', { name: '全选当前筛选结果' }))

    expect(screen.getByText('已勾选 3/3')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '选择 model-0' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: '选择 model-2' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: '选择 model-3' })).not.toBeChecked()
    expect(message.warning).toHaveBeenCalledWith(expect.stringContaining('还有 2 个未勾选'))
  })

  it('表头全选只作用于当前筛选结果，不会选中看不到的行', async () => {
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse(previewPayload([
      { catalog_model_id: 'gpt-4o' },
      { catalog_model_id: 'claude-3' },
      { catalog_model_id: 'qwen-max' },
    ])))

    renderModal()

    await screen.findByRole('checkbox', { name: '选择 gpt-4o' })
    await userEvent.type(screen.getByRole('searchbox'), 'gpt')
    await userEvent.click(screen.getByRole('checkbox', { name: '全选当前筛选结果' }))

    expect(screen.getByRole('checkbox', { name: '选择 gpt-4o' })).toBeChecked()
    expect(screen.getByText('已勾选 1/200')).toBeInTheDocument()

    await userEvent.clear(screen.getByRole('searchbox'))
    expect(await screen.findByRole('checkbox', { name: '选择 claude-3' })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: '选择 qwen-max' })).not.toBeChecked()
  })

  it('目录被截断时明确告知，避免管理员以为上游只有这些模型', async () => {
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse(previewPayload(
      [{ catalog_model_id: 'gpt-4o' }],
      { catalog_truncated: true }
    )))

    renderModal()

    expect(await screen.findByText(/仅展示前 2000 条/)).toBeInTheDocument()
  })

  it('渠道切换后丢弃上一个渠道的晚到目录响应', async () => {
    let resolveFirst: (value: any) => void = () => undefined
    const first = new Promise((resolve) => { resolveFirst = resolve })
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockImplementation((providerID: string) => {
      if (providerID === PROVIDER.id) return first as any
      return Promise.resolve(okResponse({
        ...previewPayload([{ catalog_model_id: 'second-provider-model' }]),
        provider_id: OTHER_PROVIDER.id,
      })) as any
    })

    const { rerender } = renderModal()
    rerender(<ModelCatalogSyncModal provider={OTHER_PROVIDER} open onClose={vi.fn()} onSynced={vi.fn()} />)

    expect(await screen.findByRole('checkbox', { name: '选择 second-provider-model' })).toBeInTheDocument()

    resolveFirst(okResponse(previewPayload([{ catalog_model_id: 'stale-first-provider-model' }])))
    await waitFor(() => {
      expect(screen.queryByRole('checkbox', { name: '选择 stale-first-provider-model' })).not.toBeInTheDocument()
    })
    expect(screen.getByRole('checkbox', { name: '选择 second-provider-model' })).toBeInTheDocument()
  })

  it('目录请求失败时提示可全量同步，而不是把上一次的候选留在界面上', async () => {
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockRejectedValue({
      isAxiosError: true,
      response: { status: 502, data: { error: { code: 'catalog_unavailable', message: '无法读取上游模型目录' } } },
    })

    renderModal()

    expect(await screen.findByText('无法读取上游模型目录')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试同步' })).toBeInTheDocument()
  })
  it('不勾选新模型也能刷新完整目录并显示移除回执', async () => {
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse(previewPayload([])))
    const sync = vi.spyOn(api.modelApi, 'sync').mockResolvedValue(okResponse({ provider_id: PROVIDER.id, created: 0, updated: 1, deactivated: 2, skipped: 0, reappeared: 0 }))
    renderModal()
    await waitFor(() => expect(screen.getByRole('button', { name: '刷新目录并清理失效模型' })).not.toBeDisabled())
    await userEvent.click(screen.getByRole('button', { name: '刷新目录并清理失效模型' }))
    await waitFor(() => expect(sync).toHaveBeenCalledWith(PROVIDER.id, undefined))
    expect(await screen.findByText(/移除 2/)).toBeInTheDocument()
  })

  it('协议探测失败显示具体原因，并与目录下架区分', async () => {
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse(previewPayload([{catalog_model_id:'gpt-4o'}])))
    vi.spyOn(api.modelApi, 'sync').mockResolvedValue(okResponse({ provider_id: PROVIDER.id, created: 0, updated: 1, deactivated: 0, skipped: 0, verification_failed: 1, verification_failures: [{model_id:'m1',upstream_model_id:'gpt-4o',reason:'timeout'}] }))
    renderModal()
    await userEvent.click(await screen.findByRole('checkbox', { name: '选择 gpt-4o' }))
    await userEvent.click(screen.getByRole('button', { name: /同步已选 1 个模型/ }))
    expect(await screen.findByText('目录已同步，部分模型验证失败')).toBeInTheDocument()
    expect(screen.getByText(/探测超时.*不会认定为下架/)).toBeInTheDocument()
  })

})
