import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Providers from '../pages/Providers'
import AzureModelSyncModal from '../components/providers/AzureModelSyncModal'
import * as api from '../services/api'

// Mock antd message
vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      warning: vi.fn(),
      error: vi.fn(),
    },
  }
})

const OPENAI_PROVIDER = {
  id: 'prov_test_123',
  name: 'Test OpenAI',
  provider_type: 'openai',
  base_url: 'https://api.openai.com',
  has_credential: true,
  status: 'active',
}

function okResponse<T>(data: T) {
  return { data, status: 200, statusText: 'OK', headers: {}, config: {} } as any
}

function mockProviderList(providers: Array<Record<string, unknown>>) {
  vi.spyOn(api.providerApi, 'list').mockResolvedValue(okResponse({ data: providers }))
}

function mockCatalogPreview(candidates: Array<{ catalog_model_id: string; display_name: string; current_status?: string }>) {
  return vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse({
    provider_id: OPENAI_PROVIDER.id,
    candidates,
    catalog_unavailable: false,
    catalog_truncated: false,
    current_active: 0,
    max_selection: 200,
  }))
}

function mockSyncResult(overrides: Record<string, unknown> = {}) {
  return vi.spyOn(api.modelApi, 'sync').mockResolvedValue(okResponse({
    provider_id: OPENAI_PROVIDER.id,
    total_seen: 2,
    created: 1,
    updated: 1,
    deactivated: 0,
    skipped: 0,
    verified: 2,
    verification_failed: 0,
    ...overrides,
  }))
}

describe('Providers page: models sync behavior', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
  })

  const renderProviders = () => {
    return render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <Providers />
        </QueryClientProvider>
      </MemoryRouter>
    )
  }

  it('窄屏操作列取消固定并允许按钮换行', async () => {
    vi.spyOn(api.providerApi, 'list').mockResolvedValue({
      data: {
        data: [{
          id: 'prov_mobile_001',
          name: '窄屏测试渠道',
          provider_type: 'openai',
          base_url: 'https://api.mobile.example.com',
          has_credential: true,
          status: 'active',
        }],
      },
    } as any)

    renderProviders()

    await screen.findByText('窄屏测试渠道')
    const actionHeader = await screen.findByRole('columnheader', { name: '操作' })
    expect(actionHeader).not.toHaveClass('ant-table-cell-fix-right')

    const syncButton = screen.getByRole('button', { name: /同步模型/i })
    expect(syncButton.closest('.ant-space')).toHaveStyle({ flexWrap: 'wrap' })
  })

  it('Azure 点击同步只打开验证弹窗，不调用旧同步接口', async () => {
    vi.spyOn(api.providerApi, 'list').mockResolvedValue({
      data: {
        data: [{
          id: 'prov_azure_001',
          name: 'Microsoft Azure',
          provider_type: 'azure',
          base_url: 'https://example.openai.azure.com',
          has_credential: true,
          status: 'active',
        }],
      },
    } as any)
    const legacySync = vi.spyOn(api.modelApi, 'sync').mockResolvedValue({ data: {} } as any)

    renderProviders()

    await userEvent.click(await screen.findByRole('button', { name: /同步模型/i }))

    expect(await screen.findByRole('dialog', { name: /Azure 模型验证同步/i })).toBeInTheDocument()
    expect(legacySync).not.toHaveBeenCalled()
  })

  // 管理员要能先看到上游目录再决定同步哪些模型，而不是一点按钮就全量同步 1～5 分钟。
  it('非 Azure 渠道点击同步模型先拉候选目录并打开勾选弹窗，不直接同步', async () => {
    mockProviderList([OPENAI_PROVIDER])
    const preview = mockCatalogPreview([
      { catalog_model_id: 'gpt-4o', display_name: 'GPT-4o' },
      { catalog_model_id: 'gpt-3.5-turbo', display_name: 'gpt-3.5-turbo' },
    ])
    const sync = mockSyncResult()

    renderProviders()

    await userEvent.click(await screen.findByRole('button', { name: /同步模型/i }))

    expect(await screen.findByRole('dialog', { name: /选择要同步的模型/i })).toBeInTheDocument()
    await waitFor(() => expect(preview).toHaveBeenCalledWith(OPENAI_PROVIDER.id))
    expect(await screen.findByText('gpt-4o')).toBeInTheDocument()
    expect(sync).not.toHaveBeenCalled()
  })

  it('确认后只把勾选的模型标识传给同步接口', async () => {
    mockProviderList([OPENAI_PROVIDER])
    mockCatalogPreview([
      { catalog_model_id: 'gpt-4o', display_name: 'GPT-4o' },
      { catalog_model_id: 'gpt-3.5-turbo', display_name: 'gpt-3.5-turbo', current_status: 'active' },
    ])
    const sync = mockSyncResult()

    renderProviders()

    await userEvent.click(await screen.findByRole('button', { name: /同步模型/i }))
    await userEvent.click(await screen.findByRole('checkbox', { name: '选择 gpt-4o' }))
    await userEvent.click(screen.getByRole('button', { name: /同步已选 1 个模型/ }))

    await waitFor(() => {
      expect(sync).toHaveBeenCalledWith(OPENAI_PROVIDER.id, ['gpt-4o'])
    })
  })

  it('同步回执显示沿用验证的模型数', async () => {
    const { message } = await import('antd')
    mockProviderList([OPENAI_PROVIDER])
    mockCatalogPreview([{ catalog_model_id: 'gpt-4o', display_name: 'GPT-4o' }])
    mockSyncResult({ created: 0, updated: 5, verified: 1, reused: 4, verification_failed: 0 })

    renderProviders()

    await userEvent.click(await screen.findByRole('button', { name: /同步模型/i }))
    await userEvent.click(await screen.findByRole('checkbox', { name: '选择 gpt-4o' }))
    await userEvent.click(screen.getByRole('button', { name: /同步已选 1 个模型/ }))

    await waitFor(() => {
      expect(message.success).toHaveBeenCalledWith(expect.stringContaining('沿用验证 4'))
    })
    expect(await screen.findByText(/协议验证 1，沿用验证 4/)).toBeInTheDocument()
  })

  it('部分模型验证失败时显示警告并刷新模型列表缓存', async () => {
    const { message } = await import('antd')
    mockProviderList([OPENAI_PROVIDER])
    mockCatalogPreview([{ catalog_model_id: 'gpt-4o', display_name: 'GPT-4o' }])
    mockSyncResult({ created: 3, updated: 11, verified: 14, verification_failed: 1 })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')

    renderProviders()

    await userEvent.click(await screen.findByRole('button', { name: /同步模型/i }))
    await userEvent.click(await screen.findByRole('checkbox', { name: '选择 gpt-4o' }))
    await userEvent.click(screen.getByRole('button', { name: /同步已选 1 个模型/ }))

    await waitFor(() => {
      expect(message.warning).toHaveBeenCalledWith(expect.stringContaining('新增 3'))
    })
    expect(message.warning).toHaveBeenCalledWith(expect.stringContaining('更新 11'))
    expect(message.error).not.toHaveBeenCalled()
    expect(message.success).not.toHaveBeenCalled()
    expect(message.warning).toHaveBeenCalledWith(expect.stringContaining('部分模型验证失败'))
    await waitFor(() => {
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ['models'] })
    })
  })
})

type VerifiedSyncMocks = {
  previewVerifiedSync: ReturnType<typeof vi.fn>
  verifySyncCandidates: ReturnType<typeof vi.fn>
  commitVerifiedSync: ReturnType<typeof vi.fn>
}

function mockAzureVerifiedApis(previewData: Record<string, unknown>) {
  const mocks: VerifiedSyncMocks = {
    previewVerifiedSync: vi.fn().mockResolvedValue({ data: previewData }),
    verifySyncCandidates: vi.fn(),
    commitVerifiedSync: vi.fn().mockResolvedValue({
      data: { provider_id: 'prov_azure_verified', created: 1, updated: 0, reactivated: 0, deactivated: 0 },
    }),
  }
  Object.assign(api.modelApi, mocks)
  return mocks
}

function preview(candidates: Array<Record<string, unknown>>, extra: Record<string, unknown> = {}) {
  return {
    provider_id: 'prov_azure_verified',
    candidates,
    catalog_unavailable: false,
    catalog_truncated: false,
    current_active: candidates.filter((item) => item.current_status === 'active').length,
    ...extra,
  }
}

// 按请求内容逐条回成功凭证，失败表里的部署按指定原因失败。
function echoVerify(failures: Record<string, string> = {}) {
  return (_providerID: string, items: Array<{ catalog_model_id: string; deployment_name: string }>) => Promise.resolve({
    data: {
      provider_id: 'prov_azure_verified',
      results: items.map((item) => failures[item.catalog_model_id]
        ? { catalog_model_id: item.catalog_model_id, deployment_name: item.deployment_name, status: 'failed', error_kind: failures[item.catalog_model_id], proof_token: `bad-${item.catalog_model_id}` }
        : { catalog_model_id: item.catalog_model_id, deployment_name: item.deployment_name, status: 'success', proof_token: `token-${item.catalog_model_id}`, expires_at: '2099-01-01T00:00:00Z' }),
    },
  })
}

describe('Azure verified model sync dialog', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
    vi.spyOn(api.providerApi, 'list').mockResolvedValue({
      data: {
        data: [{
          id: 'prov_azure_verified',
          name: 'Azure 生产渠道',
          provider_type: 'azure',
          base_url: 'https://example.openai.azure.com',
          has_credential: true,
          status: 'active',
        }],
      },
    } as any)
  })

  const openDialog = async () => {
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <Providers />
        </QueryClientProvider>
      </MemoryRouter>
    )
    await userEvent.click(await screen.findByRole('button', { name: /同步模型/i }))
    return screen.findByRole('dialog', { name: /Azure 模型验证同步/i })
  }

  it('只验证勾选项并使用编辑后的部署名称，成功后直接启用，不再有确认步骤', async () => {
    const mocks = mockAzureVerifiedApis(preview([
      { catalog_model_id: 'gpt-a', display_name: 'GPT A', deployment_name: 'gpt-a', current_status: 'active' },
      { catalog_model_id: 'gpt-b', display_name: 'GPT B', deployment_name: 'gpt-b' },
    ]))
    mocks.verifySyncCandidates.mockImplementation(echoVerify())

    await openDialog()
    await userEvent.click(await screen.findByRole('checkbox', { name: '选择 gpt-b' }))
    const deployment = screen.getByRole('textbox', { name: 'gpt-b 部署名称' })
    await userEvent.clear(deployment)
    await userEvent.type(deployment, 'customer-gpt-b')
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 1 个/ }))

    await waitFor(() => {
      expect(mocks.commitVerifiedSync).toHaveBeenCalledWith('prov_azure_verified', ['token-gpt-b'])
    })
    expect(mocks.verifySyncCandidates).toHaveBeenCalledWith('prov_azure_verified', [
      { catalog_model_id: 'gpt-b', deployment_name: 'customer-gpt-b' },
    ])
    expect(await screen.findByText('已启用 1 个')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '选择 gpt-b' })).not.toBeChecked()
    expect(screen.getByRole('button', { name: /验证并启用 0 个/ })).toBeDisabled()
    expect(screen.queryByRole('dialog', { name: /确认/ })).not.toBeInTheDocument()
  })

  it('部分失败时只提交成功凭证，已启用模型验证失败仍保持启用，失败项保留勾选便于重试', async () => {
    const mocks = mockAzureVerifiedApis(preview([
      { catalog_model_id: 'gpt-ok', display_name: 'GPT OK', deployment_name: 'deployment-ok' },
      { catalog_model_id: 'gpt-old', display_name: 'GPT Old', deployment_name: 'deployment-old', current_status: 'active' },
    ]))
    mocks.verifySyncCandidates.mockImplementation(echoVerify({ 'gpt-old': 'not_deployed' }))

    await openDialog()
    await userEvent.click(await screen.findByRole('checkbox', { name: '全选当前筛选结果' }))
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 2 个/ }))

    expect(await screen.findByText('已启用 1 个，1 个失败，原状态不变')).toBeInTheDocument()
    expect(mocks.commitVerifiedSync).toHaveBeenCalledTimes(1)
    expect(mocks.commitVerifiedSync).toHaveBeenCalledWith('prov_azure_verified', ['token-gpt-ok'])
    const commitArguments = JSON.stringify(mocks.commitVerifiedSync.mock.calls[0])
    expect(commitArguments).not.toContain('bad-gpt-old')
    expect(commitArguments).not.toMatch(/tenant_id|api_key|raw_response|catalog_model_id|deployment_name/)
    expect(screen.getByText('部署名称错误或尚未开通')).toBeInTheDocument()
    expect(screen.getByText('仍保持启用')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '选择 gpt-old' })).toBeChecked()
    expect(screen.getByRole('button', { name: /验证并启用 1 个/ })).toBeEnabled()
  })

  it('模型很多时不设 50 个上限，自动分批验证并逐批启用', async () => {
    const candidates = Array.from({ length: 60 }, (_, index) => ({
      catalog_model_id: `model-${String(index).padStart(2, '0')}`,
      display_name: `model-${String(index).padStart(2, '0')}`,
      deployment_name: `deploy-${index}`,
    }))
    const mocks = mockAzureVerifiedApis(preview(candidates))
    mocks.verifySyncCandidates.mockImplementation(echoVerify())

    await openDialog()
    await userEvent.click(await screen.findByRole('checkbox', { name: '全选当前筛选结果' }))
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 60 个/ }))

    expect(await screen.findByText('已启用 60 个')).toBeInTheDocument()
    expect(mocks.verifySyncCandidates).toHaveBeenCalledTimes(8)
    for (const call of mocks.verifySyncCandidates.mock.calls) {
      expect(call[1].length).toBeLessThanOrEqual(8)
    }
    const committed = mocks.commitVerifiedSync.mock.calls.flatMap((call) => call[1])
    expect(committed).toHaveLength(60)
    expect(new Set(committed).size).toBe(60)
  })

  it('点停止后在当前批次结束时停下，剩余部署保持未验证', async () => {
    const candidates = Array.from({ length: 20 }, (_, index) => ({
      catalog_model_id: `stop-${index}`,
      display_name: `stop-${index}`,
      deployment_name: `stop-${index}`,
    }))
    const mocks = mockAzureVerifiedApis(preview(candidates))
    let release: () => void = () => undefined
    mocks.verifySyncCandidates.mockImplementationOnce((providerID: string, items: any[]) => new Promise((resolve) => {
      release = () => resolve(echoVerify()(providerID, items))
    }))
    mocks.verifySyncCandidates.mockImplementation(echoVerify())

    await openDialog()
    await userEvent.click(await screen.findByRole('checkbox', { name: '全选当前筛选结果' }))
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 20 个/ }))
    await waitFor(() => expect(mocks.verifySyncCandidates).toHaveBeenCalledTimes(1))
    await userEvent.click(screen.getByRole("button", { name: /停\s*止/ }))
    release()

    expect(await screen.findByText('已启用 8 个，12 个未验证')).toBeInTheDocument()
    expect(mocks.verifySyncCandidates).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: /验证并启用 12 个/ })).toBeEnabled()
  })

  it('凭据无效时立即中止，不继续调用上游', async () => {
    const candidates = Array.from({ length: 20 }, (_, index) => ({
      catalog_model_id: `auth-${index}`,
      display_name: `auth-${index}`,
      deployment_name: `auth-${index}`,
    }))
    const mocks = mockAzureVerifiedApis(preview(candidates))
    mocks.verifySyncCandidates.mockImplementation(echoVerify(Object.fromEntries(candidates.map((item) => [item.catalog_model_id, 'unauthorized']))))

    await openDialog()
    await userEvent.click(await screen.findByRole('checkbox', { name: '全选当前筛选结果' }))
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 20 个/ }))

    expect(await screen.findByText('已启用 0 个，20 个失败，原状态不变')).toBeInTheDocument()
    expect(mocks.verifySyncCandidates).toHaveBeenCalledTimes(1)
    expect(mocks.commitVerifiedSync).not.toHaveBeenCalled()
  })

  it('按状态筛选并只全选当前筛选结果', async () => {
    mockAzureVerifiedApis(preview([
      { catalog_model_id: 'on-1', display_name: 'on-1', deployment_name: 'on-1', current_status: 'active' },
      { catalog_model_id: 'on-2', display_name: 'on-2', deployment_name: 'on-2', current_status: 'active' },
      { catalog_model_id: 'off-1', display_name: 'off-1', deployment_name: 'off-1' },
    ]))

    await openDialog()
    await screen.findByRole('checkbox', { name: '选择 off-1' })
    await userEvent.click(screen.getByText('已启用 2'))
    expect(screen.queryByRole('checkbox', { name: '选择 off-1' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('checkbox', { name: '全选当前筛选结果' }))
    expect(screen.getByRole('button', { name: /验证并启用 2 个/ })).toBeEnabled()
    await userEvent.click(screen.getByText('全部 3'))
    expect(screen.getByRole('checkbox', { name: '选择 off-1' })).not.toBeChecked()
  })

  it('目录不可用时可手工添加部署并验证启用', async () => {
    const mocks = mockAzureVerifiedApis(preview([], { catalog_unavailable: true }))
    mocks.verifySyncCandidates.mockImplementation(echoVerify())

    await openDialog()
    expect(await screen.findByText(/无法读取 Azure 模型目录/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /手工添加部署/i }))
    await userEvent.type(screen.getByRole('textbox', { name: '模型标识' }), 'gpt-manual')
    await userEvent.type(screen.getByRole('textbox', { name: '部署名称' }), 'deployment-manual')
    await userEvent.click(screen.getByRole('button', { name: /添加并勾选/i }))
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 1 个/ }))

    await waitFor(() => {
      expect(mocks.verifySyncCandidates).toHaveBeenCalledWith('prov_azure_verified', [
        { catalog_model_id: 'gpt-manual', deployment_name: 'deployment-manual' },
      ])
    })
    expect(await screen.findByText('已启用 1 个')).toBeInTheDocument()
  })

  it('验证进行中锁定候选，防止中途改动', async () => {
    const mocks = mockAzureVerifiedApis(preview([
      { catalog_model_id: 'gpt-lock', display_name: 'GPT Lock', deployment_name: 'gpt-lock' },
    ]))
    let release: () => void = () => undefined
    mocks.verifySyncCandidates.mockImplementation((providerID: string, items: any[]) => new Promise((resolve) => {
      release = () => resolve(echoVerify()(providerID, items))
    }))

    await openDialog()
    const checkbox = await screen.findByRole('checkbox', { name: '选择 gpt-lock' })
    const deployment = screen.getByRole('textbox', { name: 'gpt-lock 部署名称' })
    await userEvent.click(checkbox)
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 1 个/ }))

    await waitFor(() => expect(mocks.verifySyncCandidates).toHaveBeenCalledTimes(1))
    expect(checkbox).toBeDisabled()
    expect(deployment).toBeDisabled()
    expect(screen.getByRole('button', { name: /手工添加部署/i })).toBeDisabled()

    release()
    expect(await screen.findByText('已启用 1 个')).toBeInTheDocument()
    expect(checkbox).not.toBeDisabled()
    expect(deployment).not.toBeDisabled()
  })

  it('丢弃已切换渠道的晚到验证结果，不会替旧渠道提交', async () => {
    const mocks = mockAzureVerifiedApis({})
    mocks.previewVerifiedSync.mockImplementation((providerID: string) => Promise.resolve({
      data: {
        provider_id: providerID,
        candidates: [{
          catalog_model_id: 'gpt-shared',
          display_name: providerID === 'provider-a' ? 'Provider A Model' : 'Provider B Model',
          deployment_name: 'shared-deployment',
        }],
        catalog_unavailable: false,
        catalog_truncated: false,
        current_active: 0,
      },
    }))
    let release: () => void = () => undefined
    mocks.verifySyncCandidates.mockImplementation((providerID: string, items: any[]) => new Promise((resolve) => {
      release = () => resolve(echoVerify()(providerID, items))
    }))
    const onClose = vi.fn()
    const onCommitted = vi.fn()

    const view = render(
      <AzureModelSyncModal provider={{ id: 'provider-a', name: 'Azure A' }} open onClose={onClose} onCommitted={onCommitted} />
    )
    await userEvent.click(await screen.findByRole('checkbox', { name: '选择 gpt-shared' }))
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 1 个/ }))
    await waitFor(() => expect(mocks.verifySyncCandidates).toHaveBeenCalledWith('provider-a', expect.any(Array)))

    view.rerender(
      <AzureModelSyncModal provider={{ id: 'provider-b', name: 'Azure B' }} open onClose={onClose} onCommitted={onCommitted} />
    )
    expect(await screen.findByText('Provider B Model')).toBeInTheDocument()
    release()
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(screen.queryByText(/已启用 1 个/)).not.toBeInTheDocument()
    expect(mocks.commitVerifiedSync).not.toHaveBeenCalled()
    expect(onCommitted).not.toHaveBeenCalled()
  })

  it('组件卸载后忽略在途验证的错误回包', async () => {
    const { message } = await import('antd')
    const mocks = mockAzureVerifiedApis(preview([
      { catalog_model_id: 'gpt-unmount', display_name: 'GPT Unmount', deployment_name: 'gpt-unmount' },
    ]))
    let rejectLate: (reason: Error) => void = () => undefined
    mocks.verifySyncCandidates.mockReturnValue(new Promise((_, reject) => { rejectLate = reject }))
    const onCommitted = vi.fn()
    const view = render(
      <AzureModelSyncModal
        provider={{ id: 'provider-unmount', name: 'Azure Unmount' }}
        open
        onClose={vi.fn()}
        onCommitted={onCommitted}
      />
    )
    await userEvent.click(await screen.findByRole('checkbox', { name: '选择 gpt-unmount' }))
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 1 个/ }))
    await waitFor(() => expect(mocks.verifySyncCandidates).toHaveBeenCalledTimes(1))

    view.unmount()
    rejectLate(new Error('late failure'))
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(message.error).not.toHaveBeenCalled()
    expect(onCommitted).not.toHaveBeenCalled()
  })

  it.each([
    { caseName: '渠道配置冲突', commitError: { response: { status: 409, data: { error: { code: 'sync_conflict' } } } } },
    { caseName: '验证凭证失效', commitError: { response: { status: 400, data: { error: { code: 'invalid_verification' } } } } },
  ])('$caseName 时停止后续批次，保留勾选和部署名称以便重试', async ({ commitError }) => {
    const candidates = Array.from({ length: 12 }, (_, index) => ({
      catalog_model_id: `conflict-${index}`,
      display_name: `conflict-${index}`,
      deployment_name: `conflict-${index}`,
    }))
    const mocks = mockAzureVerifiedApis(preview(candidates))
    mocks.verifySyncCandidates.mockImplementation(echoVerify())
    mocks.commitVerifiedSync.mockRejectedValue(commitError)

    await openDialog()
    await userEvent.click(await screen.findByRole('checkbox', { name: '全选当前筛选结果' }))
    await userEvent.click(screen.getByRole('button', { name: /验证并启用 12 个/ }))

    expect(await screen.findByText('已启用 0 个，8 个失败，原状态不变，4 个未验证')).toBeInTheDocument()
    expect(mocks.verifySyncCandidates).toHaveBeenCalledTimes(1)
    expect(screen.getAllByText('渠道配置已变化，请重试').length).toBeGreaterThan(0)
    expect(screen.getByRole('checkbox', { name: '选择 conflict-0' })).toBeChecked()
    expect(screen.getByRole('textbox', { name: 'conflict-0 部署名称' })).toHaveValue('conflict-0')
    expect(screen.getByRole('button', { name: /验证并启用 12 个/ })).toBeEnabled()
  })
})
