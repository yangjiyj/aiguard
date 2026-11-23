import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ModelCatalogSyncModal from '../components/providers/ModelCatalogSyncModal'
import * as api from '../services/api'
import { MODEL_SYNC_TIMEOUT_MS, apiClient } from '../services/api'

// 模型同步的后端预算由 control-plane 的 modelSyncControlPlaneRequestTimeout 决定
// （10 分钟）。前端必须与之对齐，否则会在后台仍在同步时误报「同步失败」。
// 现场证据：验收 VM 上后台 68～99 秒才返回 200，浏览器却在 30 秒弹失败。
const CONTROL_PLANE_MODEL_SYNC_BUDGET_MS = 10 * 60 * 1000

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

const PROVIDER = {
  id: 'prov_sync_timeout',
  name: '慢速同步渠道',
}

function okResponse<T>(data: T) {
  return { data, status: 200, statusText: 'OK', headers: {}, config: {} } as any
}

function mockCandidates(ids: string[]) {
  return vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse({
    provider_id: PROVIDER.id,
    candidates: ids.map((id) => ({ catalog_model_id: id, display_name: id })),
    catalog_unavailable: false,
    catalog_truncated: false,
    current_active: 0,
    max_selection: 200,
  }))
}

function renderModal(onSynced = vi.fn()) {
  return render(
    <ModelCatalogSyncModal
      provider={PROVIDER}
      open
      onClose={() => undefined}
      onSynced={onSynced}
    />
  )
}

async function selectAndSubmit(catalogModelID: string) {
  await userEvent.click(await screen.findByRole('checkbox', { name: `选择 ${catalogModelID}` }))
  return screen.getByRole('button', { name: /同步已选 1 个模型/ })
}

// antd 的 loading 按钮不加 disabled 属性，只加 ant-btn-loading 并挡住点击，
// 因此"处理中"要按 loading 状态断言，并由"重复点击不产生新请求"兜住真实并发语义。
function expectProcessing(button: HTMLElement) {
  expect(button.className).toContain('ant-btn-loading')
}

describe('模型目录同步：前后端超时预算对齐', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('modelApi.sync 与候选目录接口使用与后端一致的独立超时预算，且不放宽全局管理 API 预算', () => {
    expect(MODEL_SYNC_TIMEOUT_MS).toBe(CONTROL_PLANE_MODEL_SYNC_BUDGET_MS)

    const post = vi.spyOn(apiClient, 'post').mockResolvedValue(okResponse({}))
    api.modelApi.sync('prov_sync_timeout')
    api.modelApi.previewCatalogSync('prov_sync_timeout')

    expect(post).toHaveBeenCalledWith(
      '/models/sync',
      { provider_id: 'prov_sync_timeout' },
      expect.objectContaining({ timeout: CONTROL_PLANE_MODEL_SYNC_BUDGET_MS })
    )
    expect(post).toHaveBeenCalledWith(
      '/models/sync/candidates',
      { provider_id: 'prov_sync_timeout' },
      expect.objectContaining({ timeout: CONTROL_PLANE_MODEL_SYNC_BUDGET_MS })
    )
    // 全局默认仍是 30 秒：不能因为同步慢就放宽所有普通管理 API。
    expect(apiClient.defaults.timeout).toBe(30000)
  })

  it('耗时超过 30 秒但在预算内成功：全程保持处理中，不出现同步失败', async () => {
    const { message } = await import('antd')
    mockCandidates(['gpt-4o'])
    let resolveSync: (value: any) => void = () => undefined
    vi.spyOn(api.modelApi, 'sync').mockReturnValue(
      new Promise((resolve) => {
        resolveSync = resolve
      }) as any
    )
    const onSynced = vi.fn()

    renderModal(onSynced)
    const submit = await selectAndSubmit('gpt-4o')
    await userEvent.click(submit)

    // 后台仍在跑：按钮保持 loading/disabled，且不得提前判定失败。
    await waitFor(() => expectProcessing(submit))
    expect(message.error).not.toHaveBeenCalled()

    resolveSync(okResponse({
      provider_id: PROVIDER.id,
      total_seen: 15,
      created: 3,
      updated: 11,
      deactivated: 0,
      skipped: 0,
      verified: 14,
      verification_failed: 1,
    }))

    expect(await screen.findByText('目录已同步，部分模型验证失败')).toBeInTheDocument()
    expect(message.error).not.toHaveBeenCalled()
    expect(onSynced).toHaveBeenCalledWith(expect.objectContaining({ created: 3, updated: 11 }))
  })

  it('同步 pending 期间不能重复提交，避免并发同步', async () => {
    mockCandidates(['gpt-4o'])
    const sync = vi.spyOn(api.modelApi, 'sync').mockReturnValue(new Promise(() => undefined) as any)

    renderModal()
    const submit = await selectAndSubmit('gpt-4o')
    await userEvent.click(submit)

    await waitFor(() => expect(sync).toHaveBeenCalledTimes(1))
    await waitFor(() => expectProcessing(submit))

    // 管理员因为迟迟没结果而反复点击，不应再产生并发请求。
    await userEvent.click(submit)
    await userEvent.click(submit)
    expect(sync).toHaveBeenCalledTimes(1)
  })

  it('真正达到同步专用超时：提示后台可能仍在同步，不笼统说失败', async () => {
    const { message } = await import('antd')
    mockCandidates(['gpt-4o'])
    // axios 超时的真实形态：code=ECONNABORTED，无 response。
    vi.spyOn(api.modelApi, 'sync').mockRejectedValue({
      code: 'ECONNABORTED',
      message: `timeout of ${CONTROL_PLANE_MODEL_SYNC_BUDGET_MS}ms exceeded`,
      isAxiosError: true,
    })

    renderModal()
    await userEvent.click(await selectAndSubmit('gpt-4o'))

    await waitFor(() => {
      expect(message.warning).toHaveBeenCalledWith(expect.stringContaining('后台'))
    })
    const warned = (message.warning as any).mock.calls.flat().join(' ')
    expect(warned).toMatch(/稍后刷新/)
    expect(message.error).not.toHaveBeenCalledWith('同步失败')
  })

  it('HTTP 4xx/5xx 仍显示后端可读错误，不被统一映射成超时提示', async () => {
    const { message } = await import('antd')
    mockCandidates(['gpt-4o'])
    vi.spyOn(api.modelApi, 'sync').mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 502,
        data: { error: { code: 'catalog_unavailable', message: '无法读取上游模型目录' } },
      },
    })

    renderModal()
    await userEvent.click(await selectAndSubmit('gpt-4o'))

    await waitFor(() => {
      expect(message.error).toHaveBeenCalledWith('无法读取上游模型目录')
    })
    expect(message.warning).not.toHaveBeenCalled()
  })

  it('provider_unsupported 与 sync_in_progress 仍走精确提示', async () => {
    const { message } = await import('antd')
    mockCandidates(['gpt-4o'])
    const sync = vi.spyOn(api.modelApi, 'sync').mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 400,
        data: { error: { code: 'provider_unsupported', message: 'provider does not support model catalog fetch' } },
      },
    })

    renderModal()
    await userEvent.click(await selectAndSubmit('gpt-4o'))

    await waitFor(() => {
      expect(message.warning).toHaveBeenCalledWith('该渠道不支持模型目录同步')
    })
    expect(message.error).not.toHaveBeenCalled()

    sync.mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 409,
        data: { error: { code: 'sync_in_progress', message: '该渠道正在同步模型，请等待完成后重试' } },
      },
    })
    await userEvent.click(screen.getByRole('button', { name: /同步已选 1 个模型/ }))

    await waitFor(() => {
      expect(message.warning).toHaveBeenCalledWith('该渠道正在同步，请等待完成后重试')
    })
  })

  it('目录不可用时提供全量同步兜底，且请求不携带勾选参数', async () => {
    vi.spyOn(api.modelApi, 'previewCatalogSync').mockResolvedValue(okResponse({
      provider_id: PROVIDER.id,
      candidates: [],
      catalog_unavailable: true,
      catalog_truncated: false,
      current_active: 0,
      max_selection: 200,
    }))
    const sync = vi.spyOn(api.modelApi, 'sync').mockResolvedValue(okResponse({
      provider_id: PROVIDER.id,
      total_seen: 15,
      created: 15,
      updated: 0,
      deactivated: 0,
      skipped: 0,
    }))

    renderModal()
    await userEvent.click(await screen.findByRole('button', { name: '重试同步' }))

    await waitFor(() => expect(sync).toHaveBeenCalledWith(PROVIDER.id, undefined))
  })

  it('同步提示与请求不携带 endpoint、API Key 等敏感信息', async () => {
    const { message } = await import('antd')
    mockCandidates(['gpt-4o'])
    const sync = vi.spyOn(api.modelApi, 'sync').mockResolvedValue(okResponse({
      provider_id: PROVIDER.id,
      total_seen: 1,
      created: 1,
      updated: 0,
      deactivated: 0,
      skipped: 0,
    }))

    renderModal()
    await userEvent.click(await selectAndSubmit('gpt-4o'))

    await waitFor(() => expect(sync).toHaveBeenCalled())
    const emitted = JSON.stringify([
      sync.mock.calls,
      (message.success as any).mock.calls,
      (message.warning as any).mock.calls,
      (message.error as any).mock.calls,
    ])
    expect(emitted).not.toMatch(/https?:\/\//)
    expect(emitted).not.toMatch(/api_key|apiKey|secret|ciphertext|Bearer /i)
  })
})
