import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import userEvent from '@testing-library/user-event'
import Providers from '../pages/Providers'
import * as api from '../services/api'

const ok = (body: any) => ({ data: body, status: 200, statusText: 'OK', headers: {}, config: {} } as any)

// 控制台巡检（11-10）：置灰的按钮一定要讲清楚为什么灰——
//   - 没配凭据的渠道，“验证”按钮置灰，悬停提示只是“验证指定模型”；
//   - Gemini / Vertex / Bedrock 渠道配了凭据，“同步模型”仍然置灰，悬停提示却写“从上游拉取模型目录”。
describe('渠道管理 — 置灰按钮的原因提示', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.modelApi, 'catalogSyncState').mockResolvedValue(ok({ interval_seconds: 3600, status: 'never', result: {} }))
    vi.spyOn(api.providerApi, 'metrics').mockResolvedValue(ok({ data: [], window_minutes: 30 }))
    vi.spyOn(api.providerApi, 'deleted').mockResolvedValue(ok({ items: [] }))
  })

  afterEach(() => {
    vi.restoreAllMocks()
    cleanup()
    document.body.innerHTML = ''
  })

  const renderPage = () => render(
    <MemoryRouter><QueryClientProvider client={queryClient}><Providers /></QueryClientProvider></MemoryRouter>,
  )

  it('没配凭据：验证按钮置灰并说明要先配置凭据', async () => {
    vi.spyOn(api.providerApi, 'list').mockResolvedValue(ok({ data: [{ id: 'p1', name: '无凭据渠道', provider_type: 'openai', base_url: 'https://x', has_credential: false, status: 'active' }], total: 1 }))
    renderPage()

    const verify = await screen.findByRole('button', { name: '验证上游 无凭据渠道' })
    expect(verify).toBeDisabled()
    await userEvent.setup({ pointerEventsCheck: 0 }).hover(verify)
    expect(await screen.findByText('先配置凭据才能验证')).toBeInTheDocument()
  })

  it('Gemini 渠道：同步模型置灰并说明改去模型管理手动添加', async () => {
    vi.spyOn(api.providerApi, 'list').mockResolvedValue(ok({ data: [{ id: 'p2', name: 'Gemini 渠道', provider_type: 'gemini', base_url: 'https://g', has_credential: true, status: 'active' }], total: 1 }))
    renderPage()

    const sync = await screen.findByRole('button', { name: /同步模型/ })
    expect(sync).toBeDisabled()
    await userEvent.setup({ pointerEventsCheck: 0 }).hover(sync)
    await waitFor(() => expect(screen.getByText('该类型的模型请在“模型管理”里手动添加')).toBeInTheDocument())
    expect(screen.queryByText('从上游拉取模型目录，再选择要同步哪些模型')).not.toBeInTheDocument()
  })

  it('OpenAI 渠道配了凭据：同步模型可点，提示不变', async () => {
    vi.spyOn(api.providerApi, 'list').mockResolvedValue(ok({ data: [{ id: 'p3', name: 'OpenAI 渠道', provider_type: 'openai', base_url: 'https://o', has_credential: true, status: 'active' }], total: 1 }))
    renderPage()

    const sync = await screen.findByRole('button', { name: /同步模型/ })
    expect(sync).toBeEnabled()
    await userEvent.hover(sync)
    expect(await screen.findByText('从上游拉取模型目录，再选择要同步哪些模型')).toBeInTheDocument()
  })
})
