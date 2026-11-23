import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { message } from 'antd'
import Apps from '../pages/Apps'
import * as api from '../services/api'

vi.mock('antd', async () => { const a = await vi.importActual('antd'); return { ...a, message: { success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() } } })

// 控制台巡检（11-10）：别的页面带着参数跳到应用管理，页面以前只认 project_id：
//   - 部门“应用”标签页里点应用名 → /apps?highlight=…（不认，白点一下）
//   - 同处的“新建应用” → /apps?team_id=…（不认，只是回到应用列表）
//   - 指向已删除/不存在的应用 → 什么都不发生，也没有任何提示
describe('应用管理 — 深链接', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: { data: [{ id: 'proj_001', name: '客服助手', code: 'support', status: 'active', environment: 'production' }] } } as any)
    vi.spyOn(api.projectApi, 'get').mockResolvedValue({ data: { id: 'proj_001', name: '客服助手', team_id: 'team_rd', model_whitelist: ['gpt-4o'], quota_limits: {} } } as any)
    vi.spyOn(api.projectApi, 'listUsers').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.modelApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [{ id: 'team_rd', name: '研发部' }] } } as any)
  })

  const renderApps = (url: string) => render(
    <MemoryRouter initialEntries={[url]}>
      <QueryClientProvider client={queryClient}><Apps /></QueryClientProvider>
    </MemoryRouter>,
  )

  it('highlight 参数打开对应应用的抽屉', async () => {
    renderApps('/apps?highlight=proj_001')

    await waitFor(() => expect(api.projectApi.get).toHaveBeenCalledWith('proj_001'))
    expect(await screen.findByText('基本信息')).toBeInTheDocument()
    expect(message.info).not.toHaveBeenCalled()
  })

  it('指向不存在或已删除的应用时明说，不开抽屉', async () => {
    renderApps('/apps?project_id=proj_gone')

    await waitFor(() => expect(message.info).toHaveBeenCalledWith('该应用已不存在'))
    expect(api.projectApi.get).not.toHaveBeenCalled()
    expect(screen.queryByText('基本信息')).not.toBeInTheDocument()
  })

  it('team_id 参数直接打开新建应用窗口并选好所属部门', async () => {
    renderApps('/apps?team_id=team_rd')

    expect(await screen.findByRole('dialog', { name: '新建应用' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getAllByText('研发部').length).toBeGreaterThan(0))
  })

  it('不带参数时不弹任何东西', async () => {
    renderApps('/apps')

    expect(await screen.findByText('客服助手')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(message.info).not.toHaveBeenCalled()
  })
})
