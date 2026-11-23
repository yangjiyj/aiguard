import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Keys from '../pages/Keys'
import { keyApi, projectApi, userApi } from '../services/api'

// 控制台巡检（11-10）：用户删除占用清单里的“去处理”跳 /keys?project_id=…&key_id=…，
// 密钥页要把被指的那把密钥直接搜出来；找不到时说清楚；已删除的应用/用户不要把内部 ID 当名字露出来。
vi.mock('../services/api', () => ({
  default: { get: vi.fn().mockResolvedValue({ data: {} }) },
  keyApi: { list: vi.fn(), create: vi.fn(), update: vi.fn(), revoke: vi.fn(), delete: vi.fn(), reveal: vi.fn(), setTrafficClass: vi.fn() },
  budgetApi: { keyReadModel: vi.fn() },
  projectApi: { list: vi.fn() },
  userApi: { list: vi.fn() },
}))

vi.mock('../stores/auth', () => ({
  useAuthStore: () => ({ user: { id: 'admin_1', username: 'admin', role: 'platform_admin' } }),
}))

const key = (id: string, extra: Record<string, unknown> = {}) => ({
  id, project_id: 'proj_live', user_id: 'user_alice', name: `备注-${id}`, key_prefix: `jjd_${id.slice(-4)}`,
  scopes: ['chat'], status: 'active', created_at: '2026-06-08T00:00:00Z', ...extra,
})

function renderKeys(url: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}><Keys /></MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('密钥页 — 从“去处理”带 key_id 进入', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(projectApi.list).mockResolvedValue({ data: { data: [{ id: 'proj_live', name: '在用应用' }] } } as any)
    vi.mocked(userApi.list).mockResolvedValue({ data: { data: [{ id: 'user_alice', username: 'alice' }] } } as any)
  })
  afterEach(() => cleanup())

  it('把被指的密钥直接搜出来，而不是让人在 10 条一页的列表里翻', async () => {
    const many = Array.from({ length: 15 }, (_, i) => key(`key_${String(i).padStart(4, '0')}`))
    vi.mocked(keyApi.list).mockResolvedValue({ data: { data: many } } as any)

    renderKeys('/keys?project_id=proj_live&key_id=key_0012')

    expect(await screen.findByText('备注-key_0012')).toBeInTheDocument()
    expect(screen.queryByText('备注-key_0000')).not.toBeInTheDocument()
    expect(screen.getByPlaceholderText(/搜索 ID/)).toHaveValue('key_0012')
  })

  it('指向的密钥已经不存在时给出明确的空状态', async () => {
    vi.mocked(keyApi.list).mockResolvedValue({ data: { data: [key('key_0001')] } } as any)

    renderKeys('/keys?project_id=proj_live&key_id=key_gone')

    expect(await screen.findByText('没有找到这把密钥，可能已被删除')).toBeInTheDocument()
  })

  it('不带 key_id 时保持原样：列出全部密钥，没有多余的空状态文案', async () => {
    vi.mocked(keyApi.list).mockResolvedValue({ data: { data: [key('key_0001'), key('key_0002')] } } as any)

    renderKeys('/keys')

    expect(await screen.findByText('备注-key_0001')).toBeInTheDocument()
    expect(screen.getByText('备注-key_0002')).toBeInTheDocument()
    expect(screen.queryByText('没有找到这把密钥，可能已被删除')).not.toBeInTheDocument()
  })
})

describe('密钥页 — 已删除的应用和用户', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(projectApi.list).mockResolvedValue({ data: { data: [{ id: 'proj_live', name: '在用应用' }] } } as any)
    vi.mocked(userApi.list).mockResolvedValue({ data: { data: [{ id: 'user_alice', username: 'alice' }] } } as any)
  })
  afterEach(() => cleanup())

  it('写“已删除应用 / 已删除用户”，不露出内部 ID', async () => {
    vi.mocked(keyApi.list).mockResolvedValue({
      data: { data: [key('key_ghost', { status: 'revoked', project_id: 'proj_58d07099abcdef', user_id: '3a85cc35-e8ed-42f9-a9e1-c2180e5d7d3b' })] },
    } as any)

    renderKeys('/keys')

    expect(await screen.findByText('已删除应用')).toBeInTheDocument()
    expect(screen.getByText('已删除用户')).toBeInTheDocument()
    expect(screen.queryByText(/proj_58d07099/)).not.toBeInTheDocument()
    expect(screen.queryByText(/3a85cc35/)).not.toBeInTheDocument()
  })

  it('应用和用户还在时照常显示名称', async () => {
    vi.mocked(keyApi.list).mockResolvedValue({ data: { data: [key('key_ok')] } } as any)

    renderKeys('/keys')

    expect(await screen.findByText('在用应用')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('alice')).toBeInTheDocument())
    expect(screen.queryByText('已删除应用')).not.toBeInTheDocument()
    expect(screen.queryByText('已删除用户')).not.toBeInTheDocument()
  })
})
