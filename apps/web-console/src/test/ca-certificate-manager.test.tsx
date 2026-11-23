import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import CACertificateManager from '../components/CACertificateManager'
import { caApi, type CACertificate } from '../services/api'

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: { success: vi.fn(), warning: vi.fn(), error: vi.fn() },
  }
})

const current: CACertificate = {
  id: 'ca_current',
  tenant_id: 'tenant_demo',
  ca_type: 'root',
  certificate_pem: 'pem',
  status: 'active',
  fingerprint_sha256: '11'.repeat(32),
  created_at: '2026-01-01T00:00:00Z',
  expires_at: '2027-01-01T00:00:00Z',
}

const pending: CACertificate = {
  ...current,
  id: 'ca_pending',
  status: 'pending',
  fingerprint_sha256: '22'.repeat(32),
  created_at: '2026-02-01T00:00:00Z',
}

const deprecated: CACertificate = {
  ...current,
  id: 'ca_deprecated',
  status: 'deprecated',
  fingerprint_sha256: '33'.repeat(32),
  created_at: '2025-01-01T00:00:00Z',
}

const renderManager = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <CACertificateManager />
    </QueryClientProvider>,
  )
}

describe('CACertificateManager', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(caApi, 'list').mockResolvedValue({
      data: { data: [pending, current, deprecated], total: 3 },
    } as any)
  })

  it('separates generation from activation and protects the current CA', async () => {
    vi.spyOn(caApi, 'generate').mockResolvedValue({ data: pending } as any)
    renderManager()

    expect(await screen.findByText('当前正向代理 CA')).toBeInTheDocument()
    expect(screen.getByText('待切换')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '生成待切换 CA' })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '删除' })).toHaveLength(2)

    fireEvent.click(screen.getByRole('button', { name: '生成待切换 CA' }))
    fireEvent.click(await screen.findByRole('button', { name: '生成' }))
    await waitFor(() => expect(caApi.generate).toHaveBeenCalledWith(3650))
  })

  it('requires explicit client-deployment acknowledgement before activation', async () => {
    vi.spyOn(caApi, 'activate').mockResolvedValue({ data: { ...pending, status: 'active' } } as any)
    renderManager()

    fireEvent.click(await screen.findByRole('button', { name: '切换为当前' }))
    const confirm = await screen.findByRole('button', { name: '确认切换' })
    expect(confirm).toBeDisabled()

    fireEvent.click(screen.getByRole('checkbox'))
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)

    await waitFor(() => expect(caApi.activate).toHaveBeenCalledWith('ca_pending'))
  })

  it('bulk-cleans only retired or expired certificates', async () => {
    vi.spyOn(caApi, 'delete').mockResolvedValue({ data: {} } as any)
    renderManager()

    fireEvent.click(await screen.findByRole('button', { name: '清理旧证书 (1)' }))
    fireEvent.click(await screen.findByRole('button', { name: '确认清理' }))

    await waitFor(() => expect(caApi.delete).toHaveBeenCalledTimes(1))
    expect(caApi.delete).toHaveBeenCalledWith('ca_deprecated')
    expect(caApi.delete).not.toHaveBeenCalledWith('ca_current')
    expect(caApi.delete).not.toHaveBeenCalledWith('ca_pending')
  })
})
