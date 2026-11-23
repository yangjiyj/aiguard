import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import License from '../pages/License'
import { licenseApi } from '../services/api'

vi.mock('../services/api', () => ({
  licenseApi: {
    status: vi.fn(),
    import: vi.fn(),
  },
}))

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      error: vi.fn(),
    },
  }
})

describe('License page', () => {
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

  const renderPage = () =>
    render(
      <QueryClientProvider client={queryClient}>
        <License />
      </QueryClientProvider>,
    )

  it('renders missing license state', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({
      data: {
        status: 'missing',
        valid: false,
        reason: 'license not imported',
        trial_days: 90,
        public_key_set: true,
      },
    } as any)

    renderPage()

    expect(await screen.findByText('未导入')).toBeInTheDocument()
  })

  it('renders trial license without crashing', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({
      data: {
        status: 'trial',
        valid: true,
        days_left: 88,
        trial_days: 90,
        public_key_set: true,
      },
    } as any)

    renderPage()

    // 不再白屏：试用状态徽章可见。
    expect(await screen.findByText('测试授权')).toBeInTheDocument()
    // 试用是有效运行态：剩余天数应展示（而非 '—'）。页面多处展示天数，用 findAllByText。
    const dayEls = await screen.findAllByText(/88\s*天/)
    expect(dayEls.length).toBeGreaterThan(0)
  })

  it('renders v2 bundle trial details and all licensed features', async () => {
    const features = ['agent_audit', 'content_retention', 'ide_proxy', 'sensitive_data_guard', 'web_ai']
    vi.mocked(licenseApi.status).mockResolvedValue({
      data: {
        status: 'active',
        valid: true,
        days_left: 49,
        trial_days: 90,
        public_key_set: true,
        imported_at: '2026-07-06T10:17:29Z',
        version: 'license.v2',
        key_id: 'bundle-trial-key',
        features,
        payload_v2: {
          schemaVersion: 'license.v2',
          licenseId: 'lic_v2_trial_1783310839',
          customer: { id: 'jjdguard-trial', displayName: 'JJDGUARD 试用授权' },
          subject: { displayName: 'JJDGuard Enterprise License', products: ['newapi-enterprise'] },
          edition: 'enterprise',
          issuedAt: '2026-07-06T06:48:19Z',
          notBefore: '2026-07-06T06:47:19Z',
          expiresAt: '2026-10-04T06:48:19Z',
          maxUsers: 25,
          features,
        },
      },
    } as any)

    renderPage()

    expect(await screen.findByText('5 / 6')).toBeInTheDocument()
    expect(screen.getByText('JJDGUARD 试用授权')).toBeInTheDocument()
    expect(screen.getByText('lic_v2_trial_1783310839')).toBeInTheDocument()
    expect(screen.getAllByText('已启用')).toHaveLength(5)
    expect(screen.getAllByText('测试授权').length).toBeGreaterThan(0)
    expect(screen.queryByText('尚未导入授权，平台运行于未授权状态')).not.toBeInTheDocument()
  })

  it('五项试用授权明确展示未授权的端侧能力', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: {
      status: 'active', valid: true, public_key_set: true,
      features: ['web_ai', 'agent_audit', 'ide_proxy', 'content_retention', 'sensitive_data_guard'],
    } } as any)
    renderPage()
    expect(await screen.findByText('5 / 6')).toBeInTheDocument()
    expect(screen.getByText('端侧智能体安全')).toBeInTheDocument()
    expect(screen.getByText('未授权')).toBeInTheDocument()
    expect(screen.getAllByText('已启用')).toHaveLength(5)
  })

  it('有效端侧授权显示为已启用，而不会被五项目录遗漏', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: {
      status: 'active', valid: true, public_key_set: true,
      features: ['web_ai', 'agent_audit', 'ide_proxy', 'content_retention', 'sensitive_data_guard', 'agent_security'],
    } } as any)
    renderPage()
    expect(await screen.findByText('6 / 6')).toBeInTheDocument()
    expect(screen.getByText('端侧智能体安全')).toBeInTheDocument()
    expect(screen.getAllByText('已启用')).toHaveLength(6)
  })

  it('无效许可证中的能力字段不能显示为已启用', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({ data: {
      status: 'expired', valid: false, public_key_set: true,
      features: ['web_ai', 'agent_audit', 'ide_proxy', 'content_retention', 'sensitive_data_guard', 'agent_security'],
    } } as any)
    renderPage()
    expect(await screen.findByText('已过期')).toBeInTheDocument()
    expect(screen.queryByText('已启用')).not.toBeInTheDocument()
    expect(screen.getAllByText('未授权')).toHaveLength(6)
  })

  it('imports pasted license token through admin API', async () => {
    vi.mocked(licenseApi.status).mockResolvedValue({
      data: {
        status: 'missing',
        valid: false,
        trial_days: 90,
        public_key_set: true,
      },
    } as any)
    vi.mocked(licenseApi.import).mockResolvedValue({
      data: {
        status: 'active',
        valid: true,
        public_key_set: true,
      },
    } as any)

    renderPage()

    const input = await screen.findByPlaceholderText(/"algorithm":"ed25519"/)
    fireEvent.change(input, { target: { value: '{"algorithm":"ed25519"}' } })
    fireEvent.click(screen.getByRole('button', { name: /导入授权/ }))

    await waitFor(() => {
      expect(licenseApi.import).toHaveBeenCalledWith('{"algorithm":"ed25519"}')
    })
  })
})
