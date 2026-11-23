import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuditHmacDefaultKeyBanner, AuditIntegrityStatusLine } from '../components/AuditIntegrityStatus'
import { auditChainApi } from '../services/api'

vi.mock('../services/api', () => ({
  auditChainApi: { integrity: vi.fn() },
}))

const renderLine = () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <AuditIntegrityStatusLine timezone="Asia/Shanghai" />
    </QueryClientProvider>,
  )
}

describe('审计链完整性状态', () => {
  beforeEach(() => vi.clearAllMocks())

  it('显示最近一次校验通过及北京时间', async () => {
    vi.mocked(auditChainApi.integrity).mockResolvedValue({ data: { hmac_default_key: false, verified: true, ok: true, last_verified_at: '2026-10-11T03:00:00Z' } } as any)
    renderLine()
    expect(await screen.findByText('最近一次完整性校验：通过（2026-10-11 11:00:00）')).toBeInTheDocument()
  })

  it('校验失败时显示中文原因和异常序号，不露英文', async () => {
    vi.mocked(auditChainApi.integrity).mockResolvedValue({ data: { hmac_default_key: false, verified: true, ok: false, last_verified_at: '2026-10-11T03:00:00Z', first_break_at_seq: 42, detail: '签名校验失败' } } as any)
    const { container } = renderLine()
    expect(await screen.findByText('最近一次完整性校验：失败（2026-10-11 11:00:00）')).toBeInTheDocument()
    expect(screen.getByText('原因：签名校验失败')).toBeInTheDocument()
    expect(screen.getByText('首个异常记录序号：42')).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/[a-z_]{4,}/)
  })

  it('尚未校验时说明会自动执行', async () => {
    vi.mocked(auditChainApi.integrity).mockResolvedValue({ data: { hmac_default_key: false, verified: false } } as any)
    renderLine()
    expect(await screen.findByText(/尚未执行/)).toBeInTheDocument()
  })

  it('开发默认密钥时显示红色告警条，配置了密钥则不显示', () => {
    const { rerender } = render(<AuditHmacDefaultKeyBanner integrity={{ hmac_default_key: true, verified: false }} />)
    const banner = screen.getByRole('alert')
    expect(banner).toHaveTextContent('审计签名密钥未配置')
    expect(banner.className).toContain('ant-alert-error')
    rerender(<AuditHmacDefaultKeyBanner integrity={{ hmac_default_key: false, verified: true, ok: true }} />)
    expect(screen.queryByText(/审计签名密钥未配置/)).not.toBeInTheDocument()
  })
})
