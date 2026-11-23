import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Anomalies from '../pages/Anomalies'
import { anomalyApi } from '../services/api'

vi.mock('../services/api', () => ({
  anomalyApi: {
    list: vi.fn().mockResolvedValue({
      data: {
        data: [
          {
            ID: 'anom_01',
            DetectedDate: '2026-05-28',
            Dimension: 'absolute_spike',
            ScopeType: '',
            ScopeID: '',
            Baseline: 100.0,
            Actual: 850.0,
            Severity: 'high',
            DetailJSON: {
              threshold: 320,
              ratio: 8.5,
            },
            AckedAt: null,
          },
        ],
      },
    }),
    ack: vi.fn().mockResolvedValue({ data: {} }),
  },
}))

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  )
}

describe('Anomalies page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders customer-facing anomaly analysis content', async () => {
    render(<Anomalies />, { wrapper: makeWrapper() })

    expect(await screen.findByText('异常分析')).toBeInTheDocument()
    expect(await screen.findByText('用量突增')).toBeInTheDocument()
    expect(screen.getByText('异常研判过程')).toBeInTheDocument()
    expect(screen.getByText('计算偏离程度')).toBeInTheDocument()
    expect((await screen.findAllByText('全局租户')).length).toBeGreaterThan(0)
    expect((await screen.findAllByText(/当前值约为基线的 8.5 倍/)).length).toBeGreaterThan(0)
    expect(screen.getAllByText('立即确认费用来源').length).toBeGreaterThan(0)
    expect(screen.queryByText('absolute_spike')).not.toBeInTheDocument()
    expect(screen.queryByText('key_surge')).not.toBeInTheDocument()
    expect(screen.queryByText(/Key/)).not.toBeInTheDocument()
  })

  it('passes numeric range expected by backend', async () => {
    render(<Anomalies />, { wrapper: makeWrapper() })

    expect(await screen.findByText('异常分析')).toBeInTheDocument()
    expect(vi.mocked(anomalyApi.list).mock.calls[0][0]).toMatchObject({ range: '30' })
    expect(screen.getByText(/全部类型/)).toBeTruthy()
  })
})
