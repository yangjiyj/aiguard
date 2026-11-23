import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import ModelQualityView from '../components/ModelQualityView'

const base = { provider_id: 'p1', provider_name: 'examplegw' }
const items = [
  { ...base, model_id: 'luna', model_name: 'gpt-5.6-luna', samples: 27, upstream_samples: 27, upstream_successes: 27, success_rate: 1, first_event_p50_ms: 5304, output_tokens_per_sec_p50: 38.3, p50_ms: 19500, p95_ms: 40600, pre_upstream_p50_ms: 1074 },
  { ...base, model_id: 'sol', model_name: 'gpt-6.1-sol', samples: 17, upstream_samples: 17, upstream_successes: 15, success_rate: 15 / 17, http_4xx: 2, first_event_p50_ms: 7941, output_tokens_per_sec_p50: 21.5 },
  { ...base, model_id: 'sonnet', model_name: 'claude-sonnet-5-5', samples: 14, upstream_samples: 14, upstream_successes: 12, success_rate: 12 / 14, http_5xx: 2, first_event_p50_ms: 8527, output_tokens_per_sec_p50: 64.5 },
  { ...base, model_id: 'g6', model_name: 'gpt-6-luna', samples: 3, upstream_samples: 3, upstream_successes: 1, success_rate: 1 / 3 },
  { ...base, model_id: 'opus', model_name: 'claude-opus-5-5', samples: 0 },
  { provider_id: '', model_id: '', samples: 100, upstream_samples: 100, upstream_successes: 98, success_rate: 0.98, http_4xx: 2 },
]

describe('quality cards', () => {
  it('names the availability problem, ranks speed and latency, and drops vague verdicts', () => {
    render(<ModelQualityView items={items} loading={false} columns={[]} onDiagnose={() => {}} windowHours={24} />)
    const luna = screen.getByLabelText('gpt-5.6-luna 真实流量质量')
    expect(luna).not.toHaveAttribute('data-flag')
    expect(within(luna).getByText('最快 · 1/3')).toBeInTheDocument()
    expect(within(luna).getByText('2/3')).toBeInTheDocument()
    const sol = screen.getByLabelText('gpt-6.1-sol 真实流量质量')
    expect(sol).toHaveAttribute('data-flag', 'bad')
    expect(within(sol).getAllByText('可用率 88.2%').length).toBeGreaterThan(0)
    expect(within(sol).getByText('15 / 17 · 4xx 2')).toBeInTheDocument()
    expect(screen.getByText('近 24 小时 3 次请求，样本不足')).toBeInTheDocument()
    expect(screen.getByText('近 24 小时无请求')).toBeInTheDocument()
    const unrec = screen.getByLabelText('未识别模型')
    expect(within(unrec).getByText('100 次请求')).toBeInTheDocument()
    expect(within(unrec).getByText('可用率 98.0%')).toBeInTheDocument()
    for (const vague of ['较差', '偏慢', '良好', '未知模型', '未知上游']) expect(screen.queryByText(new RegExp(vague))).toBeNull()
  })
})
