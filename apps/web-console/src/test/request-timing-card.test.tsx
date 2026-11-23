import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import RequestTimingCard from '../components/RequestTimingCard'
import type { UsageRecord } from '../services/api'

const record = { latency_ms: 1600, upstream_ttft_ms: 200 } as UsageRecord

describe('请求耗时分解', () => {
  it('显示分段、净网关处理和输出速度，并说明重叠口径', () => {
    render(<RequestTimingCard record={{ ...record, timing: { input_security_ms: 100, pre_upstream_ms: 250, output_security_ms: 80, generation_ms: 1100, output_tokens_per_sec: 32.14 } }} />)
    expect(screen.getByText('耗时分解')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: '分段耗时相对占比' })).toBeInTheDocument()
    expect(screen.getByText('0.15 s')).toBeInTheDocument()
    expect(screen.getByText('32.1 词元/秒')).toBeInTheDocument()
    expect(screen.getByText(/各阶段不能简单相加/)).toBeInTheDocument()
    expect(screen.queryByText('此记录早于分段计时上线')).not.toBeInTheDocument()
  })

  it('旧记录只显示总计和首字，不伪造分段', () => {
    render(<RequestTimingCard record={{ ...record, timing: { latency_ms: 1600, upstream_ttft_ms: 200 } }} />)
    expect(screen.getByText('此记录早于分段计时上线')).toBeInTheDocument()
    expect(screen.getByText('0.20 s')).toBeInTheDocument()
    expect(screen.queryByText('安全检测（输入）')).not.toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(screen.queryByText('输出速度')).not.toBeInTheDocument()
  })

  it('保留真实零值，缺失的网关及速度显示未知', () => {
    render(<RequestTimingCard record={{ ...record, timing: { input_security_ms: 0, pre_upstream_ms: null, output_tokens_per_sec: null } }} />)
    expect(screen.getByText('0.00 s')).toBeInTheDocument()
    const row = screen.getByText('网关处理').closest('tr')!
    expect(within(row).getByText('未知')).toBeInTheDocument()
    expect(screen.queryByText('此记录早于分段计时上线')).not.toBeInTheDocument()
  })
})
