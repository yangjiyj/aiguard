import { Card, Descriptions, Typography } from 'antd'
import type { UsageRecord } from '../services/api'
import { probeLatency } from '../utils/modelProbe'

const available = (value: number | null | undefined): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0

export default function RequestTimingCard({ record }: { record: UsageRecord }) {
  const timing = record.timing
  const total = timing?.latency_ms ?? record.latency_ms
  const first = timing?.upstream_ttft_ms ?? record.upstream_ttft_ms
  const segmented = [timing?.input_security_ms, timing?.output_security_ms, timing?.pre_upstream_ms, timing?.generation_ms].some(available)
  // 发出上游前的耗时已含输入检测，展示净处理时间，避免重复计算输入检测。
  const gateway = available(timing?.pre_upstream_ms) && available(timing?.input_security_ms)
    ? Math.max(0, timing.pre_upstream_ms - timing.input_security_ms) : null
  const stages = [
    { label: '安全检测（输入）', value: timing?.input_security_ms, color: 'var(--chart-2)' },
    { label: '网关处理', value: gateway, color: 'var(--chart-1)' },
    { label: '等待上游首字', value: first, color: 'var(--chart-3)' },
    { label: '生成', value: timing?.generation_ms, color: 'var(--chart-6)' },
    { label: '安全检测（输出）', value: timing?.output_security_ms, color: 'var(--chart-4)' },
  ]
  const weight = stages.reduce((sum, stage) => sum + (available(stage.value) ? stage.value : 0), 0)
  return <Card size="small" title="耗时分解">
    {segmented ? <>
      <div role="img" aria-label="分段耗时相对占比" style={{ display: 'flex', height: 14, overflow: 'hidden', borderRadius: 4, background: 'var(--border-color)', marginBottom: 12 }}>
        {stages.filter((stage) => available(stage.value) && stage.value > 0).map((stage) => <span key={stage.label} title={`${stage.label}：${probeLatency(stage.value)}`} style={{ width: `${weight ? stage.value! / weight * 100 : 0}%`, background: stage.color }} />)}
      </div>
      <Descriptions size="small" column={1} items={[
        ...stages.map((stage) => ({ key: stage.label, label: <span><span aria-hidden="true" style={{ display: 'inline-block', width: 8, height: 8, background: stage.color, marginRight: 6 }} />{stage.label}</span>, children: probeLatency(stage.value) })),
        { key: 'pre', label: '发出上游前（含输入检测）', children: probeLatency(timing?.pre_upstream_ms) },
        { key: 'total', label: '总计', children: probeLatency(total) },
        { key: 'speed', label: '输出速度', children: available(timing?.output_tokens_per_sec) ? `${timing.output_tokens_per_sec.toFixed(1)} 词元/秒` : '未知' },
      ]} />
      <Typography.Text type="secondary">分段条展示已知阶段的相对占比；网关处理已扣除输入检测。流式输出检测与生成可能重叠，各阶段不能简单相加为总耗时。未采集的阶段显示未知。</Typography.Text>
    </> : <>
      <Descriptions size="small" column={1} items={[{ key: 'total', label: '总计', children: probeLatency(total) }, { key: 'first', label: '等待上游首字', children: probeLatency(first) }]} />
      <Typography.Text type="secondary">此记录早于分段计时上线</Typography.Text>
    </>}
  </Card>
}
