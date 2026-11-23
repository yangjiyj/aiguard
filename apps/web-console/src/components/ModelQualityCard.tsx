import type { ModelQualityItem } from '../services/modelOperations'
import { availabilityFlag, compactCount, msText, qualityLabel } from '../utils/modelQuality'

export type Rank = { rank: number; of: number } | null

export function KpiCard({ label, value, hint, alert }: { label: string; value: string; hint?: string; alert?: boolean }) {
  return <div className="mq-kpi" data-alert={alert ? 'true' : undefined}>
    <div className="mq-kpi-label">{label}</div>
    <div className="mq-kpi-value">{value}</div>
    {hint && <div className="mq-kpi-hint">{hint}</div>}
  </div>
}

const rankText = (rank: Rank) => rank == null ? '' : rank.rank === 1 && rank.of > 1 ? `最快 · 1/${rank.of}` : `${rank.rank}/${rank.of}`
const rateText = (rate?: number | null) => rate == null ? '—' : `${(rate * 100).toFixed(1).replace(/\.0$/, '')}%`

function errorText(item: ModelQualityItem) {
  const parts = [['5xx', item.http_5xx], ['429', item.http_429], ['4xx', item.http_4xx]].filter(([, n]) => n) as [string, number][]
  return parts.map(([k, n]) => `${k} ${compactCount(n)}`).join(' · ')
}

export function QualityCard({ item, firstRank, speedRank, onDiagnose }: { item: ModelQualityItem; firstRank: Rank; speedRank: Rank; onDiagnose: (item: ModelQualityItem) => void }) {
  const flag = availabilityFlag(item)
  const success = item.success_rate ?? item.availability
  const upstream = item.upstream_samples ?? item.samples ?? 0
  const ok = item.upstream_successes ?? (success == null ? null : Math.round(success * upstream))
  const speed = item.output_tokens_per_sec_p50
  const errors = errorText(item)
  return <article className="mq-card" data-flag={flag ? 'bad' : undefined} aria-label={`${qualityLabel(item)} 真实流量质量`}>
    <header className="mq-card-head">
      <div className="mq-card-title"><div className="mq-card-name" title={qualityLabel(item)}>{qualityLabel(item)}</div><div className="mq-card-sub">{item.provider_name || item.provider_id}</div></div>
      {flag && <span className="mq-flag">{flag}</span>}
    </header>
    <div className="mq-trio">
      <div><div className="mq-trio-label">可用率</div><div className={'mq-trio-value' + (flag ? ' mq-bad' : '')}>{rateText(success)}</div><div className="mq-trio-sub">{ok == null ? '' : `${compactCount(ok)} / ${compactCount(upstream)}`}{errors && ` · ${errors}`}</div></div>
      <div><div className="mq-trio-label">首字 P50</div><div className="mq-trio-value">{msText(item.first_event_p50_ms)}</div><div className="mq-trio-sub">{rankText(firstRank)}</div></div>
      <div><div className="mq-trio-label">输出速度</div><div className="mq-trio-value">{speed == null ? '—' : speed.toFixed(1)}{speed != null && <small> t/s</small>}</div><div className="mq-trio-sub">{rankText(speedRank)}</div></div>
    </div>
    {item.last_error && <div className="mq-last-error" title={item.last_error}>最近错误：{item.last_error}</div>}
    <footer className="mq-card-foot">
      <span>总耗时 <b>{msText(item.p50_ms)}</b> / <b>{msText(item.p95_ms)}</b></span>
      <span>网关 <b>{msText(item.pre_upstream_p50_ms)}</b></span>
      <span className="mq-spacer" />
      <button type="button" className="mq-link" disabled={!item.samples} onClick={() => onDiagnose(item)}>请求诊断</button>
    </footer>
  </article>
}

export function ThinCard({ item, windowLabel, onDiagnose }: { item: ModelQualityItem; windowLabel: string; onDiagnose: (item: ModelQualityItem) => void }) {
  const samples = item.samples ?? item.total ?? 0
  return <article className="mq-card mq-thin" aria-label={`${qualityLabel(item)} 真实流量质量`}>
    <header className="mq-card-head"><div className="mq-card-title"><div className="mq-card-name" title={qualityLabel(item)}>{qualityLabel(item)}</div><div className="mq-card-sub">{item.provider_name || item.provider_id}</div></div></header>
    <div className="mq-thin-text">{samples ? `${windowLabel} ${compactCount(samples)} 次请求，样本不足` : `${windowLabel}无请求`}</div>
    <footer className="mq-card-foot"><span className="mq-spacer" /><button type="button" className="mq-link" disabled={!samples} onClick={() => onDiagnose(item)}>请求诊断</button></footer>
  </article>
}

// 没带模型名和模型 ID 的请求（多为识别失败的代理流量）合并成一行，不占卡片。
export function UnrecognisedRow({ items }: { items: ModelQualityItem[] }) {
  const samples = items.reduce((n, i) => n + (i.samples ?? i.total ?? 0), 0)
  const upstream = items.reduce((n, i) => n + (i.upstream_samples ?? 0), 0)
  const ok = items.reduce((n, i) => n + (i.upstream_successes ?? 0), 0)
  const merged = { ...items[0], http_5xx: items.reduce((n, i) => n + (i.http_5xx ?? 0), 0), http_429: items.reduce((n, i) => n + (i.http_429 ?? 0), 0), http_4xx: items.reduce((n, i) => n + (i.http_4xx ?? 0), 0) }
  const errors = errorText(merged)
  return <div className="mq-unrec" aria-label="未识别模型">
    <b>未识别模型</b>
    <span>{compactCount(samples)} 次请求</span>
    {upstream > 0 && <span>可用率 {(ok / upstream * 100).toFixed(1)}%</span>}
    {errors && <span>{errors}</span>}
  </div>
}
