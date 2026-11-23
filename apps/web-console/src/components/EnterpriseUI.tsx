import type { KeyboardEvent, ReactNode } from 'react'
import { Tag, Tooltip, Typography } from 'antd'
import { compactNumber, formatFull, isCompacted } from '../utils/format'

const { Title, Text } = Typography

type Tone = 'blue' | 'green' | 'orange' | 'red' | 'purple' | 'cyan' | 'gray'

const toneClass = (tone?: Tone) => `enterprise-tone-${tone || 'blue'}`

export function EnterprisePageHeader({
  eyebrow,
  title,
  description,
  actions,
  meta,
}: {
  eyebrow?: string
  title: string
  description?: string
  actions?: ReactNode
  meta?: ReactNode
}) {
  return (
    <div className="enterprise-page-header">
      <div className="enterprise-page-header-main">
        {eyebrow ? <Text className="enterprise-eyebrow">{eyebrow}</Text> : null}
        <Title level={3} className="enterprise-page-title">{title}</Title>
        {description ? <Text className="enterprise-page-description">{description}</Text> : null}
        {meta ? <div className="enterprise-page-meta">{meta}</div> : null}
      </div>
      {actions ? <div className="enterprise-page-actions">{actions}</div> : null}
    </div>
  )
}

/**
 * 表格列/内联文本里的大计数统一展示：万/亿紧凑，>=1万时悬停 tooltip 给完整值。
 * 用于统计/排行表格的「请求数 / Token 数」列，避免大数字撑破列宽；
 * 货币金额不要用它（走各自的 currency formatter）。
 */
export function CompactNumber({ value, suffix }: { value?: number | null; suffix?: string }) {
  const n = value ?? 0
  const body = (
    <span>
      {compactNumber(n)}
      {suffix ? <span style={{ marginLeft: 2, color: 'var(--text-tertiary)' }}>{suffix}</span> : null}
    </span>
  )
  return isCompacted(n) ? <Tooltip title={formatFull(n)}>{body}</Tooltip> : body
}

export function MetricCard({
  label,
  value,
  valueNumber,
  unit,
  hint,
  tone,
  icon,
  footer,
  onClick,
  ariaLabel,
}: {
  label: string
  /** 已格式化好的展示值（货币、百分比等）。与 valueNumber 二选一。 */
  value?: ReactNode
  /** 原始计数（请求数 / Token 数等）。传此值时自动做万/亿紧凑展示，并在 tooltip 里给出完整值。 */
  valueNumber?: number | null
  unit?: string
  hint?: ReactNode
  tone?: Tone
  icon?: ReactNode
  footer?: ReactNode
  onClick?: () => void
  ariaLabel?: string
}) {
  const hasNumber = valueNumber !== undefined && valueNumber !== null
  const valueEl = hasNumber ? (
    isCompacted(valueNumber) ? (
      <Tooltip title={formatFull(valueNumber)}>
        <span className="enterprise-metric-value">{compactNumber(valueNumber)}</span>
      </Tooltip>
    ) : (
      <span className="enterprise-metric-value">{compactNumber(valueNumber)}</span>
    )
  ) : (
    <span className="enterprise-metric-value">{value}</span>
  )
  const interactiveProps = onClick ? {
    role: 'button' as const,
    tabIndex: 0,
    'aria-label': ariaLabel || label,
    onClick,
    onKeyDown: (event: KeyboardEvent<HTMLDivElement>) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        onClick()
      }
    },
  } : {}

  return (
    <div className={`enterprise-metric-card ${toneClass(tone)}${onClick ? ' enterprise-metric-card--interactive' : ''}`} {...interactiveProps}>
      <div className="enterprise-metric-topline">
        <Text className="enterprise-metric-label">{label}</Text>
        {icon ? <span className="enterprise-metric-icon">{icon}</span> : null}
      </div>
      <div className="enterprise-metric-value-row">
        {valueEl}
        {unit ? <span className="enterprise-metric-unit">{unit}</span> : null}
      </div>
      {hint ? <div className="enterprise-metric-hint">{hint}</div> : null}
      {footer ? <div className="enterprise-metric-footer">{footer}</div> : null}
    </div>
  )
}

export function SectionPanel({
  title,
  description,
  extra,
  children,
  className,
}: {
  title: ReactNode
  description?: ReactNode
  extra?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`enterprise-section ${className || ''}`.trim()}>
      <div className="enterprise-section-header">
        <div className="enterprise-section-heading">
          <div className="enterprise-section-title">{title}</div>
          {description ? <div className="enterprise-section-description">{description}</div> : null}
        </div>
        {extra ? <div className="enterprise-section-extra">{extra}</div> : null}
      </div>
      <div className="enterprise-section-body">{children}</div>
    </section>
  )
}

export function InsightStrip({
  title,
  items,
}: {
  title: string
  items: Array<{ label: string; value: ReactNode; tone?: Tone; description?: ReactNode }>
}) {
  return (
    <div className="enterprise-insight-strip">
      <div className="enterprise-insight-title">{title}</div>
      <div className="enterprise-insight-items">
        {items.map((item) => (
          <div className={`enterprise-insight-item ${toneClass(item.tone)}`} key={item.label}>
            <div className="enterprise-insight-label">{item.label}</div>
            <div className="enterprise-insight-value">{item.value}</div>
            {item.description ? <div className="enterprise-insight-description">{item.description}</div> : null}
          </div>
        ))}
      </div>
    </div>
  )
}

export function AnalysisFlow({
  items,
}: {
  items: Array<{ label: string; value: ReactNode; tone?: Tone; description?: ReactNode }>
}) {
  return (
    <div className="enterprise-analysis-flow">
      {items.map((item, index) => (
        <div className={`enterprise-analysis-step ${toneClass(item.tone)}`} key={item.label}>
          <div className="enterprise-analysis-index">{index + 1}</div>
          <div className="enterprise-analysis-content">
            <div className="enterprise-analysis-label">{item.label}</div>
            <div className="enterprise-analysis-value">{item.value}</div>
            {item.description ? <div className="enterprise-analysis-description">{item.description}</div> : null}
          </div>
        </div>
      ))}
    </div>
  )
}

export function StatusPill({ tone, children }: { tone?: Tone; children: ReactNode }) {
  return <Tag className={`enterprise-status-pill ${toneClass(tone)}`}>{children}</Tag>
}
