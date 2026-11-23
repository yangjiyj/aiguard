import type { CSSProperties, ReactNode } from 'react'
import { Typography } from 'antd'
import { RAW_EVIDENCE_OMITTED_TEXT, rawEvidenceDisplay } from '../utils/alertEvidence'

const { Paragraph } = Typography

// 命中原文的统一展示：有原文给原文（截断时标出），原文因单事件上限没随事件存时提示到内容留存查看，
// 否则显示 fallback（历史打码片段或“未记录”）。
export default function RawEvidenceText({ raw, truncated, omitted, fallback = '', prefix, rows = 6, className, style }: {
  raw?: string | null
  truncated?: boolean | null
  omitted?: boolean | null
  fallback?: string
  prefix?: ReactNode
  rows?: number
  className?: string
  style?: CSSProperties
}) {
  const text = rawEvidenceDisplay(raw, truncated) || (omitted ? RAW_EVIDENCE_OMITTED_TEXT : fallback)
  if (!text) return null
  return (
    <Paragraph className={className} style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', marginBottom: 0, ...style }} ellipsis={{ rows, expandable: true, symbol: '展开' }}>
      {prefix}{text}
    </Paragraph>
  )
}
