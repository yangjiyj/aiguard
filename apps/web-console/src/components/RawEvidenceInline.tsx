import { useEffect, useRef, useState } from 'react'
import { Button, Space, Typography } from 'antd'
import { rawEvidenceApi } from '../services/rawEvidence'
import { errorMessage, pickEvidence } from '../utils/rawEvidence'
import { splitByRange, verifiedHitRange, type HitRange } from '../utils/hitHighlight'

const { Text } = Typography

type Props = {
  requestId: string
  direction: 'input' | 'output'
  messageIndex: number | null
  matchedLocation?: string
  rawEvidenceSha256?: string
}

// 在告警详情里就地查看原文留证。点“查看原文”才请求；每次查看都会写入操作审计。
export default function RawEvidenceInline({ requestId, direction, messageIndex, matchedLocation, rawEvidenceSha256 }: Props) {
  const [shown, setShown] = useState<{ text: string; range: HitRange | null; truncated: boolean; originalChars: number; savedChars: number } | null>(null)
  const [loading, setLoading] = useState(false)
  const [problem, setProblem] = useState('')
  const unmounted = useRef(false)
  useEffect(() => {
    unmounted.current = false
    return () => { unmounted.current = true }
  }, [])

  const reveal = async () => {
    setLoading(true)
    setProblem('')
    try {
      const listed = await rawEvidenceApi.list({ request_id: requestId, direction, limit: 50 })
      if (unmounted.current) return
      const target = pickEvidence(listed.data.items, messageIndex)
      if (!target) {
        setProblem('没有找到这条命中对应的原文留证')
        return
      }
      const revealed = await rawEvidenceApi.reveal(target.id)
      const text = revealed.data.text
      const range = target.message_index === messageIndex ? await verifiedHitRange(text, matchedLocation, rawEvidenceSha256) : null
      if (unmounted.current) return
      setShown({ text, range, truncated: !!revealed.data.truncated, originalChars: revealed.data.original_chars ?? 0, savedChars: revealed.data.content_chars })
    } catch (e) {
      if (!unmounted.current) setProblem(errorMessage(e, '原文读取失败'))
    } finally {
      if (!unmounted.current) setLoading(false)
    }
  }

  if (shown) {
    const parts = shown.range ? splitByRange(shown.text, shown.range) : null
    return (
      <Space direction="vertical" size={4} style={{ width: '100%' }}>
        {shown.truncated ? <Text type="secondary" style={{ fontSize: 12 }}>原文共 {shown.originalChars} 字，仅保存前 {shown.savedChars} 字</Text> : null}
        <pre data-testid="raw-evidence-text" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 420, overflow: 'auto', margin: 0 }}>
          {parts ? <>{parts[0]}<mark data-testid="raw-evidence-hit">{parts[1]}</mark>{parts[2]}</> : shown.text}
        </pre>
      </Space>
    )
  }
  return (
    <Space size={8}>
      <Button onClick={() => void reveal()} loading={loading}>查看原文</Button>
      {problem ? <Text type="secondary">{problem}</Text> : null}
    </Space>
  )
}
