import { useState } from 'react'
import { Alert, Button, Drawer, Empty, Input, List, Space, Tag, Typography } from 'antd'
import { Link } from 'react-router-dom'
import { leakTraceApi, type LeakTraceResult } from '../services/leakTrace'
import { formatAgentType } from '../utils/agents'

const { Text, Paragraph } = Typography

const MAX_TEXT = 20000

function watermarkNotice(result: LeakTraceResult) {
  if (result.watermark === 'verified') {
    return <Alert type="success" showIcon message="已通过隐式水印定位到原始请求" />
  }
  if (result.watermark === 'forged') {
    return <Alert type="warning" showIcon message="文本里有格式完整的水印，但校验未通过" description="可能被篡改或来自其他系统，已改用文本片段检索。" />
  }
  return <Alert type="info" showIcon message="文本里没有可用的隐式水印，已改用文本片段在近 30 天的助手回复中检索" />
}

export default function LeakTraceDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<LeakTraceResult | null>(null)

  const submit = async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await leakTraceApi.trace(text)
      setResult(res.data)
    } catch (e: unknown) {
      const message = (e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message
      setError(message || '溯源失败，请稍后重试')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Drawer title="泄露溯源" open={open} onClose={onClose} width={640} destroyOnHidden>
      <Paragraph type="secondary">
        粘贴一段疑似泄露的 AI 回复。开启了隐式水印的回复可以直接定位到原始请求；没有水印时，按文本片段检索留存的助手回复。结果只显示请求信息，查看正文请进入对应的留证记录。
      </Paragraph>
      <Input.TextArea
        aria-label="疑似泄露的文本"
        value={text}
        onChange={(e) => setText(e.target.value)}
        maxLength={MAX_TEXT}
        showCount
        autoSize={{ minRows: 6, maxRows: 14 }}
        placeholder="粘贴文本，建议保留原始格式"
      />
      <Space style={{ marginTop: 12 }}>
        <Button type="primary" loading={loading} disabled={!text.trim()} onClick={() => { void submit() }}>开始溯源</Button>
        <Button onClick={() => { setText(''); setResult(null); setError(null) }}>清空</Button>
      </Space>
      {error ? <Alert style={{ marginTop: 16 }} type="error" showIcon message={error} /> : null}
      {result ? (
        <div style={{ marginTop: 16 }}>
          {result.method === 'none' ? <Alert type="info" showIcon message={result.note || '无法检索'} /> : watermarkNotice(result)}
          {result.fragments?.length ? (
            <div style={{ marginTop: 12 }}>
              <Text strong>检索片段</Text>
              <ol style={{ paddingLeft: 20, margin: '4px 0 0' }}>
                {result.fragments.map((f) => <li key={f}><Text type="secondary">{f}</Text></li>)}
              </ol>
            </div>
          ) : null}
          {result.method !== 'none' ? (
            result.matches.length ? (
              <List
                style={{ marginTop: 12 }}
                header={<Text strong>{`找到 ${result.matches.length} 个请求`}</Text>}
                dataSource={result.matches}
                renderItem={(m) => (
                  <List.Item
                    actions={[<Link key="open" to={`/audit/access-retention?request_id=${encodeURIComponent(m.request_id)}`}>查看留证</Link>]}
                  >
                    <List.Item.Meta
                      title={<Space wrap><span>{m.username || m.user_id || '未知用户'}</span>{m.target ? <Tag>{m.target}</Tag> : null}{m.agent_type ? <Tag color="blue">{formatAgentType(m.agent_type)}</Tag> : null}</Space>}
                      description={<Space wrap size={12}><span>{new Date(m.occurred_at).toLocaleString()}</span><Text type="secondary" copyable>{m.request_id}</Text>{m.fragments?.length ? <span>{`命中片段 ${m.fragments.join('、')}`}</span> : null}</Space>}
                    />
                  </List.Item>
                )}
              />
            ) : <Empty style={{ marginTop: 16 }} description={result.note || '没有找到匹配的请求'} />
          ) : null}
        </div>
      ) : null}
    </Drawer>
  )
}
