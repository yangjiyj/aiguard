import { Alert, Button, Space, Typography } from 'antd'
import { CopyOutlined } from '@ant-design/icons'
import { clientBaseUrls, gatewayAddressRisks } from '../utils/clientBaseUrl'

const { Text } = Typography

/**
 * 按协议分别给出客户端 Base URL。
 * 地址来自「对外调用地址」配置（通过 url 传入），组件不自行猜测任何协议或端口。
 */
export default function ClientBaseUrlGuide({ url, onCopy, omitOpenAIAddress = false }: { url: string; onCopy?: (value: string) => unknown; omitOpenAIAddress?: boolean }) {
  const addresses = clientBaseUrls(url)
  const risks = gatewayAddressRisks(url)
  const row = (label: string, hint: string, value: string, copyLabel: string) => (
    <div>
      <Space size={8} wrap>
        <Text strong style={{ fontSize: 12 }}>{label}</Text>
        {value ? <Text code>{value}</Text> : null}
        {value && onCopy ? <Button size="small" icon={<CopyOutlined />} aria-label={copyLabel} onClick={() => void onCopy(value)}>复制</Button> : null}
      </Space>
      <div><Text type="secondary" style={{ fontSize: 12 }}>{hint}</Text></div>
    </div>
  )
  return (
    <Space direction="vertical" size={8} style={{ width: '100%' }}>
      {addresses.anthropic ? <>
        {row('Anthropic 协议', '适用于 Claude Code 等：地址不带 /v1，客户端会自己拼接 /v1/messages（环境变量 ANTHROPIC_BASE_URL 同样不带 /v1）。', addresses.anthropic, '复制 Anthropic 协议地址')}
        {row('OpenAI 协议', omitOpenAIAddress ? '适用于 Codex、Cherry Studio 等：地址带一层 /v1，即上方所选入口的地址。' : '适用于 Codex、Cherry Studio 等：地址带一层 /v1。', omitOpenAIAddress ? '' : addresses.openai, '复制 OpenAI 协议地址')}
      </> : null}
      {risks.map(text => <Alert key={text} type="error" showIcon role="alert" message={text} />)}
    </Space>
  )
}
