import { ApiOutlined } from '@ant-design/icons'
import deepseekLogo from '../../assets/providers/deepseek.svg'
import qwenLogo from '../../assets/providers/qwen.svg'
import './ProviderIdentity.css'

const providerLabels: Record<string, string> = { openai: 'OpenAI', anthropic: 'Anthropic', azure: 'Azure OpenAI', bedrock: 'AWS Bedrock', gemini: 'Google Vertex AI / Gemini', deepseek: 'DeepSeek', moonshot: 'Moonshot', kimi: 'Kimi', zhipu: '智谱GLM', minimax: 'MiniMax', qwen: '阿里千问', hunyuan: '腾讯混元', doubao: '字节豆包', newapi: 'NewAPI 上游', openrouter: 'OpenRouter', xinference: 'Xinference', vertex: 'Google Vertex AI', custom: '自定义 (自建中转)' }

interface ProviderIdentityProps {
  providerType?: string
  name?: string
  strong?: boolean
}

export default function ProviderIdentity({ providerType, name, strong = false }: ProviderIdentityProps) {
  const type = (providerType || '').trim().toLowerCase()
  const typeLabel = Object.prototype.hasOwnProperty.call(providerLabels, type) ? providerLabels[type] : 'API'
  const logo = type === 'deepseek' ? deepseekLogo : type === 'qwen' ? qwenLogo : undefined
  const label = name || typeLabel

  return (
    <span className={`provider-identity${strong ? ' provider-identity--strong' : ''}`} title={name && name !== typeLabel ? `${name} · ${typeLabel}` : typeLabel}>
      <span className={`provider-identity__mark${logo ? ' provider-identity__mark--brand' : ''}`} aria-hidden="true">
        {logo ? <img src={logo} alt="" width={18} height={18} draggable={false} /> : <ApiOutlined />}
      </span>
      <span className="provider-identity__name">{label}</span>
    </span>
  )
}
