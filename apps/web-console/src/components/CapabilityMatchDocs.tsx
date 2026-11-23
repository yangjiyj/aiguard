import { Tag, Typography } from 'antd'
import type { SecurityPolicyCapability } from '../services/securityPoliciesApi'
import { capabilityDisplayName } from '../pages/security-policy/policyCenterEnterpriseModel'

const { Text } = Typography

const codeStyle = { whiteSpace: 'pre-wrap', wordBreak: 'break-all' } as const

const Examples = ({ label, items }: { label: string; items?: string[] }) =>
  items && items.length > 0 ? (
    <div className="capability-match-examples">
      <Text type="secondary">{label}</Text>
      {items.map((item, index) => <Text code key={`${index}-${item}`} style={codeStyle}>{item}</Text>)}
    </div>
  ) : null

// 从告警或阻断记录跳过来时，那一次命中的可读内容。
export function CurrentHit({ text }: { text: string }) {
  if (!text) return null
  return (
    <section aria-label="本次命中" className="capability-match-current">
      <Text strong>本次命中</Text>
      <Text code style={codeStyle}>{text}</Text>
    </section>
  )
}

// 规则绑定的每个检测能力具体认什么，配会命中和不会命中的示例。
export default function CapabilityMatchDocs({ capabilities }: { capabilities: SecurityPolicyCapability[] }) {
  const documented = capabilities.filter((capability) => capability.matches)
  if (documented.length === 0) return null
  return (
    <section aria-label="匹配什么" className="capability-match-docs">
      <Text strong>匹配什么</Text>
      {documented.map((capability) => (
        <div key={capability.category} data-testid="capability-match-doc" className="capability-match-doc">
          <div>
            {documented.length > 1 ? <Text strong>{capabilityDisplayName(capability)}：</Text> : null}
            <Text>{capability.matches}</Text>
            {capability.judged_by_ai ? <Tag style={{ marginInlineStart: 8 }}>由 AI 判断</Tag> : null}
          </div>
          <Examples label="会命中" items={capability.hit_examples} />
          <Examples label="不会命中" items={capability.miss_examples} />
        </div>
      ))}
    </section>
  )
}
