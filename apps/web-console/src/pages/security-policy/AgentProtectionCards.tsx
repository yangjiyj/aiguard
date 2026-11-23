import { useMemo } from 'react'
import { Alert, Space, Typography } from 'antd'
import ProtectionGroupSection from '../../components/protection/ProtectionGroupSection'
import { useProtectionSettings } from '../../components/protection/protectionHooks'
import type { ProtectionGroup } from '../../services/api'

const { Text } = Typography

const GROUPS: Array<{ group: ProtectionGroup; title: string }> = [
  { group: 'agent_target', title: '敏感目标' },
  { group: 'agent_fallback', title: '兜底判定' },
  { group: 'endpoint', title: '端侧内置规则' },
]

// 智能体行为页的三张防护项卡片；读取失败统一提示一次。
export default function AgentProtectionCards({ canManage }: { canManage: boolean }) {
  const query = useProtectionSettings()
  // 后端还没有登记某组的项时不显示空卡片；“取严”说明放在第一张可见卡片标题旁。
  const visibleGroups = useMemo(
    () => GROUPS.filter(({ group }) => !query.isSuccess || (query.data ?? []).some((item) => item.group === group)),
    [query.data, query.isSuccess],
  )
  if (query.isError) return <Alert type="error" showIcon message="防护项读取失败" style={{ marginTop: 16 }} />
  return (
    <div className="agent-protection-cards">
      {visibleGroups.map(({ group, title }, index) => (
        <ProtectionGroupSection
          key={group}
          group={group}
          ariaLabel={title}
          canManage={canManage}
          showError={false}
          title={index === 0 ? <Space size={12}>{title}<Text type="secondary" style={{ fontWeight: 400, fontSize: 13 }}>和上面的分类卡片取严</Text></Space> : title}
        />
      ))}
    </div>
  )
}
