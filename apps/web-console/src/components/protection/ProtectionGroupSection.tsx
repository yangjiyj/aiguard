import { useState, type CSSProperties, type ReactNode } from 'react'
import { Alert } from 'antd'
import { SectionPanel } from '../EnterpriseUI'
import type { ProtectionGroup } from '../../services/api'
import ProtectionItemTable from './ProtectionItemTable'
import AgentExceptionModal, { type AgentExceptionPrefill, type AgentExceptionTargetKind } from './AgentExceptionModal'
import { FILE_PROTECTION_KEYS } from './constants'
import { useAgentExceptionCounts, useProtectionFocus, useProtectionGroupItems, useScrollToElement } from './protectionHooks'

// 一组防护项：标题 + 表格 + 加例外弹窗。智能体行为页、MCP 调用策略、Skill 安全准入共用。
// 这组还没有任何项时不显示；读取失败时提示（showError=false 时由外层统一提示）。
export default function ProtectionGroupSection({
  group,
  title,
  ariaLabel,
  canManage,
  showError = true,
  style,
}: {
  group: ProtectionGroup
  title: ReactNode
  ariaLabel: string
  canManage: boolean
  showError?: boolean
  // 外边距放在这里：没有项、不显示时不留空白。
  style?: CSSProperties
}) {
  const { query, items } = useProtectionGroupItems(group)
  const counts = useAgentExceptionCounts()
  const { focusKey, focusGroup, prefillFor } = useProtectionFocus()
  const [exception, setException] = useState<{ prefill: AgentExceptionPrefill; targetKind?: AgentExceptionTargetKind } | null>(null)
  const focusedItem = focusKey ? items.find((item) => item.key === focusKey) : undefined
  useScrollToElement(focusedItem ? `protection-item-${focusedItem.key}` : focusGroup === group ? `protection-group-${group}` : undefined, query.isSuccess)

  if (query.isError) return showError ? <Alert type="error" showIcon message="防护项读取失败" style={style} /> : null
  if (query.isSuccess && items.length === 0) return null
  return (
    <div id={`protection-group-${group}`} className={`protection-group-section${focusGroup === group ? ' is-focused' : ''}`} style={style}>
      <SectionPanel title={title}>
        <ProtectionItemTable
          ariaLabel={ariaLabel}
          items={items}
          loading={query.isLoading}
          canManage={canManage}
          focusKey={focusKey}
          exceptionCounts={counts}
          onAddException={(item) => setException({
            prefill: prefillFor(item.key),
            targetKind: group === 'mcp' ? 'mcp' : FILE_PROTECTION_KEYS.has(item.key) ? 'file' : undefined,
          })}
        />
      </SectionPanel>
      {exception ? <AgentExceptionModal prefill={exception.prefill} targetKind={exception.targetKind} onClose={() => setException(null)} /> : null}
    </div>
  )
}
