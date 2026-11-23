import { useState } from 'react'
import { Button, Select, Space, Table, Tag, Typography, message } from 'antd'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { mcpRedlineApi, type McpRedlineAction, type McpRedlineSetting } from '../services/api'
import { SectionPanel } from '../components/EnterpriseUI'
import AgentExceptionModal from '../components/protection/AgentExceptionModal'
import { useAgentExceptionCounts } from '../components/protection/protectionHooks'
import { REDLINE_LABELS } from './McpRedlineLabels'

const { Text } = Typography

const ACTION_OPTIONS: { value: McpRedlineAction; label: string }[] = [
  { value: 'off', label: '关闭' },
  { value: 'record', label: '仅记录' },
  { value: 'alert', label: '告警' },
  { value: 'block', label: '阻断' },
]

export default function McpRedlineSettings({ canEdit = true }: { canEdit?: boolean }) {
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: ['mcp-redline-settings'],
    queryFn: () => mcpRedlineApi.list(),
  })
  const items: McpRedlineSetting[] = query.data?.data?.items ?? []
  const counts = useAgentExceptionCounts()
  const [exceptionRule, setExceptionRule] = useState<string | null>(null)
  const mutation = useMutation({
    mutationFn: (payload: Record<string, McpRedlineAction>) => mcpRedlineApi.update(payload),
    onSuccess: () => {
      message.success('红线处置已更新')
      void queryClient.invalidateQueries({ queryKey: ['mcp-redline-settings'] })
    },
    onError: () => message.error('红线处置更新失败'),
  })
  const blockCount = items.filter((item) => item.action === 'block').length

  return (
    <SectionPanel
      title="安全红线"
      extra={<Tag color={blockCount > 0 ? 'red' : 'default'}>阻断 {blockCount} / {items.length}</Tag>}
    >
      <Table<McpRedlineSetting>
        rowKey="rule_name"
        size="small"
        pagination={false}
        loading={query.isLoading}
        dataSource={items}
        columns={[
          {
            title: '红线',
            dataIndex: 'rule_name',
            render: (name: string) => (
              <div>
                <Text strong>{REDLINE_LABELS[name]?.title ?? name}</Text>
                <div><Text type="secondary" style={{ fontSize: 12 }}>{REDLINE_LABELS[name]?.hint ?? name}</Text></div>
              </div>
            ),
          },
          {
            title: '处置',
            dataIndex: 'action',
            width: 160,
            render: (action: McpRedlineAction, record) => (
              <Select<McpRedlineAction>
                aria-label={`红线处置-${record.rule_name}`}
                value={action}
                options={ACTION_OPTIONS}
                disabled={!canEdit || mutation.isPending}
                style={{ width: 120 }}
                onChange={(next) => mutation.mutate({ [record.rule_name]: next })}
              />
            ),
          },
          {
            title: '例外',
            key: 'exceptions',
            width: 160,
            render: (_: unknown, record) => {
              const count = counts[record.rule_name] ?? 0
              return (
                <Space size={8}>
                  {count > 0 ? <Link to="/security/agents/advanced?tab=exceptions">{count} 条</Link> : <Text type="secondary">0 条</Text>}
                  <Button size="small" disabled={!canEdit} aria-label={`${REDLINE_LABELS[record.rule_name]?.title ?? record.rule_name}加例外`} onClick={() => setExceptionRule(record.rule_name)}>加例外</Button>
                </Space>
              )
            },
          },
        ]}
      />
      {exceptionRule ? (
        <AgentExceptionModal
          prefill={{ scope_type: 'tenant', rule_id: exceptionRule }}
          targetKind="mcp"
          onClose={() => setExceptionRule(null)}
        />
      ) : null}
    </SectionPanel>
  )
}
