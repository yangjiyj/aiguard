import { useEffect, useMemo, useRef, useState } from 'react'
import { Button, InputNumber, Select, Space, Table, Typography, message } from 'antd'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  protectionSettingsApi,
  type ProtectionAction,
  type ProtectionParamSpec,
  type ProtectionSettingItem,
} from '../../services/api'
import { actionLabel } from '../../utils/actionLabels'
import { extractApiError } from '../../utils/apiError'
import { PROTECTION_SETTINGS_QUERY_KEY } from './protectionHooks'

const { Text } = Typography

type ParamDrafts = Record<string, Record<string, unknown>>

function paramValue(item: ProtectionSettingItem, spec: ProtectionParamSpec): unknown {
  const stored = item.params?.[spec.key]
  return stored === undefined || stored === null ? spec.default : stored
}

function storedParams(item: ProtectionSettingItem): Record<string, unknown> {
  return Object.fromEntries((item.param_specs ?? []).map((spec) => [spec.key, paramValue(item, spec)]))
}

function draftsFor(items: ProtectionSettingItem[]): ParamDrafts {
  return Object.fromEntries(items.map((item) => [item.key, storedParams(item)]))
}

function clamp(value: number, spec: ProtectionParamSpec): number {
  let next = Math.round(value)
  if (typeof spec.min === 'number' && next < spec.min) next = spec.min
  if (typeof spec.max === 'number' && spec.max > 0 && next > spec.max) next = spec.max
  return next
}

export default function ProtectionItemTable({
  items,
  canManage,
  focusKey,
  exceptionCounts,
  exceptionsHref = '/security/agents/advanced?tab=exceptions',
  onAddException,
  ariaLabel,
  loading = false,
}: {
  items: ProtectionSettingItem[]
  canManage: boolean
  focusKey?: string
  exceptionCounts?: Record<string, number>
  exceptionsHref?: string
  onAddException?: (item: ProtectionSettingItem) => void
  ariaLabel: string
  loading?: boolean
}) {
  const queryClient = useQueryClient()
  // 按“键 + 动作 + 参数内容”判断服务端值是否真的变了；同样内容的刷新不重置还没保存的输入。
  const signature = useMemo(() => JSON.stringify(items.map((item) => [item.key, item.action, storedParams(item)])), [items])
  const [drafts, setDraftsState] = useState<ParamDrafts>(() => draftsFor(items))
  // 草稿同时写进 ref：失焦、删除标签等事件里读到的是同一轮里刚改的值，不会“界面已改、服务端没存”。
  const draftsRef = useRef<ParamDrafts>(drafts)
  const setDrafts = (next: ParamDrafts) => {
    draftsRef.current = next
    setDraftsState(next)
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { setDrafts(draftsFor(items)) }, [signature])

  const mutation = useMutation({
    mutationFn: ({ key, action, params }: { key: string; action: ProtectionAction; params: Record<string, unknown> }) =>
      protectionSettingsApi.update({ [key]: { action, params } }),
    onSuccess: async (response) => {
      message.success('已保存')
      const next = (response?.data as { items?: unknown } | undefined)?.items
      if (Array.isArray(next)) queryClient.setQueryData(PROTECTION_SETTINGS_QUERY_KEY, next)
      await queryClient.invalidateQueries({ queryKey: PROTECTION_SETTINGS_QUERY_KEY })
    },
    onError: (error) => {
      message.error(extractApiError(error) || '保存失败')
      setDrafts(draftsFor(items))
    },
  })

  const disabled = !canManage || mutation.isPending
  const save = (item: ProtectionSettingItem, action: ProtectionAction, params: Record<string, unknown>) => {
    if (!canManage) return
    mutation.mutate({ key: item.key, action, params })
  }
  const setDraft = (item: ProtectionSettingItem, spec: ProtectionParamSpec, value: unknown) => {
    const current = draftsRef.current
    setDrafts({ ...current, [item.key]: { ...current[item.key], [spec.key]: value } })
  }
  const saveParam = (item: ProtectionSettingItem, spec: ProtectionParamSpec, value: unknown) => {
    const params = { ...storedParams(item), ...draftsRef.current[item.key], [spec.key]: value }
    if (JSON.stringify(params) === JSON.stringify(storedParams(item))) return
    save(item, item.action, params)
  }

  const renderParam = (item: ProtectionSettingItem, spec: ProtectionParamSpec) => {
    const value = drafts[item.key]?.[spec.key]
    const name = `${item.label}${spec.label}`
    if (spec.kind === 'string_list') {
      return (
        <Select
          key={spec.key}
          mode="tags"
          open={false}
          aria-label={name}
          placeholder={spec.label}
          style={{ minWidth: 200 }}
          disabled={disabled}
          value={Array.isArray(value) ? value.map(String) : []}
          tokenSeparators={[',', ' ']}
          onChange={(next: string[]) => {
            const before = draftsRef.current[item.key]?.[spec.key]
            setDraft(item, spec, next)
            // 删除标签（列表变短）立即保存；新增等离开输入框时一起保存。
            if (next.length < (Array.isArray(before) ? before.length : 0)) saveParam(item, spec, next)
          }}
          onBlur={() => saveParam(item, spec, draftsRef.current[item.key]?.[spec.key] ?? [])}
        />
      )
    }
    if (spec.kind === 'int') {
      return (
        <Space key={spec.key} size={4}>
          <Text type="secondary">{spec.label}</Text>
          <InputNumber
            aria-label={name}
            min={spec.min}
            max={spec.max}
            precision={0}
            disabled={disabled}
            value={typeof value === 'number' ? value : Number(value) || undefined}
            onChange={(next) => setDraft(item, spec, next)}
            onBlur={(event) => {
              // 以输入框里的文字为准，超出范围就拉回上下限再保存。
              const typed = Number(String(event.target.value).replace(/,/g, '').trim())
              if (String(event.target.value).trim() === '' || !Number.isFinite(typed)) {
                setDraft(item, spec, paramValue(item, spec))
                return
              }
              const next = clamp(typed, spec)
              setDraft(item, spec, next)
              saveParam(item, spec, next)
            }}
          />
        </Space>
      )
    }
    // 不认识的参数类型只读显示，不提供编辑。
    return <Text key={spec.key} type="secondary">{`${spec.label}：${typeof value === 'string' ? value : JSON.stringify(value)}`}</Text>
  }

  const hasParams = items.some((item) => (item.param_specs ?? []).length > 0)
  const columns = [
    { title: '防护项', dataIndex: 'label', key: 'label', render: (label: string) => <Text strong>{label}</Text> },
    {
      title: '动作',
      key: 'action',
      width: 150,
      render: (_: unknown, item: ProtectionSettingItem) => (
        <Select<ProtectionAction>
          aria-label={`${item.label}动作`}
          value={item.action}
          disabled={disabled}
          style={{ width: 128 }}
          options={item.actions.map((action) => ({ value: action, label: actionLabel(action) }))}
          onChange={(action) => save(item, action, { ...storedParams(item), ...draftsRef.current[item.key] })}
        />
      ),
    },
    ...(hasParams ? [{
      title: '参数',
      key: 'params',
      render: (_: unknown, item: ProtectionSettingItem) => <Space wrap>{(item.param_specs ?? []).map((spec) => renderParam(item, spec))}</Space>,
    }] : []),
    ...(onAddException ? [{
      title: '例外',
      key: 'exceptions',
      width: 160,
      render: (_: unknown, item: ProtectionSettingItem) => {
        const count = exceptionCounts?.[item.key] ?? 0
        return (
          <Space size={8}>
            {count > 0 ? <Link to={exceptionsHref}>{count} 条</Link> : <Text type="secondary">0 条</Text>}
            <Button size="small" disabled={!canManage} aria-label={`${item.label}加例外`} onClick={() => onAddException(item)}>加例外</Button>
          </Space>
        )
      },
    }] : []),
  ]

  return (
    <Table<ProtectionSettingItem>
      aria-label={ariaLabel}
      rowKey="key"
      size="small"
      pagination={false}
      loading={loading}
      dataSource={items}
      columns={columns}
      rowClassName={(item) => `protection-item-row${item.key === focusKey ? ' is-focused' : ''}`}
      onRow={(item) => ({ id: `protection-item-${item.key}` })}
    />
  )
}
