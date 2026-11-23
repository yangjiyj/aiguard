import { useState } from 'react'
import dayjs from 'dayjs'
import { Alert, Button, Input, Modal, Select, Space, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ws8AlertInboxApi } from '../services/api'
import type { AlertInboxBulkReadPreview } from '../services/api'
import { AuditDateRangeFilter } from './AuditExportControls'
import type { AuditDateRange } from './AuditExportControls'
import { auditRangeParams, formatInTimezone } from '../utils/ws8ReportRange'
import { inboxTypeLabel } from '../utils/alertInboxDisplay'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'

const { Text } = Typography

// 管理员专用：把某一类历史通知标为已读。只改消息中心里的「已读状态」，不关闭告警、不删除、不修改任何数据。
// 预览里展示的范围用后端回显的 from/to 换算：from 为起始日零点，to 为结束日次日零点（开区间），显示时回退 1ms 得到含当日的自然日。
// 三步：1 选范围（类别 + 起止日期，缺一不可）→ 2 预览将影响的条数 → 3 手动输入该条数二次确认。
// 入口按钮由页面按控制台管理员角色控制；后端才是真正的闸门（403 / 409 在这里翻成中文提示）。

const PROTECTED_HINT = '安全告警类消息不支持批量已读，请逐条处理或到告警页按告警组处置'

type BulkReadError = { response?: { status?: number; data?: { error?: { code?: string; details?: { current_count?: number } } } } }

export default function AlertInboxBulkRead({ open, onClose, timezone }: { open: boolean; onClose: () => void; timezone?: string }) {
  const qc = useQueryClient()
  const identity = useAuditQueryIdentity()
  const [type, setType] = useState<string | undefined>()
  const [range, setRange] = useState<AuditDateRange>(null)
  const [preview, setPreview] = useState<AlertInboxBulkReadPreview | null>(null)
  const [typed, setTyped] = useState('')

  const summaryQ = useQuery({
    queryKey: ['alerts-inbox-type-summary', identity],
    queryFn: () => ws8AlertInboxApi.typeSummary(),
    enabled: open,
  })
  const types = summaryQ.data?.data?.types ?? []

  const reset = () => { setType(undefined); setRange(null); setPreview(null); setTyped('') }
  const close = () => { reset(); onClose() }
  const typeLabel = type ? inboxTypeLabel(type).label : ''
  const ready = Boolean(type && range)

  const previewM = useMutation({
    mutationFn: (scope: { type: string; from: string; to: string }) => ws8AlertInboxApi.bulkReadPreview(scope),
    onSuccess: (res) => { setPreview(res.data); setTyped('') },
    onError: (e: BulkReadError) => {
      const code = e.response?.data?.error?.code
      if (code === 'type_protected') message.error(PROTECTED_HINT)
      else if (e.response?.status === 403) message.error('仅管理员可以执行该操作')
      else message.error('查询失败，未做任何修改')
    },
  })

  const runPreview = () => {
    if (!type || !range) return
    const { from, to } = auditRangeParams(range, timezone)
    if (!from || !to) return
    previewM.mutate({ type, from, to })
  }

  const bulkM = useMutation({
    mutationFn: (p: AlertInboxBulkReadPreview) =>
      ws8AlertInboxApi.bulkRead({ type: p.type, from: p.from, to: p.to, expected_count: p.matched_unread, confirm: true }),
    onSuccess: (res, p) => {
      message.success(`已将 ${res.data?.marked_read ?? p.matched_unread} 条消息标为已读`)
      // 折叠视图、逐条视图的 queryKey 都以 alerts-inbox 开头，一次刷新全部。
      qc.invalidateQueries({ queryKey: ['alerts-inbox'] })
      // 类别下拉里的未读数也要刷新（queryKey 前缀按数组元素匹配，不会被上面的 ['alerts-inbox'] 覆盖）。
      qc.invalidateQueries({ queryKey: ['alerts-inbox-type-summary'] })
      close()
    },
    onError: (e: BulkReadError, p) => {
      const status = e.response?.status
      const err = e.response?.data?.error
      if (status === 409 && err?.code === 'count_changed') {
        const current = err.details?.current_count
        message.error(`范围内的未读数已变化（现为 ${typeof current === 'number' ? current : '若干'} 条），请重新查询后再确认`)
        // 回到预览步骤并刷新预览，用新的条数重新二次确认。
        previewM.mutate({ type: p.type, from: p.from, to: p.to })
      } else if (status === 403) {
        message.error('仅管理员可以执行该操作')
      } else {
        message.error('操作失败，未做任何修改')
      }
    },
  })

  const count = preview?.matched_unread ?? 0
  const confirmReady = Boolean(preview) && count > 0 && typed.trim() === String(count)

  return (
    <Modal
      open={open}
      title="批量标为已读"
      width={640}
      onCancel={close}
      destroyOnHidden
      footer={[
        <Button key="cancel" onClick={close}>取消</Button>,
        ...(preview && count > 0 ? [
          <Button
            key="confirm"
            danger
            type="primary"
            disabled={!confirmReady}
            loading={bulkM.isPending}
            onClick={() => bulkM.mutate(preview)}
          >
            {`确认标为已读（${count} 条）`}
          </Button>,
        ] : []),
      ]}
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="此操作只改变消息中心里的已读状态，不会关闭告警、不会删除或修改任何数据。"
      />
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <div>
          <div style={{ marginBottom: 4 }}><Text strong>① 选择范围</Text></div>
          <Space wrap>
            <Select
              aria-label="消息类别"
              placeholder="请选择消息类别"
              style={{ width: 340 }}
              loading={summaryQ.isLoading}
              value={type}
              onChange={(value) => { setType(value); setPreview(null); setTyped('') }}
              optionLabelProp="text"
              options={types.map((t) => {
                const info = inboxTypeLabel(t.type)
                const text = `${info.label} · 未读 ${Number(t.unread).toLocaleString('en-US')}`
                return {
                  value: t.type,
                  disabled: !t.bulk_read_allowed,
                  text,
                  label: (
                    <span>
                      {text}
                      {/* 未知类别附灰色类型码，只在管理员弹窗里出现，便于区分。 */}
                      {!info.known && <Text type="secondary" style={{ fontSize: 12, marginLeft: 6 }}>{t.type}</Text>}
                    </span>
                  ),
                }
              })}
            />
            <AuditDateRangeFilter value={range} onChange={(next) => { setRange(next); setPreview(null); setTyped('') }} timezone={timezone} />
          </Space>
          <div style={{ marginTop: 4 }}>
            <Text type="secondary" style={{ fontSize: 12 }}>{PROTECTED_HINT}</Text>
          </div>
        </div>

        <div>
          <div style={{ marginBottom: 4 }}><Text strong>② 预览将影响的条数</Text></div>
          <Button disabled={!ready} loading={previewM.isPending} onClick={runPreview}>查询将影响的条数</Button>
          {preview && (
            <div data-testid="bulk-read-preview" style={{ marginTop: 8 }}>
              {count > 0 ? (
                <Text>
                  {`将把【${typeLabel}】在 ${formatInTimezone(preview.from, timezone, 'YYYY-MM-DD')} ～ ${formatInTimezone(dayjs(preview.to).subtract(1, 'millisecond'), timezone, 'YYYY-MM-DD')} 之间的 ${count.toLocaleString('en-US')} 条未读消息标记为已读。此操作只改变消息中心里的已读状态，不会关闭告警、不会删除或修改任何数据。`}
                </Text>
              ) : (
                <Text type="warning">该范围内没有未读消息</Text>
              )}
            </div>
          )}
        </div>

        {preview && count > 0 && (
          <div>
            <div style={{ marginBottom: 4 }}><Text strong>③ 二次确认</Text></div>
            <Text type="secondary" style={{ display: 'block', marginBottom: 4 }}>
              请手动输入上面的条数 {count} 以启用确认按钮。
            </Text>
            <Input
              aria-label="输入影响条数以确认"
              placeholder={`输入 ${count}`}
              style={{ width: 200 }}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
            />
          </div>
        )}
      </Space>
    </Modal>
  )
}
