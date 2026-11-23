import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Drawer, Empty, Form, Input, Modal, Select, Space, Switch, Table, Tag, Typography, message, theme } from 'antd'
import { rawEvidenceApi, type RawEvidenceMeta, type RawEvidenceQuery, type RawEvidenceReveal } from '../services/rawEvidence'
import { useAuthStore } from '../stores/auth'
import { canToggleRawEvidenceRole } from '../utils/access'
import { errorMessage } from '../utils/rawEvidence'
import { buildSegments, foldConsecutive, looksEscaped, type RawEvidenceRow } from '../utils/rawEvidenceView'

const { Text } = Typography

// 脱敏原文留证：默认只列元数据（脱敏版本仍在内容留证里）；点"查看原文"直接查看（事由可不填），每次查看都会写入操作审计。
export default function RawEvidenceDrawer({ open, onClose, requestId }: { open: boolean; onClose: () => void; requestId?: string | null }) {
  const { token } = theme.useToken()
  const [filters, setFilters] = useState<RawEvidenceQuery>({})
  const [items, setItems] = useState<RawEvidenceMeta[]>([])
  const [total, setTotal] = useState(0)
  const [enabled, setEnabled] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reason, setReason] = useState('')
  const [revealingId, setRevealingId] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<RawEvidenceReveal | null>(null)
  const canToggle = canToggleRawEvidenceRole(useAuthStore((state) => state.user?.role))
  const [currentHit, setCurrentHit] = useState(0)
  const [unescape, setUnescape] = useState(true)
  const preRef = useRef<HTMLPreElement>(null)
  const rows = useMemo(() => foldConsecutive(items), [items])
  const hits = useMemo(() => [...(revealed?.hits || [])].sort((a, b) => a.start - b.start), [revealed])
  const escaped = useMemo(() => (revealed ? looksEscaped(revealed.text) : false), [revealed])
  const segments = useMemo(() => (revealed ? buildSegments(revealed.text, hits, escaped && unescape) : []), [revealed, hits, escaped, unescape])

  // 打开原文或切换命中时，把当前命中滚到可见区域中间。
  useEffect(() => {
    if (!revealed || !hits.length) return
    const el = preRef.current?.querySelector(`mark[data-hit="${currentHit}"]`) as HTMLElement | null
    el?.scrollIntoView?.({ block: 'center' })
  }, [revealed, hits, currentHit, segments])

  const load = useCallback(async (query: RawEvidenceQuery) => {
    setLoading(true)
    setError(null)
    try {
      const res = await rawEvidenceApi.list(query)
      setItems(res.data.items)
      setTotal(res.data.total)
      setEnabled(res.data.enabled)
    } catch (e) {
      setError(errorMessage(e, '查询失败，请稍后重试'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!open) return
    const initial: RawEvidenceQuery = requestId ? { request_id: requestId } : {}
    setFilters(initial)
    setRevealed(null)
    void load(initial)
  }, [open, requestId, load])

  // 关闭抽屉即清掉内存里的原文。
  const close = () => {
    setRevealed(null)
    setReason('')
    onClose()
  }

  // 点"查看原文"直接查看：不弹事由框、不二次确认；事由可在上方小输入框里选填。
  const reveal = async (row: RawEvidenceMeta) => {
    setRevealingId(row.id)
    try {
      const res = await rawEvidenceApi.reveal(row.id, reason.trim())
      setCurrentHit(0)
      setUnescape(true)
      setRevealed(res.data)
    } catch (e) {
      message.error(errorMessage(e, '查看失败'))
    } finally {
      setRevealingId(null)
    }
  }

  const toggle = async (next: boolean) => {
    try {
      const res = await rawEvidenceApi.setEnabled(next)
      setEnabled(res.data.enabled)
      message.success(next ? '已开启脱敏原文留证' : '已关闭脱敏原文留证（已有留证按保留期自然过期）')
    } catch (e) {
      message.error(errorMessage(e, '设置失败'))
    }
  }

  return (
    <Drawer title="脱敏原文留证" open={open} onClose={close} width={960} destroyOnClose>
      <Text type="secondary" style={{ display: 'block', marginBottom: 12, fontSize: 12 }}>仅覆盖聊天类通道的文本，查看会记入操作审计。</Text>
      <Space style={{ marginBottom: 12 }} align="center" wrap>
        <Text>脱敏原文留证开关</Text>
        {canToggle ? (
          <Switch aria-label="脱敏原文留证开关" checked={enabled} onChange={toggle} />
        ) : (
          <Text type="secondary">{enabled ? '已开启（系统管理员可修改）' : '已关闭（系统管理员可修改）'}</Text>
        )}
        <Input aria-label="查看事由" size="small" style={{ width: 240 }} maxLength={200} allowClear placeholder="查看事由（可不填）" value={reason} onChange={(e) => setReason(e.target.value)} />
      </Space>
      <Form layout="inline" style={{ marginBottom: 12, rowGap: 8 }} onFinish={() => load(filters)}>
        <Form.Item label="请求 ID">
          <Input aria-label="请求 ID" allowClear value={filters.request_id} onChange={(e) => setFilters({ ...filters, request_id: e.target.value || undefined })} />
        </Form.Item>
        <Form.Item label="阻断编号">
          <Input aria-label="阻断编号" allowClear value={filters.block_id} onChange={(e) => setFilters({ ...filters, block_id: e.target.value || undefined })} />
        </Form.Item>
        <Form.Item label="命中规则">
          <Input aria-label="命中规则" allowClear placeholder="规则编号或名称" value={filters.rule} onChange={(e) => setFilters({ ...filters, rule: e.target.value || undefined })} />
        </Form.Item>
        <Form.Item label="处置">
          <Select
            aria-label="处置"
            allowClear
            style={{ width: 110 }}
            value={filters.disposition}
            onChange={(v) => setFilters({ ...filters, disposition: v })}
            options={[{ value: 'masked', label: '已脱敏' }, { value: 'blocked', label: '已阻断' }]}
          />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>查询</Button>
        </Form.Item>
      </Form>
      {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} /> : null}
      <Table<RawEvidenceRow>
        size="small"
        rowKey="id"
        loading={loading}
        dataSource={rows}
        pagination={{ total, pageSize: 50, showTotal: (n) => `共 ${n} 条`, onChange: (page) => void load({ ...filters, offset: (page - 1) * 50 }) }}
        locale={{ emptyText: <Empty description="没有匹配的原文留证" /> }}
        columns={[
          { title: '时间', dataIndex: 'created_at', width: 160, render: (v: string) => new Date(v).toLocaleString() },
          { title: '请求 ID', dataIndex: 'request_id', ellipsis: true },
          { title: '方向', dataIndex: 'direction', width: 70, render: (v: string) => (v === 'input' ? '输入' : '输出') },
          { title: '处置', dataIndex: 'disposition', width: 80, render: (v: string) => <Tag color={v === 'blocked' ? 'red' : 'blue'}>{v === 'blocked' ? '已阻断' : '已脱敏'}</Tag> },
          { title: '阻断编号', dataIndex: 'block_id', ellipsis: true, render: (v?: string) => v || '-' },
          { title: '命中规则', key: 'rules', render: (_: unknown, r) => <Space size={4} wrap>{(r.rule_names.length ? r.rule_names : r.rule_ids).join('、') || '-'}{r.repeat ? <Tag color="orange">连续 {r.repeat} 次</Tag> : null}</Space> },
          { title: '字数', dataIndex: 'content_chars', width: 90, render: (v: number, r) => (r.ref_evidence_id ? <Space size={4}>{v}<Tag>重复</Tag></Space> : v) },
          { title: '操作', key: 'op', width: 100, render: (_: unknown, r) => <Button size="small" loading={revealingId === r.id} onClick={() => void reveal(r)}>查看原文</Button> },
        ]}
      />
      <Modal title="脱敏前原文" open={!!revealed} onCancel={() => setRevealed(null)} footer={<Button onClick={() => setRevealed(null)}>关闭并清除</Button>} width={960} destroyOnClose>
        {revealed ? (
          <Space direction="vertical" style={{ width: '100%' }}>
            <Text type="secondary">请求 {revealed.request_id} · {revealed.direction === 'input' ? '输入' : '输出'} · 角色 {revealed.role}</Text>
            {revealed.rules?.length ? (
              <Space size={[4, 4]} wrap aria-label="命中规则说明">
                <Text strong>{revealed.disposition === 'blocked' ? '阻断依据' : '脱敏依据'}</Text>
                {revealed.rules.map((rule) => (
                  <Tag key={`${rule.rule_name}|${rule.action}`} color={rule.action === 'block' ? 'red' : 'blue'}
                    style={{ cursor: rule.located ? 'pointer' : 'default' }}
                    onClick={() => { const i = hits.findIndex((h) => h.rule_name === rule.rule_name); if (i >= 0) setCurrentHit(i) }}>
                    {rule.rule_name}{rule.located ? '' : rule.semantic ? '（整段判定）' : '（原文中未定位）'}
                  </Tag>
                ))}
              </Space>
            ) : null}
            {revealed.rules?.filter((rule) => rule.semantic && rule.reason).map((rule) => (
              <Text key={`reason|${rule.rule_name}`} type="secondary">{rule.rule_name}：{rule.reason}</Text>
            ))}
            <Space size={8} wrap>
              {hits.length ? (
                <>
                  <Text>命中 {currentHit + 1} / {hits.length} 处</Text>
                  <Button size="small" disabled={hits.length < 2} onClick={() => setCurrentHit((currentHit - 1 + hits.length) % hits.length)}>上一处</Button>
                  <Button size="small" disabled={hits.length < 2} onClick={() => setCurrentHit((currentHit + 1) % hits.length)}>下一处</Button>
                </>
              ) : null}
              {escaped ? <Checkbox checked={unescape} onChange={(e) => setUnescape(e.target.checked)}>还原换行</Checkbox> : null}
            </Space>
            {revealed.truncated ? (
              <Text type="secondary" style={{ fontSize: 12 }}>原文共 {revealed.original_chars ?? 0} 字，仅保存前 {revealed.content_chars} 字</Text>
            ) : null}
            <pre ref={preRef} aria-label="原文内容" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 520, overflow: 'auto', background: token.colorFillTertiary, color: token.colorText, padding: 12, margin: 0 }}>
              {segments.map((seg, i) => (seg.hit === null ? (
                <span key={i}>{seg.text}</span>
              ) : (
                <mark key={i} data-hit={seg.hit} title={hits[seg.hit]?.rule_name}
                  style={{ background: '#ffe58f', color: '#1f1f1f', padding: 0, outline: seg.hit === currentHit ? '2px solid #ff4d4f' : undefined }}>{seg.text}</mark>
              )))}
            </pre>
          </Space>
        ) : null}
      </Modal>
    </Drawer>
  )
}
