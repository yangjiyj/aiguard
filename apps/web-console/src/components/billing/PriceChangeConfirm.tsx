import { useState, type ReactNode } from 'react'
import { Alert, Checkbox, Modal, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  currencyName,
  formatExpiry,
  formatPriceMicros,
  formatRatioPpm,
  priceKindLabel,
  writeCount,
  zeroPriceChanges,
  type PriceChange,
  type PriceField,
  type PriceChangeKind,
} from './priceChange'

const { Text } = Typography

interface PriceChangeConfirmProps {
  changes: PriceChange[]
  onConfirm: () => void
  onCancel: () => void
  confirmLoading?: boolean
}

const KIND_COLOR: Record<PriceChangeKind, string> = {
  to_zero: 'red',
  new: 'blue',
  adjust: 'orange',
  extras_only: 'purple',
  unchanged: 'default',
}

// 有变化：旧值灰色删除线 → 新值加粗；没变化或没有旧版本：只显示值。
function diffCell(oldText: string | null, newText: string, changed: boolean): ReactNode {
  if (!changed || oldText === null) return changed ? <Text strong>{newText}</Text> : <span>{newText}</span>
  return <span><Text delete type="secondary">{oldText}</Text>{' → '}<Text strong>{newText}</Text></span>
}

const ratioText = (snapshot: PriceChange['next']) => (
  `基础 ${formatPriceMicros(snapshot.baseInput, snapshot.currency)} × 模型 ${formatRatioPpm(snapshot.modelRatioPpm)} × 输出 ${formatRatioPpm(snapshot.completionRatioPpm)}`
)

// 失效时间变化：控制台提交从不带失效时间，覆盖一个带失效时间的版本等于取消它，需要明确告诉用户。
function expiryHint(change: PriceChange): ReactNode {
  if (!change.changedFields.includes('expiresAt') || !change.old) return null
  const { old, next } = change
  if (next.expiresAt === null && old.expiresAt !== null) {
    return <Space direction="vertical" size={0}>
      <Tag color="orange">取消失效时间</Tag>
      <Text type="secondary" style={{ fontSize: 12 }}>原失效 {formatExpiry(old.expiresAt)}</Text>
    </Space>
  }
  return <Text type="secondary" style={{ fontSize: 12 }}>失效时间 {formatExpiry(old.expiresAt)} → {formatExpiry(next.expiresAt)}</Text>
}

const anyChanged = (change: PriceChange, fields: PriceField[]) => change.changedFields.some(field => fields.includes(field))
const isRatio = (change: PriceChange) => change.next.mode === 'newapi_ratio'

export default function PriceChangeConfirm({ changes, onConfirm, onCancel, confirmLoading }: PriceChangeConfirmProps) {
  const [acknowledged, setAcknowledged] = useState(false)
  const zeroChanges = zeroPriceChanges(changes)
  const count = writeCount(changes)
  const blocked = zeroChanges.length > 0 && !acknowledged

  const priceCell = (field: 'input' | 'output' | 'cacheRead' | 'cacheWrite', ratioField: PriceField | null) => (_: unknown, change: PriceChange) => {
    const { old, next } = change
    // 计费方式发生切换（直接单价 ↔ 倍率）时，旧值只在「输入」列整体展示一次，其余列只显示新值。
    const modeSwitched = old !== null && old.mode !== next.mode
    const oldLabel = (snapshot: NonNullable<typeof old>) => (
      snapshot.mode === 'newapi_ratio'
        ? ratioText(snapshot)
        : `${formatPriceMicros(snapshot.input, snapshot.currency)} / ${formatPriceMicros(snapshot.output, snapshot.currency)}`
    )
    if (isRatio(change)) {
      // 倍率行：输入列显示「基础 × 模型倍率 × 输出倍率」（与输出列合并），缓存列显示倍率。
      if (field === 'input') {
        const changed = anyChanged(change, ['mode', 'baseInput', 'modelRatioPpm', 'completionRatioPpm', 'currency'])
        return diffCell(old ? oldLabel(old) : null, ratioText(next), changed)
      }
      if (field === 'output') return null
      const value = field === 'cacheRead' ? next.cachedRatioPpm : next.cacheWriteRatioPpm
      const text = value === null ? '未设置' : `×${formatRatioPpm(value)}`
      if (!old || modeSwitched) return diffCell(null, text, change.changed)
      const oldValue = field === 'cacheRead' ? old.cachedRatioPpm : old.cacheWriteRatioPpm
      const oldText = oldValue === null ? '未设置' : `×${formatRatioPpm(oldValue)}`
      return diffCell(oldText, text, anyChanged(change, [ratioField as PriceField]))
    }
    const format = (snapshot: PriceChange['next']) => formatPriceMicros(snapshot[field], snapshot.currency)
    if (modeSwitched) return diffCell(field === 'input' && old ? oldLabel(old) : null, format(next), true)
    return diffCell(old ? format(old) : null, format(next), anyChanged(change, ['currency', field]))
  }

  const columns: ColumnsType<PriceChange> = [
    {
      title: '模型', key: 'model', render: (_, change) => <span>
        <Text strong>{change.modelLabel}</Text>
        {change.modelLabel !== change.modelName && <Text type="secondary" style={{ fontSize: 12 }}> {change.modelName}</Text>}
      </span>,
    },
    {
      title: '币种', key: 'currency', render: (_, change) => diffCell(
        change.old ? currencyName(change.old.currency) : null, currencyName(change.next.currency), anyChanged(change, ['currency']),
      ),
    },
    { title: '输入', key: 'input', onCell: change => ({ colSpan: isRatio(change) ? 2 : 1 }), render: priceCell('input', null) },
    { title: '输出', key: 'output', onCell: change => ({ colSpan: isRatio(change) ? 0 : 1 }), render: priceCell('output', null) },
    { title: '缓存读', key: 'cacheRead', render: priceCell('cacheRead', 'cachedRatioPpm') },
    { title: '缓存写', key: 'cacheWrite', render: priceCell('cacheWrite', 'cacheWriteRatioPpm') },
    {
      title: '提示', key: 'hint', render: (_, change) => <Space direction="vertical" size={2}>
        <Tag color={KIND_COLOR[change.kind]}>{priceKindLabel[change.kind]}</Tag>
        {expiryHint(change)}
      </Space>,
    },
  ]

  return <Modal
    open
    title="确认价格变更"
    width={900}
    okText={`确认写入 ${count} 个模型`}
    cancelText="取消"
    maskClosable={false}
    confirmLoading={confirmLoading}
    okButtonProps={{ disabled: blocked || count === 0, danger: zeroChanges.length > 0 }}
    onOk={onConfirm}
    onCancel={onCancel}
  >
    {zeroChanges.length > 0 && <>
      <Alert
        type="error"
        showIcon
        style={{ marginBottom: 12 }}
        message={`以下 ${zeroChanges.length} 个模型的输入、输出价格将被改成 0，相当于免费：${zeroChanges.map(change => change.modelLabel).join('、')}`}
      />
      <Checkbox checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} style={{ marginBottom: 12 }}>
        我已核对，确认把以上模型的价格改成 0
      </Checkbox>
    </>}
    <Table<PriceChange>
      rowKey="modelName"
      size="small"
      pagination={false}
      columns={columns}
      dataSource={changes}
      scroll={{ y: 360 }}
    />
    <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>单位：每百万 Token；标记「无变化」的模型不会写入。</Text>
  </Modal>
}
