import { Button, Empty, Popover, Space, Typography } from 'antd'
import { InfoCircleOutlined } from '@ant-design/icons'
import { formatMoneyMicros } from './billingFormat'
import { modelDisplayLabel } from './modelDisplay'
import { BILLING_SECTION_LABELS as labels } from './sectionLabels'
import './ModelCostDistribution.css'

export type ModelCostItem = {
  id: string
  name: string
  model_name?: string
  model_label?: string
  secondary?: string
  billable_micros: number | string
}

export default function ModelCostDistribution({ data, currency }: { data: ModelCostItem[]; currency: string }) {
  const total = data.reduce((sum, row) => sum + Number(row.billable_micros), 0)
  const rows = [...data].sort((a, b) => Number(b.billable_micros) - Number(a.billable_micros))
  if (!rows.length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
  return <div className="billing-model-distribution">
    {rows.map((row, index) => {
      const modelName = row.model_name || row.name || row.id
      const label = modelDisplayLabel(modelName, [{ ...row, model_name: modelName }])
      const share = total > 0 ? Number(row.billable_micros) / total : 0
      return <div className="billing-model-cost-row" key={row.id + ':' + row.name + ':' + (row.secondary || '')}>
        <div className="billing-model-cost-main">
          <span className="billing-model-cost-rank">{index + 1}</span>
          <span className="billing-model-cost-name">{label}</span>
          <Popover title={labels.modelTrace} trigger="click" content={<Space className="billing-model-cost-details" direction="vertical" size={4}>
            <Typography.Text strong>{label}</Typography.Text>
            <Typography.Text type="secondary">{labels.modelIdentifier}</Typography.Text>
            <Typography.Text code copyable={{ text: modelName }}>{modelName}</Typography.Text>
            {row.id && row.id !== modelName ? <Typography.Text code copyable={{ text: row.id }}>{row.id}</Typography.Text> : null}
            {row.secondary ? <Typography.Text type="secondary">{row.secondary}</Typography.Text> : null}
          </Space>}>
            <Button type="text" size="small" aria-label={`${labels.modelTrace}：${label}`} icon={<InfoCircleOutlined />} />
          </Popover>
          <Typography.Text className="billing-model-cost-amount" strong>{formatMoneyMicros(row.billable_micros, currency)}</Typography.Text>
          <Typography.Text className="billing-model-cost-share" type="secondary">{(share * 100).toFixed(1)}%</Typography.Text>
        </div>
        <div className="billing-model-cost-track" aria-hidden="true"><span style={{ width: `${Math.max(0, Math.min(100, share * 100))}%` }} /></div>
      </div>
    })}
  </div>
}
