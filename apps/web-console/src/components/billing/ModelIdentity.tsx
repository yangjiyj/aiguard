import { Button, Popover, Space, Typography } from 'antd'
import { InfoCircleOutlined } from '@ant-design/icons'
import { BILLING_SECTION_LABELS as labels } from './sectionLabels'

export default function ModelIdentity({ modelName, label, strong = false }: { modelName: string; label: string; strong?: boolean }) {
  return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, maxWidth: '100%' }}>
    <Typography.Text strong={strong} style={{ minWidth: 0, overflowWrap: 'anywhere' }}>{label}</Typography.Text>
    {modelName ? <Popover title={labels.modelTrace} trigger="click" content={<Space direction="vertical">
      <Typography.Text type="secondary">{labels.modelIdentifier}</Typography.Text>
      <Typography.Text code copyable={{ text: modelName }}>{modelName}</Typography.Text>
    </Space>}>
      <Button type="text" size="small" style={{ flexShrink: 0 }} aria-label={`${labels.modelTrace}：${label}`} icon={<InfoCircleOutlined />} />
    </Popover> : null}
  </span>
}
