import { Button, Card, Space, Tag, Typography } from 'antd'
import { EditOutlined } from '@ant-design/icons'
import type { ModelRoutingRule } from '../../services/api'
import { strategyLabel } from './routingLabels'

export default function DefaultRoutingCard({ rule, onEdit, readOnly = false }: { rule: ModelRoutingRule | null; onEdit: () => void; readOnly?: boolean }) {
  return (
    <Card className="model-routing-rule-card">
      <div className="model-routing-card-row">
        <div>
          <Space size={10} wrap>
            <Typography.Title level={5}>全局默认规则</Typography.Title>
            <Tag color={rule?.enabled ? 'green' : 'default'}>{rule ? '已生效' : '待配置'}</Tag>
          </Space>
          <Typography.Paragraph type="secondary">
            适用于所有未单独配置的多线路模型；以后新同步的模型会自动继承，无需逐个维护。
          </Typography.Paragraph>
          <Space wrap>
            <Typography.Text strong>{strategyLabel(rule)}</Typography.Text>
            {rule && <Typography.Text type="secondary">{rule.config.providers.filter((item) => item.enabled).length} 条参与线路</Typography.Text>}
          </Space>
        </div>
        {!readOnly && <Button type="primary" icon={<EditOutlined />} onClick={onEdit} aria-label="编辑默认规则">{rule ? '编辑默认规则' : '配置默认规则'}</Button>}
      </div>
    </Card>
  )
}
