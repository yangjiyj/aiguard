import { Button, Popconfirm, Space, Table, Tag, Typography } from 'antd'
import { DeleteOutlined, EditOutlined, PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import type { ModelRoutingException } from '../../services/api'
import { strategyLabel } from './routingLabels'

interface Props {
  items: ModelRoutingException[]
  deleting: boolean
  onAdd: () => void
  onEdit: (item: ModelRoutingException) => void
  onDelete: (modelName: string) => void
  readOnly?: boolean
}

export default function ModelOverridesTable({ items, deleting, onAdd, onEdit, onDelete, readOnly = false }: Props) {
  const columns: ColumnsType<ModelRoutingException> = [
    { title: '模型', dataIndex: 'model_name', key: 'model_name', render: (value: string) => <Typography.Text strong>{value}</Typography.Text> },
    { title: '路由方式', key: 'strategy', render: (_, item) => <Tag color="blue">{strategyLabel(item)}</Tag> },
    { title: '参与线路', key: 'providers', responsive: ['md'], render: (_, item) => `${item.config.providers.filter((rule) => rule.enabled).length} 条` },
    ...(!readOnly ? [{
      title: '操作', key: 'actions', width: 176, render: (_, item) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => onEdit(item)} aria-label={`编辑 ${item.model_name}`}>编辑</Button>
          <Popconfirm title="删除后将立即恢复全局默认规则，确认删除？" onConfirm={() => onDelete(item.model_name)}>
            <Button size="small" danger loading={deleting} icon={<DeleteOutlined />} aria-label={`删除 ${item.model_name}`}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    } satisfies ColumnsType<ModelRoutingException>[number]] : []),
  ]

  return (
    <section aria-labelledby="model-overrides-title">
      <div className="model-routing-section-heading">
        <div>
          <Space align="center">
            <Typography.Title id="model-overrides-title" level={5}>特殊模型配置</Typography.Title>
            <Tag>{items.length} 个特殊配置</Tag>
          </Space>
          <Typography.Text type="secondary">这里只显示管理员主动创建的例外；其余模型自动使用全局默认规则。</Typography.Text>
        </div>
        {!readOnly && <Button icon={<PlusOutlined />} onClick={onAdd} aria-label="添加特殊模型">添加特殊模型</Button>}
      </div>
      <div className="table-card">
        <Table rowKey="model_name" columns={columns} dataSource={items} pagination={false} locale={{ emptyText: '暂无特殊配置，所有模型使用全局默认规则' }} />
      </div>
    </section>
  )
}
