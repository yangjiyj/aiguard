import { useState } from 'react'
import { Alert, Button, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message } from 'antd'
import { DeleteOutlined, EditOutlined, PlusOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { reverseProxyApi, type ReverseProxyRoute, type ReverseProxyRouteCreate, type ReverseProxyRouteUpdate } from '../services/api'
import EgressOverrideFields from '../components/protection/EgressOverrideFields'
import ConfirmSwitch from '../components/protection/ConfirmSwitch'
import { normalizeEgressOverrides } from '../utils/egressOverrides'
import { useAccess } from '../hooks/useAccess'

const { Title, Text } = Typography

const getGatewayAddr = () => {
  const configured = import.meta.env.VITE_PROXY_GATEWAY_ADDR
  if (configured) return configured.replace(/\/$/, '')
  if (typeof window === 'undefined') return ''
  const port = import.meta.env.VITE_PROXY_PORT || '8082'
  return `${window.location.protocol}//${window.location.hostname}:${port}`
}

type ReverseProxyFormValues = Omit<ReverseProxyRouteCreate, 'private_egress_cidrs'> & {
  private_egress_cidrs?: string
}

function ReverseProxy() {
  const queryClient = useQueryClient()
  const canEnableEgress = useAccess().isPlatformLevel
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRoute, setEditingRoute] = useState<ReverseProxyRoute | null>(null)
  const [form] = Form.useForm<ReverseProxyFormValues>()
  const allowPrivateEgress = Form.useWatch('allow_private_egress', form)

  const routesQuery = useQuery({
    queryKey: ['reverseProxyRoutes'],
    queryFn: () => reverseProxyApi.list(),
  })
  const gatewayAddr = getGatewayAddr()

  const createMutation = useMutation({
    mutationFn: (entry: ReverseProxyRouteCreate) => reverseProxyApi.create(entry),
    onSuccess: () => {
      message.success('添加成功')
      queryClient.invalidateQueries({ queryKey: ['reverseProxyRoutes'] })
      setModalOpen(false)
      form.resetFields()
    },
    onError: () => message.error('添加失败'),
  })

  const updateMutation = useMutation({
    mutationFn: (payload: { id: string; entry: ReverseProxyRouteUpdate }) =>
      reverseProxyApi.update(payload.id, payload.entry),
    onSuccess: () => {
      message.success('更新成功')
      queryClient.invalidateQueries({ queryKey: ['reverseProxyRoutes'] })
      setModalOpen(false)
      setEditingRoute(null)
      form.resetFields()
    },
    onError: () => message.error('更新失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => reverseProxyApi.delete(id),
    onSuccess: () => {
      message.success('删除成功')
      queryClient.invalidateQueries({ queryKey: ['reverseProxyRoutes'] })
    },
    onError: () => message.error('删除失败'),
  })

  const routes = routesQuery.data?.data?.data || []

  const openCreateModal = () => {
    setEditingRoute(null)
    form.resetFields()
    form.setFieldsValue({
      target_path_prefix: '',
      allow_private_egress: false,
      private_egress_cidrs: '',
      egress_overrides: {},
      security_enabled: true,
      stats_enabled: true,
      status: 'active',
      description: '',
    })
    setModalOpen(true)
  }

  const openEditModal = (route: ReverseProxyRoute) => {
    setEditingRoute(route)
    form.setFieldsValue({
      ...route,
      private_egress_cidrs: (route.private_egress_cidrs ?? []).join('\n'),
      egress_overrides: route.egress_overrides ?? {},
    })
    setModalOpen(true)
  }

  const submitRoute = (entry: ReverseProxyRouteCreate) => {
    if (editingRoute) {
      updateMutation.mutate({
        id: editingRoute.id,
        entry,
      })
      return
    }
    createMutation.mutate(entry)
  }

  const handleSubmit = (values: ReverseProxyFormValues) => {
    const privateEgressCIDRs = values.allow_private_egress
      ? (values.private_egress_cidrs || '')
          .split(/[\n,]/)
          .map((value) => value.trim())
          .filter(Boolean)
      : []
    const entry: ReverseProxyRouteCreate = {
      ...values,
      allow_private_egress: Boolean(values.allow_private_egress),
      private_egress_cidrs: privateEgressCIDRs,
      egress_overrides: normalizeEgressOverrides(values.egress_overrides),
    }
    // 二次确认在打开“允许私网回源”时做（与 MCP 服务一致），保存时不再重复弹出。
    submitRoute(entry)
  }

  const columns = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      width: 160,
    },
    {
      title: '路径前缀',
      dataIndex: 'path_prefix',
      key: 'path_prefix',
      width: 180,
      render: (value: string) => <Text code>{value}</Text>,
    },
    {
      title: '目标地址',
      dataIndex: 'target_url',
      key: 'target_url',
      width: 320,
      render: (value: string) => <Text code ellipsis style={{ maxWidth: 300, display: 'inline-block', verticalAlign: 'middle' }}>{value}</Text>,
    },
    {
      title: '客户端访问地址',
      key: 'endpoint',
      width: 300,
      render: (_: unknown, record: ReverseProxyRoute) => {
        if (record.status !== 'active') return <Text type="secondary">停用</Text>
        const prefix = record.path_prefix.endsWith('/') ? record.path_prefix : record.path_prefix + '/'
        const fullUrl = gatewayAddr + prefix
        return (
          <div>
            <div><Text code copyable style={{ fontSize: 12 }}>{fullUrl}</Text></div>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 2 }}>路径: {prefix}</div>
          </div>
        )
      },
    },
    {
      title: '安全策略',
      dataIndex: 'security_enabled',
      key: 'security_enabled',
      width: 110,
      render: (value: boolean) => <Tag color={value ? 'blue' : 'default'}>{value ? '启用' : '禁用'}</Tag>,
    },
    {
      title: '私网回源',
      dataIndex: 'allow_private_egress',
      key: 'allow_private_egress',
      width: 120,
      render: (value: boolean) => (
        <Tag color={value ? 'orange' : 'default'}>
          {value ? '已授权私网' : '仅公网'}
        </Tag>
      ),
    },
    {
      title: '统计',
      dataIndex: 'stats_enabled',
      key: 'stats_enabled',
      width: 70,
      render: (value: boolean) => <Tag color={value ? 'green' : 'default'}>{value ? '启用' : '禁用'}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (value: string) => <Tag color={value === 'active' ? 'green' : 'red'}>{value === 'active' ? '启用' : '停用'}</Tag>,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (value: string) => value ? new Date(value).toLocaleString() : '-',
    },
    {
      title: '操作',
      key: 'action',
      width: 150,
      render: (_: unknown, record: ReverseProxyRoute) => (
        <Space size={4}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEditModal(record)}>编辑</Button>
          <Popconfirm
            title="确认删除?"
            onConfirm={() => deleteMutation.mutate(record.id)}
            okText="确认"
            cancelText="取消"
          >
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>接入通道</Title>
        <Text style={{ fontSize: 13, color: 'var(--text-secondary)' }}>管理按路径前缀转发到上游服务的规则</Text>
      </div>

      <div className="table-card">
        <div style={{ padding: 20 }}>
          <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Text strong style={{ fontSize: 14, color: 'var(--text-primary)' }}>规则列表</Text>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreateModal}>添加规则</Button>
          </div>

          <Table
            columns={columns}
            dataSource={routes as ReverseProxyRoute[]}
            rowKey="id"
            loading={routesQuery.isLoading}
            pagination={{
              defaultPageSize: 10,
              showSizeChanger: true,
              showTotal: (total) => `共 ${total} 条`,
            }}
          />
        </div>
      </div>

      <Modal
        title={editingRoute ? '编辑反向代理规则' : '添加反向代理规则'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        footer={null}
        width={560}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit} style={{ marginTop: 16 }}>
          <Form.Item
            name="name"
            label="名称"
            rules={[{ required: true, message: '请输入名称' }]}
          >
            <Input placeholder="例如：豆包" />
          </Form.Item>

          <Form.Item
            name="path_prefix"
            label="路径前缀"
            rules={[
              { required: true, message: '请输入路径前缀' },
              {
                validator: (_, value) => !value || String(value).startsWith('/')
                  ? Promise.resolve()
                  : Promise.reject(new Error('路径前缀必须以 / 开头')),
              },
            ]}
          >
            <Input placeholder="/proxy/doubao" />
          </Form.Item>

          <Form.Item
            name="target_url"
            label="目标地址"
            rules={[
              { required: true, message: '请输入目标地址' },
              {
                validator: (_, value) => {
                  if (!value) {
                    return Promise.resolve()
                  }
                  try {
                    const parsed = new URL(value)
                    if (!parsed.protocol || !parsed.host) {
                      throw new Error('invalid')
                    }
                    return Promise.resolve()
                  } catch {
                    return Promise.reject(new Error('请输入合法的绝对 URL'))
                  }
                },
              },
            ]}
          >
            <Input placeholder="https://ark.cn-beijing.volces.com" />
          </Form.Item>

          <Form.Item
            name="target_path_prefix"
            label="目标路径前缀"
            rules={[
              {
                validator: (_, value) => !value || String(value).startsWith('/')
                  ? Promise.resolve()
                  : Promise.reject(new Error('目标路径前缀必须以 / 开头')),
              },
            ]}
          >
            <Input placeholder="/api/v3（选填）" />
          </Form.Item>

          <Form.Item name="allow_private_egress" label="允许私网回源" valuePropName="checked">
            {/* 与 MCP 服务一致：打开时二次确认，只有平台级角色能打开，已打开的租户级角色仍可关闭。 */}
            <ConfirmSwitch ariaLabel="允许私网回源" allowEnable={canEnableEgress} confirmTitle="允许私网回源？" />
          </Form.Item>

          {allowPrivateEgress && (
            <>
              <Alert
                type="warning"
                showIcon
                message="允许私网回源会扩大该路由的网络访问范围"
                description="仅填写必要的私网 CIDR。授权端口由目标地址限定。"
                style={{ marginBottom: 16 }}
              />
              <Form.Item
                name="private_egress_cidrs"
                label="允许的私网 CIDR"
                extra="每行一个 CIDR，也可使用英文逗号分隔。保存时服务端会严格校验、规范化并去重。"
                rules={[{ required: true, whitespace: true, message: '请至少填写一个私网 CIDR' }]}
              >
                <Input.TextArea rows={3} placeholder={'172.16.20.17/32\n10.20.30.0/24'} />
              </Form.Item>
            </>
          )}

          <EgressOverrideFields canEnable={canEnableEgress} />

          <Form.Item name="security_enabled" label="启用安全策略" valuePropName="checked">
            <Switch />
          </Form.Item>

          <Form.Item name="stats_enabled" label="启用流量统计" valuePropName="checked">
            <Switch />
          </Form.Item>

          <Form.Item name="status" label="状态" rules={[{ required: true, message: '请选择状态' }]}>
            <Select
              options={[
                { label: '启用', value: 'active' },
                { label: '停用', value: 'disabled' },
              ]}
            />
          </Form.Item>

          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} placeholder="选填" />
          </Form.Item>

          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setModalOpen(false)}>取消</Button>
              <Button
                type="primary"
                htmlType="submit"
                loading={createMutation.isPending || updateMutation.isPending}
              >
                提交
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default ReverseProxy
