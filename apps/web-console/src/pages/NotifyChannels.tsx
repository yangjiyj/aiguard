import { useState } from 'react'
import { ConfigProvider, Tag, Button, Modal, Form, Input, Select, Switch, Space, Popconfirm, message, Spin } from 'antd'
import { EditOutlined, DeleteOutlined, MailOutlined, LinkOutlined, CommentOutlined, SendOutlined, WechatWorkOutlined, MessageOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import ResizableTable from '../components/ResizableTable'
import { EnterprisePageHeader } from '../components/EnterpriseUI'
import { notifyApi } from '../services/api'
import { extractApiError } from '../utils/apiError'
import ConfirmSwitch from '../components/protection/ConfirmSwitch'
import { useAccess } from '../hooks/useAccess'

// 与后端 notify.dispatchChannel 实际支持的渠道类型一一对应（类型取值见 024_notify_channels.sql 注释）
const CHANNEL_TYPES = [
  { value: 'email', label: '邮件', icon: <MailOutlined /> },
  { value: 'webhook', label: 'Webhook', icon: <LinkOutlined /> },
  { value: 'dingtalk', label: '钉钉', icon: <CommentOutlined /> },
  { value: 'wecom', label: '企业微信', icon: <WechatWorkOutlined /> },
  { value: 'feishu', label: '飞书', icon: <MessageOutlined /> },
] as const

type ChannelType = 'email' | 'webhook' | 'dingtalk' | 'wecom' | 'feishu'

// 新建弹窗切换类型时需要清空的全部配置字段
const ALL_CONFIG_FIELDS = ['host', 'port', 'from', 'to', 'url', 'method', 'access_token', 'secret', 'webhook_url', 'key']
// 渠道地址是内网时默认拒绝；打开后网关会向内网地址发通知（不含回环和链路本地）。只有平台级角色能打开。
const PRIVATE_TARGET_KEY = 'allow_private_target'
const PRIVATE_TARGET_RISK = '允许连内网地址（回环、链路本地、元数据地址仍拒绝）'

interface NotifyChannel {
  id: string
  type: ChannelType
  name: string
  enabled: boolean
  config_json: Record<string, any>
}

const TYPE_LABELS: Record<ChannelType, string> = {
  email: '邮件',
  webhook: 'Webhook',
  dingtalk: '钉钉',
  wecom: '企业微信',
  feishu: '飞书',
}

const TYPE_COLORS: Record<ChannelType, string> = {
  email: 'blue',
  webhook: 'green',
  dingtalk: 'orange',
  wecom: 'cyan',
  feishu: 'geekblue',
}

// config_json 字段的友好标签（用于编辑弹窗按现有键渲染）
const CONFIG_FIELD_LABELS: Record<string, string> = {
  host: 'SMTP 主机',
  port: '端口',
  from: '发件人',
  to: '收件人（逗号分隔）',
  url: 'URL',
  method: '请求方法',
  access_token: 'Access Token',
  secret: '签名密钥',
  webhook_url: '机器人 Webhook 地址',
  key: '机器人 Key',
}

export default function NotifyChannels() {
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [editingChannel, setEditingChannel] = useState<NotifyChannel | null>(null)
  const [createForm] = Form.useForm()
  const [editForm] = Form.useForm()
  const queryClient = useQueryClient()
  const canEnablePrivateTarget = useAccess().isPlatformLevel

  // 列表查询（后端返回 {channels: [...]}）
  const { data: channels, isLoading } = useQuery({
    queryKey: ['notify-channels'],
    queryFn: async () => {
      const res = await notifyApi.list()
      return (res.data as any).channels as NotifyChannel[]
    },
  })

  // 创建
  const createMutation = useMutation({
    mutationFn: async (data: { type: ChannelType; name: string; config_json: Record<string, any> }) => {
      const res = await notifyApi.create(data)
      return res.data
    },
    onSuccess: () => {
      message.success('渠道创建成功')
      queryClient.invalidateQueries({ queryKey: ['notify-channels'] })
      setCreateModalOpen(false)
      createForm.resetFields()
    },
    onError: () => message.error('创建失败'),
  })

  // 更新
  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: { name: string; config_json: Record<string, any>; enabled: boolean } }) => {
      const res = await notifyApi.update(id, data)
      return res.data
    },
    onSuccess: () => {
      message.success('更新成功')
      queryClient.invalidateQueries({ queryKey: ['notify-channels'] })
      setEditModalOpen(false)
      setEditingChannel(null)
      editForm.resetFields()
    },
    onError: () => message.error('更新失败'),
  })

  // 删除
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await notifyApi.delete(id)
      return res.data
    },
    onSuccess: () => {
      message.success('删除成功')
      queryClient.invalidateQueries({ queryKey: ['notify-channels'] })
    },
    onError: () => message.error('删除失败'),
  })

  // 发送测试消息（后端 POST /notify-channels/{id}/test，禁用的渠道也可测试）
  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await notifyApi.test(id)
      return res.data
    },
    onSuccess: () => message.success('测试消息已发送，请到对应渠道查收'),
    onError: (e: any) => message.error(extractApiError(e) || '测试消息发送失败'),
  })

  // 启用/禁用切换
  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled, name, config_json }: { id: string; enabled: boolean; name: string; config_json: Record<string, any> }) => {
      const res = await notifyApi.update(id, { name, config_json, enabled })
      return res.data
    },
    onSuccess: (_data, variables) => {
      message.success(variables.enabled ? '已启用' : '已禁用')
      queryClient.invalidateQueries({ queryKey: ['notify-channels'] })
    },
    onError: () => message.error('操作失败'),
  })

  // 打开编辑弹窗
  const openEditModal = (channel: NotifyChannel) => {
    setEditingChannel(channel)
    editForm.setFieldsValue({
      name: channel.name,
      type: channel.type,
      ...channel.config_json,
    })
    setEditModalOpen(true)
  }

  // 处理创建提交
  const handleCreate = () => {
    createForm.validateFields().then((values) => {
      const { type, name, allow_private_target, ...config } = values
      const config_json = buildConfigJson(type, config)
      // 只有打开时才写入，未打开保持原来的配置结构（服务端缺省即拒绝内网地址）。
      if (allow_private_target) config_json.allow_private_target = true
      createMutation.mutate({ type, name, config_json })
    })
  }

  // 处理编辑提交：按现有 config_json 的键重建，避免强塞类型 schema 字段
  const handleEdit = () => {
    if (!editingChannel) return
    editForm.validateFields().then((values) => {
      const config_json: Record<string, any> = {}
      Object.keys(editingChannel.config_json).forEach((key) => {
        if (key === PRIVATE_TARGET_KEY) return
        config_json[key] = values[key]
      })
      if (values[PRIVATE_TARGET_KEY] || PRIVATE_TARGET_KEY in editingChannel.config_json) {
        config_json[PRIVATE_TARGET_KEY] = Boolean(values[PRIVATE_TARGET_KEY])
      }
      updateMutation.mutate({
        id: editingChannel.id,
        data: { name: values.name, config_json, enabled: editingChannel.enabled },
      })
    })
  }

  // 处理启用/禁用切换
  const handleToggle = (channel: NotifyChannel, newEnabled: boolean) => {
    toggleMutation.mutate({
      id: channel.id,
      enabled: newEnabled,
      name: channel.name,
      config_json: channel.config_json,
    })
  }

  // 构建 config_json（创建时按类型）
  const buildConfigJson = (type: ChannelType, config: Record<string, any>): Record<string, any> => {
    if (type === 'email') {
      const toStr = config.to || ''
      const toArr = toStr.split(',').map((s: string) => s.trim()).filter(Boolean)
      return {
        host: config.host,
        port: config.port,
        from: config.from,
        to: toArr,
      }
    }
    if (type === 'webhook') {
      return {
        url: config.url,
        method: config.method || 'POST',
      }
    }
    if (type === 'dingtalk') {
      return {
        access_token: config.access_token,
        secret: config.secret,
      }
    }
    if (type === 'wecom') {
      const out: Record<string, any> = {}
      if (config.webhook_url) out.webhook_url = config.webhook_url
      if (config.key) out.key = config.key
      return out
    }
    if (type === 'feishu') {
      return {
        webhook_url: config.webhook_url,
        secret: config.secret || '',
      }
    }
    return config
  }

  // 表格列定义
  const columns = [
    {
      title: '渠道名称',
      dataIndex: 'name',
      key: 'name',
      width: 200,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 120,
      render: (type: ChannelType) => (
        <Tag color={TYPE_COLORS[type]} icon={CHANNEL_TYPES.find(t => t.value === type)?.icon}>
          {TYPE_LABELS[type]}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 140,
      render: (enabled: boolean, record: NotifyChannel) => (
        <Space>
          <Switch
            aria-label="启用状态"
            checked={enabled}
            onChange={(newEnabled) => handleToggle(record, newEnabled)}
          />
          <Tag color={enabled ? 'green' : 'default'}>{enabled ? '启用' : '禁用'}</Tag>
        </Space>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
      render: (_: any, record: NotifyChannel) => (
        <Space>
          <Button
            aria-label="发送测试消息"
            icon={<SendOutlined />}
            loading={testMutation.isPending && testMutation.variables === record.id}
            onClick={() => testMutation.mutate(record.id)}
          >
            发送测试消息
          </Button>
          <Button aria-label="编辑" icon={<EditOutlined />} onClick={() => openEditModal(record)} />
          <Popconfirm
            title="删除确认"
            description="删除后无法恢复，确定继续？"
            onConfirm={() => deleteMutation.mutate(record.id)}
            okText="确认删除"
            cancelText="取消"
          >
            <Button aria-label="删除" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  // 动态配置字段（创建时按类型）
  const renderConfigFields = (type: ChannelType | undefined) => {
    if (!type) return null
    if (type === 'email') {
      return (
        <>
          <Form.Item name="host" label="SMTP 主机" rules={[{ required: true, message: '请输入 SMTP 主机' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="port" label="端口" rules={[{ required: true, message: '请输入端口' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="from" label="发件人" rules={[{ required: true, message: '请输入发件人邮箱' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="to" label="收件人（逗号分隔）" rules={[{ required: true, message: '请输入收件人' }]}>
            <Input placeholder="ops@example.com,sec@example.com" />
          </Form.Item>
        </>
      )
    }
    if (type === 'webhook') {
      return (
        <>
          <Form.Item name="url" label="URL" rules={[{ required: true, message: '请输入 URL' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="method" label="请求方法" initialValue="POST">
            <Select
              options={[
                { value: 'GET', label: 'GET' },
                { value: 'POST', label: 'POST' },
                { value: 'PUT', label: 'PUT' },
              ]}
            />
          </Form.Item>
        </>
      )
    }
    if (type === 'dingtalk') {
      return (
        <>
          <Form.Item name="access_token" label="Access Token" rules={[{ required: true, message: '请输入 Access Token' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="secret" label="签名密钥" rules={[{ required: true, message: '请输入签名密钥' }]}>
            <Input />
          </Form.Item>
        </>
      )
    }
    if (type === 'wecom') {
      return (
        <>
          <Form.Item
            name="webhook_url"
            label="机器人 Webhook 地址"
            extra="在企业微信群设置 → 群机器人中复制；也可以只填下方的 Key"
            rules={[({ getFieldValue }) => ({
              validator: (_, value) => (value || getFieldValue('key') ? Promise.resolve() : Promise.reject(new Error('请填写机器人 Webhook 地址或 Key'))),
            })]}
          >
            <Input placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." />
          </Form.Item>
          <Form.Item name="key" label="机器人 Key">
            <Input />
          </Form.Item>
        </>
      )
    }
    if (type === 'feishu') {
      return (
        <>
          <Form.Item name="webhook_url" label="机器人 Webhook 地址" rules={[{ required: true, message: '请输入机器人 Webhook 地址' }]}>
            <Input placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." />
          </Form.Item>
          <Form.Item name="secret" label="签名密钥（可选）" extra="机器人安全设置中开启「签名校验」时填写">
            <Input />
          </Form.Item>
        </>
      )
    }
    return null
  }

  return (
    <ConfigProvider button={{ autoInsertSpace: false }}>
    <div style={{ padding: 24 }}>
      <EnterprisePageHeader
        eyebrow="通知与告警"
        title="通知渠道配置"
        description="配置邮件、Webhook、钉钉、企业微信、飞书通知渠道，用于安全告警事件的实时触达。保存后可点「发送测试消息」验证配置。"
        actions={
          <Button
            type="primary"
            aria-label="新建渠道"
            onClick={() => setCreateModalOpen(true)}
          >
            新建渠道
          </Button>
        }
      />

      <Spin spinning={isLoading}>
        <ResizableTable
          rowKey="id"
          columns={columns}
          dataSource={channels || []}
          pagination={{ pageSize: 10 }}
        />
      </Spin>

      {/* 新建弹窗 */}
      <Modal
        title="新建通知渠道"
        open={createModalOpen}
        onCancel={() => setCreateModalOpen(false)}
        onOk={handleCreate}
        okText="确认"
        cancelText="取消"
        destroyOnClose
      >
        <Form form={createForm} layout="vertical">
          <Form.Item name="type" label="渠道类型" rules={[{ required: true, message: '请选择渠道类型' }]}>
            <Select
              aria-label="渠道类型"
              options={CHANNEL_TYPES.map(t => ({ value: t.value, label: t.label }))}
              onChange={() => createForm.resetFields(ALL_CONFIG_FIELDS)}
            />
          </Form.Item>
          <Form.Item name="name" label="渠道名称" rules={[{ required: true, message: '请输入渠道名称' }]}>
            <Input aria-label="渠道名称" />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, curr) => prev.type !== curr.type}>
            {({ getFieldValue }) => renderConfigFields(getFieldValue('type'))}
          </Form.Item>
          <Form.Item name={PRIVATE_TARGET_KEY} label="允许内网地址" valuePropName="checked">
            <ConfirmSwitch ariaLabel="允许内网地址" allowEnable={canEnablePrivateTarget} confirmTitle="允许内网地址？" confirmContent={PRIVATE_TARGET_RISK} />
          </Form.Item>
        </Form>
      </Modal>

      {/* 编辑弹窗：按现有 config_json 的键渲染输入框 */}
      <Modal
        title="编辑通知渠道"
        open={editModalOpen}
        onCancel={() => setEditModalOpen(false)}
        onOk={handleEdit}
        okText="确认"
        cancelText="取消"
        destroyOnClose
      >
        <Form form={editForm} layout="vertical">
          <Form.Item name="name" label="渠道名称" rules={[{ required: true, message: '请输入渠道名称' }]}>
            <Input aria-label="渠道名称" />
          </Form.Item>
          {editingChannel &&
            Object.keys(editingChannel.config_json).filter((key) => key !== PRIVATE_TARGET_KEY).map((key) => (
              <Form.Item key={key} name={key} label={CONFIG_FIELD_LABELS[key] || key}>
                <Input />
              </Form.Item>
            ))}
          <Form.Item name={PRIVATE_TARGET_KEY} label="允许内网地址" valuePropName="checked">
            <ConfirmSwitch ariaLabel="允许内网地址" allowEnable={canEnablePrivateTarget} confirmTitle="允许内网地址？" confirmContent={PRIVATE_TARGET_RISK} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
    </ConfigProvider>
  )
}
