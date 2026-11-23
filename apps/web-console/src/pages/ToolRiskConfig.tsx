import { useState } from 'react'
import { Alert, AutoComplete, Button, Form, Input, Modal, Select, Space, Table, Tag, Tooltip, Typography, message } from 'antd'
import { PlusOutlined, ReloadOutlined, UndoOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toolRiskConfigApi, type ObservedTool } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useSecurityExecutionMode } from '../hooks/useSecurityExecutionMode'

const { Title, Text } = Typography
type ToolType = 'file' | 'network' | 'database' | 'mcp' | 'system'
interface ToolConfig { id: string; tool_name: string; tool_type: ToolType; risk_level: string; action: string; description?: string }
const types = [{ value: 'file', label: '文件' }, { value: 'network', label: '网络' }, { value: 'database', label: '数据库' }, { value: 'mcp', label: 'MCP' }, { value: 'system', label: '系统命令' }]
const knownType = (value?: string): value is ToolType => types.some((item) => item.value === value)

export default function ToolRiskConfig() {
  const client = useQueryClient()
  const role = useAuthStore((state) => state.user?.role)
  const tenant = useAuthStore((state) => state.user?.tenant_id)
  const actor = useAuthStore((state) => state.user?.id)
  const canManage = role === 'platform_admin' || role === 'security_officer'
  const [form] = Form.useForm<{ tool_name: string; tool_type?: ToolType; description?: string }>()
  const [adding, setAdding] = useState(false)
  const name = Form.useWatch('tool_name', form) || ''
  const query = useQuery({ queryKey: ['toolRiskConfigs', tenant, actor], queryFn: () => toolRiskConfigApi.list() })
  const suggestions = useQuery({ queryKey: ['toolRiskConfigs', tenant, actor, 'suggestions'], queryFn: () => toolRiskConfigApi.list({ observed: true }), enabled: adding })
  const mode = useSecurityExecutionMode()
  const effectiveMode = mode.isError ? undefined : mode.mode?.effective_mode
  const configs: ToolConfig[] = Array.isArray(query.data?.data?.data) ? query.data.data.data : []
  const disabledTools = configs.filter((item) => item.action === 'block')
  const existing = configs.find((item) => item.tool_name === name)
  const observations: ObservedTool[] = suggestions.data?.data?.observed_source === 'tenant_gateway_observations' && Array.isArray(suggestions.data.data.observed_tools) ? suggestions.data.data.observed_tools : []
  const observed = observations.find((item) => item.tool_name === name)
  const inferred = existing?.tool_type || (knownType(observed?.runtime_tool_type) ? observed.runtime_tool_type : undefined)
  const options = observations.filter((item) => item.invocation_proposed_count > 0 && !disabledTools.some((rule) => rule.tool_name === item.tool_name)).map((item) => ({ value: item.tool_name }))
  const refresh = () => client.invalidateQueries({ queryKey: ['toolRiskConfigs'] })
  const disable = useMutation({
    mutationFn: async (values: { tool_name: string; tool_type?: ToolType; description?: string }) => {
      const current = configs.find((item) => item.tool_name === values.tool_name)
      const type = current?.tool_type || inferred || values.tool_type
      if (!type || !values.tool_name.trim()) throw new Error('请确认工具名称和类别')
      const metadata = { tool_type: type, risk_level: current?.risk_level || 'medium', action: 'block', description: values.description || current?.description || '' }
      if (current) return toolRiskConfigApi.update(current.id, metadata)
      return toolRiskConfigApi.create({ tool_name: values.tool_name, ...metadata })
    },
    onSuccess: async () => { await refresh(); setAdding(false); form.resetFields(); message.success('已加入禁用名单') },
    onError: () => message.error('保存失败，请重试'),
  })
  const restore = useMutation({
    mutationFn: (item: ToolConfig) => toolRiskConfigApi.update(item.id, { tool_type: item.tool_type, risk_level: item.risk_level, action: 'audit', description: item.description }),
    onSuccess: async () => { await refresh(); message.success('已移出禁用名单') },
    onError: () => message.error('保存失败，请重试'),
  })
  const confirmDisable = (values: { tool_name: string; tool_type?: ToolType; description?: string }) => Modal.confirm({
    title: `禁用工具 ${values.tool_name}？`,
    content: '禁用涵盖这个精确名称的全部调用，包括正常操作。防护模式下阻断，仅记录模式下留痕。',
    okText: '确认禁用', okButtonProps: { danger: true },
    onOk: () => disable.mutateAsync(values),
  })
  const confirmRestore = (item: ToolConfig) => Modal.confirm({
    title: `移出禁用名单：${item.tool_name}？`, content: '恢复按智能体行为规则处理，原工具类别配置保留。', okText: '移出名单',
    onOk: () => restore.mutateAsync(item),
  })
  return <div className="enterprise-page">
    <Space wrap style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
      <Title level={4} style={{ margin: 0 }}>工具禁用</Title>
      <Space wrap><Tag>默认：行为规则</Tag><Tag>{effectiveMode === 'record' ? '仅记录：禁用暂不拦截' : effectiveMode === 'protect' ? '防护：禁用生效' : '执行模式待确认'}</Tag><Tooltip title="刷新"><Button icon={<ReloadOutlined />} aria-label="刷新禁用名单" onClick={() => query.refetch()} /></Tooltip><Button icon={<PlusOutlined aria-hidden="true" />} disabled={!canManage || query.isError || query.isLoading} onClick={() => { form.resetFields(); setAdding(true) }}>禁用工具</Button></Space>
    </Space>
    {query.isError && <Alert type="error" showIcon message="禁用名单读取失败" />}
    <Table<ToolConfig> rowKey="id" dataSource={disabledTools} loading={query.isLoading} pagination={{ pageSize: 20 }} scroll={{ x: 640 }} locale={{ emptyText: '暂无禁用工具' }} columns={[
      { title: '工具名称', dataIndex: 'tool_name', render: (value: string) => <Text code>{value}</Text> },
      { title: '生效处理', render: () => <Tag color={effectiveMode === 'protect' ? 'red' : undefined}>{effectiveMode === 'protect' ? '阻断调用' : effectiveMode === 'record' ? '仅留记录' : '待确认'}</Tag> },
      { title: '备注', dataIndex: 'description', ellipsis: true },
      { title: '操作', width: 76, render: (_: unknown, item: ToolConfig) => <Tooltip title="移出禁用名单"><Button icon={<UndoOutlined />} aria-label={`移出禁用名单 ${item.tool_name}`} disabled={!canManage} loading={restore.isPending && restore.variables?.id === item.id} onClick={() => confirmRestore(item)} /></Tooltip> },
    ]} />
    <Modal title="禁用指定工具" open={adding} onCancel={() => setAdding(false)} onOk={() => form.submit()} okText="加入禁用名单" okButtonProps={{ 'aria-label': '加入禁用名单', disabled: !canManage || query.isError || query.isLoading || Boolean(existing?.action === 'block') }} confirmLoading={disable.isPending} destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={confirmDisable}>
        <Form.Item name="tool_name" label="精确工具名称" rules={[{ required: true, whitespace: true }]}><AutoComplete options={options} filterOption={(input, option) => String(option?.value || '').toLowerCase().includes(input.toLowerCase())}><Input maxLength={255} /></AutoComplete></Form.Item>
        {inferred ? <Form.Item label="工具类别"><Tag>{types.find((item) => item.value === inferred)?.label}</Tag></Form.Item> : <Form.Item name="tool_type" label="工具类别" rules={[{ required: true }]}><Select options={types} /></Form.Item>}
        {existing?.action === 'block' && <Tag>已在禁用名单</Tag>}
        <Form.Item name="description" label="禁用原因"><Input.TextArea maxLength={500} /></Form.Item>
      </Form>
    </Modal>
  </div>
}
