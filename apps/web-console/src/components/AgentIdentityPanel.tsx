import { useState } from 'react'
import { Alert, App, Button, Checkbox, Descriptions, Drawer, Form, Input, List, Modal, Select, Space, Table, Tabs, Tag, Typography } from 'antd'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '../services/api'
import { AGENT_DEFINITIONS, agentSourceLabel, formatAgentType } from '../utils/agents'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'

import { identityScopeOptions, type IdentityRecord } from '../utils/agentIdentity'
interface IdentityRule extends IdentityRecord { id: string; scope: string; note: string; operator_id: string; operator_name?: string; revoked_at?: string }
const channelLabel = (v: string) => ({ forward: '正向代理', reverse: '反向代理', chat_completion: 'API 调用' }[v] || v || '未记录')
const environmentLabel = (v: string) => ({ customer: '业务环境', production: '生产环境', evaluation: '评测环境', test: '测试环境', development: '开发环境' }[v] || '其他环境')
const formatTime = (v: string) => new Date(v).toLocaleString('zh-CN', { hour12: false })
const scopeLabel = (v: string) => ({ request: '单条确认', fingerprint: '调用方＋特征', dedicated_key: '专用访问密钥' }[v] || v)

export default function AgentIdentityPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
 const identity = useAuditQueryIdentity()
 const qc = useQueryClient()
 const { message } = App.useApp()
 const [tab, setTab] = useState('pending')
 const [keyword, setKeyword] = useState('')
 const [offset, setOffset] = useState(0)
 const [selected, setSelected] = useState<IdentityRecord | null>(null)
 const [busy, setBusy] = useState(false)
 const [form] = Form.useForm()
 const scope = Form.useWatch('scope', form) || 'request'
 const pending = useQuery({ queryKey: ['agent-identities', identity, keyword, offset], enabled: open && tab === 'pending', queryFn: async () => (await apiClient.get('/agent-identities', { params: { keyword, offset } })).data as { items: IdentityRecord[]; has_more: boolean } })
 const rules = useQuery({ queryKey: ['agent-identity-rules', identity], enabled: open && tab === 'rules', queryFn: async () => (await apiClient.get('/agent-identities', { params: { view: 'rules' } })).data as IdentityRule[] })
 const refresh = async () => { await Promise.all(['agent-identities', 'agent-identity-rules', 'agent-stats', 'agent-distribution'].map(key => qc.invalidateQueries({ queryKey: [key] }))) }
 const save = async () => {
  const values = await form.validateFields().catch(() => null)
  if (!values) return
  setBusy(true)
  try { await apiClient.post('/agent-identities', { ...values, request_id: selected!.request_id }); setSelected(null); message.success('已保存，原始识别依据仍可追溯'); await refresh() }
  catch (e: any) { message.error(e.response?.data?.error?.message || e.response?.data?.message || '保存失败，请重试') }
  finally { setBusy(false) }
 }
 const revoke = async (id: string) => {
  setBusy(true)
  try { await apiClient.post('/agent-identities', { revoke_id: id }); message.success('已撤销，关联记录恢复原始识别结果'); await refresh() }
  catch { message.error('撤销失败，请重试') }
  finally { setBusy(false) }
 }
 const metadata = (a: IdentityRecord) => <Descriptions size="small" column={1} items={[
  { key: 'id', label: '请求 ID', children: <Typography.Text copyable>{a.request_id}</Typography.Text> },
  { key: 'client', label: '访问密钥', children: a.key_name || '未关联命名密钥' },
  { key: 'user', label: '归属账号', children: a.user_name || '未关联账号' },
  { key: 'application', label: '所属应用', children: a.project_name || '未关联应用' },
  { key: 'ip', label: '来源 IP', children: a.source_ip || '未留存' },
  { key: 'channel', label: '通道 / 环境', children: `${channelLabel(a.channel)} / ${environmentLabel(a.environment)}` },
  { key: 'ua', label: '客户端特征', children: <span style={{ overflowWrap: 'anywhere' }}>{a.user_agent || '未留存，无法据此识别'}</span> },
  { key: 'name', label: '客户端声明名称 / 类型', children: `${a.declared_name || '未提供'} / ${a.declared_type || '未提供'}` },
  { key: 'source', label: '原始识别依据', children: agentSourceLabel(a.source) },
 ]} />
 return <>
  <Drawer title="客户端身份管理" open={open} onClose={onClose} width="min(1100px, 100vw)" destroyOnClose>
   <Alert type="info" showIcon message="登记用于审计归属，客户端声明信息不等于身份认证。" description="仅修改经过确认的当前记录；持续登记从创建后生效。规则限定当前租户、环境、通道和调用方，以核实后的接入信息为准。" style={{ marginBottom: 16 }} />
   <Tabs activeKey={tab} onChange={setTab} items={[
    { key: 'pending', label: '待识别请求', children: <Space direction="vertical" style={{ width: '100%' }} size="middle">
     <Input.Search placeholder="搜索客户端声明名称、调用方、User-Agent 或 IP" allowClear onSearch={v => { setKeyword(v); setOffset(0) }} />
     <Typography.Text type="secondary">展示最近 7 天的待确认记录，每页 50 条。请结合接入配置核实客户端身份。</Typography.Text>
     {pending.isError ? <Alert type="error" message="加载失败" action={<Button onClick={() => pending.refetch()}>重试</Button>} /> : <Table<IdentityRecord> size="small" rowKey="request_id" loading={pending.isLoading} dataSource={pending.data?.items || []} pagination={false} scroll={{ x: 760 }} columns={[
      { title: '时间 / 原始名称', render: (_, a) => <><div>{formatTime(a.created_at)}</div><Tag color="orange">{a.agent_type === 'agent-tool-call' ? '客户端待识别' : `客户端声明：${a.agent_type}`}</Tag></> },
      { title: '来源', render: (_, a) => <><div>{a.source_ip || 'IP 未留存'}</div><Typography.Text type="secondary">{channelLabel(a.channel)}</Typography.Text></> },
      { title: '识别依据', render: (_, a) => agentSourceLabel(a.source) },
      { title: '操作', render: (_, a) => <Button onClick={() => { setSelected(a); form.resetFields() }}>核对并确认</Button> },
     ]} expandable={{ expandedRowRender: metadata }} />}
     <Space><Button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>上一页</Button><span>第 {offset / 50 + 1} 页</span><Button disabled={!pending.data?.has_more} onClick={() => setOffset(offset + 50)}>下一页</Button></Space>
    </Space> },
    { key: 'rules', label: '登记与确认记录', children: <>{rules.isError && <Alert type="error" message="登记记录加载失败" action={<Button onClick={() => rules.refetch()}>重试</Button>} />}<Typography.Text type="secondary">最近 200 条操作；撤销后恢复原始识别，撤销记录保留。</Typography.Text><List loading={rules.isLoading} dataSource={rules.data || []} renderItem={a => <List.Item actions={a.revoked_at ? [<Tag key="revoked">已撤销</Tag>] : [<Button key="revoke" danger disabled={busy} onClick={() => revoke(a.id)}>撤销</Button>]}><List.Item.Meta title={<Space wrap><Tag color="blue">{formatAgentType(a.agent_type)}</Tag><Tag>{scopeLabel(a.scope)}</Tag><span>{channelLabel(a.channel)} · {environmentLabel(a.environment)}</span></Space>} description={<><div style={{ overflowWrap: 'anywhere' }}>访问密钥：{a.key_name || '未关联命名密钥'} · {a.user_agent || a.declared_type || '单条确认'}</div><div>依据：{a.note}</div><div>操作人：{a.operator_name || '未关联账号'} · {formatTime(a.created_at)}</div></>} /></List.Item>} /></> },
   ]} />
  </Drawer>
  <Modal title="核对客户端身份" open={!!selected} onCancel={() => setSelected(null)} onOk={save} confirmLoading={busy} okText="保存确认" width={660} destroyOnClose>
   {selected && <>{metadata(selected)}<Form form={form} layout="vertical" initialValues={{ scope: 'request', dedicated_key: false }} preserve={false}>
    <Form.Item name="agent_type" label="实际使用的客户端" rules={[{ required: true, message: '请选择已核实的客户端' }]}><Select showSearch optionFilterProp="label" placeholder="选择已核实的客户端" options={AGENT_DEFINITIONS.filter(a => !['agent-tool-call', 'vscode'].includes(a.type)).map(a => ({ value: a.type, label: a.label }))} /></Form.Item>
    <Form.Item name="scope" label="适用范围"><Select options={identityScopeOptions(selected)} /></Form.Item>
    {scope === 'dedicated_key' && <Form.Item name="dedicated_key" valuePropName="checked" rules={[{ validator: (_, v) => v ? Promise.resolve() : Promise.reject(new Error('需要确认此访问密钥 只供该客户端使用')) }]}><Checkbox>我已核实此访问密钥 只供该客户端使用，不与其他客户端共享</Checkbox></Form.Item>}
    <Form.Item name="note" label="确认依据" rules={[{ required: true, min: 2, whitespace: true, message: '请填写客户端配置、接入登记等核实依据' }]}><Input.TextArea maxLength={1000} showCount rows={3} placeholder="例如：已核对应用配置，此调用方为团队专用 WorkBuddy 客户端" /></Form.Item>
   </Form></>}
  </Modal>
 </>
}
