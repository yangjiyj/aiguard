import { useState } from 'react'
import { Alert, Button, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import { useMutation } from '@tanstack/react-query'
import { proxyApi, securitySystemSettingsApi, type ProxyWhitelist, type ProxyWhitelistCreate } from '../services/api'
import ConfirmSwitch from '../components/protection/ConfirmSwitch'
import ConfirmSelect from '../components/protection/ConfirmSelect'
import { useSettingsForm } from '../hooks/useSettingsForm'
import { extractApiError } from '../utils/apiError'
import { serializeList, settingBool, settingChoice, settingList, settingSourceNotice } from '../utils/settingsValue'

const { Title } = Typography

// 白名单数据由页面统一读取（与覆盖状态同一个查询），这里只负责展示与增删改。
export function ProxyWhitelistTable({ canManage, rows, loading, onChanged }: { canManage: boolean; rows: ProxyWhitelist[]; loading: boolean; onChanged: () => unknown }) {
  const [editing, setEditing] = useState<ProxyWhitelist | 'new' | null>(null)
  const [form] = Form.useForm<ProxyWhitelistCreate>()
  const refresh = async () => { await onChanged() }
  const saveM = useMutation({
    mutationFn: (values: ProxyWhitelistCreate) => {
      const entry = { ...values, host_pattern: values.host_pattern.trim(), port: values.port || 0, description: values.description?.trim() || '' }
      return editing && editing !== 'new' ? proxyApi.updateWhitelist(editing.id, entry) : proxyApi.createWhitelist(entry)
    },
    onSuccess: async () => { message.success('已保存'); setEditing(null); await refresh() },
    onError: (error) => message.error(extractApiError(error) || '保存失败'),
  })
  const deleteM = useMutation({
    mutationFn: (id: string) => proxyApi.deleteWhitelist(id),
    onSuccess: async () => { message.success('已删除'); await refresh() },
    onError: (error) => message.error(extractApiError(error) || '删除失败'),
  })
  const open = (row: ProxyWhitelist | 'new') => {
    form.resetFields()
    form.setFieldsValue(row === 'new'
      ? { host_pattern: '', port: undefined, audit_enabled: true, description: '' }
      : { host_pattern: row.host_pattern, port: row.port || undefined, audit_enabled: row.audit_enabled, description: row.description })
    setEditing(row)
  }

  return (
    <section aria-label="出站白名单" style={{ marginTop: 24 }}>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 12 }}>
        <Title level={5} style={{ margin: 0 }}>出站白名单</Title>
        <Button type="primary" icon={<PlusOutlined />} disabled={!canManage} onClick={() => open('new')}>添加白名单</Button>
      </Space>
      <Table<ProxyWhitelist>
        rowKey="id"
        size="small"
        pagination={false}
        loading={loading}
        dataSource={rows}
        locale={{ emptyText: '暂无白名单' }}
        columns={[
          { title: '主机', dataIndex: 'host_pattern' },
          { title: '端口', dataIndex: 'port', width: 100, render: (port?: number) => port ? port : '全部' },
          { title: '审计', dataIndex: 'audit_enabled', width: 90, render: (value: boolean) => value ? <Tag color="blue">审计</Tag> : <Tag>不审计</Tag> },
          { title: '说明', dataIndex: 'description', render: (value?: string) => value || '-' },
          {
            title: '操作',
            key: 'actions',
            width: 140,
            render: (_: unknown, row: ProxyWhitelist) => (
              <Space size={4}>
                <Button size="small" type="link" disabled={!canManage} onClick={() => open(row)}>编辑</Button>
                <Popconfirm title={`删除 ${row.host_pattern}？`} okText="删除" cancelText="取消" disabled={!canManage} onConfirm={() => deleteM.mutate(row.id)}>
                  <Button size="small" type="link" danger disabled={!canManage}>删除</Button>
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
      <Modal
        title={editing === 'new' ? '添加白名单' : '编辑白名单'}
        open={editing !== null}
        onCancel={() => setEditing(null)}
        onOk={() => form.submit()}
        okText="保存"
        cancelText="取消"
        confirmLoading={saveM.isPending}
        forceRender
      >
        <Form form={form} layout="vertical" onFinish={(values) => saveM.mutate(values)}>
          <Form.Item name="host_pattern" label="主机" rules={[{ required: true, whitespace: true, message: '请输入主机' }]}>
            <Input placeholder="api.example.com 或 *.example.com" />
          </Form.Item>
          <Form.Item name="port" label="端口">
            <InputNumber min={1} max={65535} precision={0} placeholder="全部端口" style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="audit_enabled" label="审计" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="description" label="说明">
            <Input maxLength={200} />
          </Form.Item>
        </Form>
      </Modal>
    </section>
  )
}

const EGRESS_SWITCHES = [
  { key: 'forward_proxy_egress_allow_private', label: '允许访问内网地址' },
  { key: 'forward_proxy_egress_allow_loopback', label: '允许访问回环地址' },
  { key: 'forward_proxy_egress_allow_metadata', label: '允许访问云元数据地址' },
] as const

type EgressFormValues = {
  forward_proxy_unlisted_action: 'deny' | 'allow_audit'
  proxy_whitelist_fail_mode: 'closed' | 'open'
  forward_proxy_egress_allow_private: boolean
  forward_proxy_egress_allow_loopback: boolean
  forward_proxy_egress_allow_metadata: boolean
  forward_proxy_egress_allowed_cidrs: string[]
  forward_proxy_egress_allowed_hosts: string[]
}

function egressValues(settings: Record<string, unknown>): EgressFormValues {
  return {
    forward_proxy_unlisted_action: settingChoice(settings.forward_proxy_unlisted_action, ['deny', 'allow_audit'] as const, 'deny'),
    proxy_whitelist_fail_mode: settingChoice(settings.proxy_whitelist_fail_mode, ['closed', 'open'] as const, 'closed'),
    forward_proxy_egress_allow_private: settingBool(settings.forward_proxy_egress_allow_private),
    forward_proxy_egress_allow_loopback: settingBool(settings.forward_proxy_egress_allow_loopback),
    forward_proxy_egress_allow_metadata: settingBool(settings.forward_proxy_egress_allow_metadata),
    forward_proxy_egress_allowed_cidrs: settingList(settings.forward_proxy_egress_allowed_cidrs),
    forward_proxy_egress_allowed_hosts: settingList(settings.forward_proxy_egress_allowed_hosts),
  }
}

const UNLISTED_RISK = '网关可被用来访问未登记的地址。'

function egressPatch(values: EgressFormValues): Record<string, unknown> {
  return {
    forward_proxy_unlisted_action: values.forward_proxy_unlisted_action,
    proxy_whitelist_fail_mode: values.proxy_whitelist_fail_mode,
    forward_proxy_egress_allow_private: Boolean(values.forward_proxy_egress_allow_private),
    forward_proxy_egress_allow_loopback: Boolean(values.forward_proxy_egress_allow_loopback),
    forward_proxy_egress_allow_metadata: Boolean(values.forward_proxy_egress_allow_metadata),
    forward_proxy_egress_allowed_cidrs: serializeList(values.forward_proxy_egress_allowed_cidrs),
    forward_proxy_egress_allowed_hosts: serializeList(values.forward_proxy_egress_allowed_hosts),
  }
}

const saveEgress = (patch: Record<string, unknown>) => securitySystemSettingsApi.update(patch)

export function ForwardProxyEgressForm({ canManage }: { canManage: boolean }) {
  const { form, query: settingsQ, mutation: saveM, submit } = useSettingsForm({ toValues: egressValues, toPatch: egressPatch, save: saveEgress })
  const disabled = !canManage || !settingsQ.isSuccess || saveM.isPending
  const notice = (key: string) => {
    const text = settingSourceNotice(settingsQ.data, key)
    return text ? <Typography.Text type="warning">{text}</Typography.Text> : undefined
  }

  return (
    <section aria-label="出站限制" style={{ marginTop: 24, maxWidth: 640 }}>
      <Title level={5} style={{ marginBottom: 12 }}>出站限制</Title>
      {settingsQ.isError ? <Alert type="error" showIcon message="出站限制读取失败" style={{ marginBottom: 12 }} /> : null}
      <Form form={form} layout="vertical" disabled={disabled} initialValues={egressValues({})} onFinish={submit}>
        <Space size={16} wrap>
          <Form.Item name="forward_proxy_unlisted_action" label="未登记目标" extra={notice('forward_proxy_unlisted_action')}>
            <ConfirmSelect ariaLabel="未登记目标" style={{ width: 180 }} options={[{ value: 'deny', label: '拒绝' }, { value: 'allow_audit', label: '放行并审计' }]} riskyValues={['allow_audit']} confirmTitle="未登记目标改为放行？" confirmContent={UNLISTED_RISK} />
          </Form.Item>
          <Form.Item name="proxy_whitelist_fail_mode" label="白名单读取失败" extra={notice('proxy_whitelist_fail_mode')}>
            <ConfirmSelect ariaLabel="白名单读取失败" style={{ width: 180 }} options={[{ value: 'closed', label: '拒绝' }, { value: 'open', label: '放行' }]} riskyValues={['open']} confirmTitle="白名单读取失败时放行？" confirmContent={UNLISTED_RISK} />
          </Form.Item>
        </Space>
        {EGRESS_SWITCHES.map(({ key, label }) => (
          <Form.Item key={key} name={key} label={label} valuePropName="checked" extra={notice(key)}>
            <ConfirmSwitch ariaLabel={label} disabled={disabled} confirmTitle={`${label}？`} />
          </Form.Item>
        ))}
        <Form.Item name="forward_proxy_egress_allowed_cidrs" label="放行网段" extra={notice('forward_proxy_egress_allowed_cidrs')}>
          <Select aria-label="放行网段" mode="tags" tokenSeparators={[',', ' ']} placeholder="10.20.0.0/16" open={false} />
        </Form.Item>
        <Form.Item name="forward_proxy_egress_allowed_hosts" label="放行主机名" extra={notice('forward_proxy_egress_allowed_hosts')}>
          <Select aria-label="放行主机名" mode="tags" tokenSeparators={[',', ' ']} placeholder="只跳过按名字的判断，内网地址仍需放行网段" open={false} />
        </Form.Item>
        <Button type="primary" htmlType="submit" disabled={disabled} loading={saveM.isPending}>保存出站限制</Button>
      </Form>
    </section>
  )
}
