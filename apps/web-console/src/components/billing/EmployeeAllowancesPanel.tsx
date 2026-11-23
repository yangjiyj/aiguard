import CurrencySwitch from './CurrencySwitch'
import { useAuthStore } from '../../stores/auth'
import { useCurrencyStore } from '../../stores/currency'
import { formatMicrosDecimal, UNKNOWN_MONEY } from '../../utils/money'
import { timezoneLabel, formatMicros } from './billingFormat'
import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Card, Col, Form, Modal, Row, Select, Space, Switch, Table, Tabs, Tag, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import AllowanceAmountInput from './AllowanceAmountInput'
import { billingEmployeeApi } from '../../services/api'
import { extractApiError } from '../../utils/apiError'

const money = (value: number | null | undefined, currency: string) => {
  if (value == null) return '未设置'
  const amount = formatMicrosDecimal(value)
  if (amount === null) return UNKNOWN_MONEY
  const code = String(currency || '').trim().toUpperCase()
  return code ? `${code} ${amount}` : formatMicros(value, currency)
}
function EmployeeDefaultSettings({ tenantID, cfg, onSave, saving, unavailable, onSwitch }: { tenantID: string; cfg: any; onSwitch: () => void; onSave: (values: any) => void; saving: boolean; unavailable: boolean }) {
  const [form] = Form.useForm()
  const role = useAuthStore(state => state.user?.role)
  const enabled = Form.useWatch('enabled', form)
  useEffect(() => { form.resetFields() }, [tenantID, form])
  useEffect(() => { if (cfg) form.setFieldsValue({ ...cfg, enabled: cfg.default_monthly_micros != null, amount: cfg.default_monthly_micros == null ? 1000 : cfg.default_monthly_micros / 1_000_000 }) }, [cfg, form])
  return <Card title="所有用户默认每月充值">
      <Form form={form} layout="vertical" initialValues={{ enabled: false, amount: 1000, currency: useCurrencyStore.getState().tenantCurrency, timezone: 'Asia/Shanghai' }} onFinish={onSave}>
        <Row gutter={16} align="top">
          <Col xs={24} sm={12} lg={4}><Form.Item name="enabled" label="启用每月充值" valuePropName="checked"><Switch style={{ marginBlock: 5 }} /></Form.Item></Col>
          <Col xs={24} sm={12} lg={4}><Form.Item name="currency" label="计费单位" rules={[{ required: true }]}><Select disabled options={[{ value: 'CNY', label: '人民币 CNY' }, { value: 'USD', label: '美元 USD' }]} /></Form.Item></Col>
          <Col xs={24} sm={12} lg={5}><Form.Item name="timezone" label="发放时区" rules={[{ required: true }]}><Select showSearch options={['Asia/Shanghai', 'UTC', 'America/New_York', 'Asia/Hong_Kong'].map(value => ({ value, label: timezoneLabel(value) }))} /></Form.Item></Col>
          <Col xs={24} sm={12} lg={11}><Form.Item label="每人每月金额" required={enabled}>
            <Form.Item name="amount" noStyle rules={enabled ? [{ required: true, message: '请输入充值金额' }] : []}><AllowanceAmountInput aria-label="默认每月充值" disabled={!enabled} /></Form.Item>
          </Form.Item></Col>
        </Row>
        {!!tenantID && !unavailable && !!cfg && role === 'platform_admin' && <Form.Item label="系统币种"><CurrencySwitch tenantID={tenantID} currency={cfg?.currency || useCurrencyStore.getState().tenantCurrency} onSuccess={onSwitch} /></Form.Item>}
        <Typography.Paragraph type="secondary" style={{ marginBottom: 12 }}>当月有效，剩余不结转；已发放的金额修改下月生效。</Typography.Paragraph>
        <Form.Item style={{ marginBottom: 0 }}><Button type="primary" htmlType="submit" loading={saving} disabled={!tenantID || unavailable}>保存每月充值</Button></Form.Item>
      </Form>
    </Card>
}

function EmployeeMonthlyEditor({ tenantID, section = 'all' }: { tenantID: string; billingMode?: string; section?: 'all' | 'defaults' | 'employees' }) {
  const cache = useQueryClient()
  const [selected, setSelected] = useState<React.Key[]>([])
  const [editOpen, setEditOpen] = useState(false)
  const [amount, setAmount] = useState<number | null>(1000)
  const [inherit, setInherit] = useState(false)
  const [editError, setEditError] = useState('')
  const currentTenant = useRef(tenantID)
  currentTenant.current = tenantID
  const settings = useQuery({ queryKey: ['employee-settings', tenantID], queryFn: () => billingEmployeeApi.settings(tenantID), enabled: !!tenantID })
  const employees = useQuery({ queryKey: ['employee-allowances', tenantID], queryFn: () => billingEmployeeApi.list(tenantID), enabled: !!tenantID && section !== 'defaults', refetchInterval: 5000 })
  const cfg = settings.data?.data?.data
  useEffect(() => { setSelected([]); setEditOpen(false); setAmount(1000); setInherit(false); setEditError('') }, [tenantID])
  const refresh = (tenant = tenantID) => { void cache.invalidateQueries({ queryKey: ['employee-settings', tenant] }); void cache.invalidateQueries({ queryKey: ['employee-allowances', tenant] }); void cache.invalidateQueries({ queryKey: ['billing-customers', tenant] }); void cache.invalidateQueries({ queryKey: ['billing-ledger', tenant] }) }
  const save = useMutation({ mutationFn: (input: { tenant: string; values: any }) => billingEmployeeApi.saveSettings(input.tenant, { currency: input.values.currency, timezone: input.values.timezone, default_monthly_micros: input.values.enabled ? Math.round(input.values.amount * 1_000_000) : null }), onSuccess: (_, input) => { refresh(input.tenant); message.success('每月充值设置已保存') }, onError: e => message.error(extractApiError(e) || '保存失败') })
  const batch = useMutation({ mutationFn: (input: { tenant: string; users: string[]; amount: number | null }) => billingEmployeeApi.saveAllowances(input.tenant, input.users, input.amount), onSuccess: (_, input) => { refresh(input.tenant); if (currentTenant.current === input.tenant) { setEditOpen(false); setSelected([]) } message.success('指定用户充值设置已保存') }, onError: e => message.error(extractApiError(e) || '保存失败') })
  const submitPersonal = () => {
    if (!inherit && (amount === null || !Number.isFinite(amount) || amount < 0 || amount > 1000000000)) { setEditError('请输入有效的充值金额'); return }
    if (!selected.length) { setEditError('请先选择用户'); return }
    setEditError('')
    batch.mutate({ tenant: tenantID, users: selected.map(String), amount: inherit ? null : Math.round(Number(amount) * 1_000_000) })
  }
  useEffect(() => { if (cfg?.currency) useCurrencyStore.getState().setTenantCurrency(cfg.currency) }, [cfg?.currency])
  const rows = employees.data?.data?.data || []
  const currency = cfg?.currency || useCurrencyStore.getState().tenantCurrency
  return <Space direction="vertical" style={{ width: '100%' }} size={16}>
    {(settings.isError || (section !== 'defaults' && employees.isError)) && <Alert type="error" message="充值设置加载失败" action={<Button onClick={() => refresh()}>重试</Button>} />}
    {section !== 'employees' ? <EmployeeDefaultSettings onSwitch={() => { refresh(); void cache.invalidateQueries({ queryKey: ['employee-billing-settings', tenantID] }); void cache.invalidateQueries({ queryKey: ['billing-prices', tenantID] }); void cache.invalidateQueries({ queryKey: ['upstream-rates', tenantID] }); void cache.invalidateQueries({ queryKey: ['channel-fixed-costs', tenantID] }) }} tenantID={tenantID} cfg={cfg} onSave={values => save.mutate({ tenant: tenantID, values })} saving={save.isPending} unavailable={settings.isLoading || settings.isError} /> : null}
    {section !== 'defaults' && <Card title="指定用户每月充值" extra={<Button disabled={!selected.length} onClick={() => { setAmount(1000); setInherit(false); setEditError(''); setEditOpen(true) }}>批量设置（{selected.length} 人）</Button>}>
      <Table rowKey="user_id" rowSelection={{ selectedRowKeys: selected, onChange: setSelected }} dataSource={rows} loading={employees.isLoading} pagination={{ pageSize: 20 }} scroll={{ x: 900 }} columns={[
        { title: '用户', dataIndex: 'username' }, { title: '部门', dataIndex: 'department_name' },
        { title: '每月充值', render: (_: unknown, r: any) => <Space>{money(r.effective_micros, r.currency)}<Tag>{r.monthly_micros == null ? '默认充值' : '指定金额'}</Tag></Space> },
        { title: '本月已充', render: (_: unknown, r: any) => money(r.monthly_status?.granted_micros ?? 0, r.currency) },
        { title: '赠送可用余额', render: (_: unknown, r: any) => money(Math.max(0, (r.monthly_status?.remaining_micros ?? 0) - (r.monthly_status?.reserved_micros ?? 0)), r.currency) },
        { title: '到期时间', render: (_: unknown, r: any) => r.monthly_status?.expires_at ? new Date(r.monthly_status.expires_at).toLocaleString() : '—' },

        { title: '操作', render: (_: unknown, r: any) => <Button type="link" onClick={() => { setSelected([r.user_id]); setAmount((r.monthly_micros ?? r.effective_micros ?? 0) / 1000000); setInherit(r.monthly_micros == null); setEditError(''); setEditOpen(true) }}>编辑充值</Button> },
      ]} />
    </Card>}
    {section !== 'defaults' && editOpen && <Modal title={`设置 ${selected.length} 人的每月充值`} okText="保存" cancelText="取消" open onCancel={() => setEditOpen(false)} onOk={submitPersonal} confirmLoading={batch.isPending}>
      <Form layout="vertical">
        <Form.Item label="使用默认充值"><Switch aria-label="使用默认充值" checked={inherit} onChange={setInherit} /></Form.Item>
        <Form.Item label="每月充值金额"><AllowanceAmountInput aria-label="每月充值金额" prefix={currency} value={amount} onChange={setAmount} disabled={inherit} /></Form.Item>
        {editError && <Alert showIcon type="error" message={editError} />}
      </Form>
    </Modal>}
  </Space>
}

export default function EmployeeAllowancesPanel(props: { tenantID: string; billingMode?: string; section?: 'all' | 'defaults' | 'employees' }) {
  if (props.section && props.section !== 'all') return <EmployeeMonthlyEditor {...props} />
  return <Tabs items={[
    { key: 'defaults', label: '所有用户默认充值', children: <EmployeeMonthlyEditor {...props} section="defaults" /> },
    { key: 'employees', label: '指定用户充值', children: <EmployeeMonthlyEditor {...props} section="employees" /> },
  ]} />
}
