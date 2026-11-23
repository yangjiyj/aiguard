import { useCurrencyStore } from '../../stores/currency'
import { useEffect, useState } from 'react'
import { Alert, Button, Card, Empty, DatePicker, Form, Input, Modal, Popconfirm, Select, Space, Table, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { billingEmployeeApi } from '../../services/api'
import { extractApiError } from '../../utils/apiError'
import TwoDecimalInput from './TwoDecimalInput'
import { formatMoneyMicros } from './billingFormat'

export default function ChannelFixedCostsPanel({ tenantID }: { tenantID: string }) {
  const cache = useQueryClient()
  const [open, setOpen] = useState(false)
  const [editingID, setEditingID] = useState<string | undefined>()
  const [form] = Form.useForm()
  const query = useQuery({ queryKey: ['channel-fixed-costs', tenantID], queryFn: () => billingEmployeeApi.fixedCosts(tenantID), enabled: !!tenantID })
  const settings = useQuery({ queryKey: ['employee-billing-settings', tenantID], queryFn: () => billingEmployeeApi.settings(tenantID), enabled: !!tenantID })
  const currency = settings.data?.data?.data?.currency || useCurrencyStore.getState().tenantCurrency
  const invalidate = async () => {
    await cache.invalidateQueries({ queryKey: ['channel-fixed-costs', tenantID] })
  }
  useEffect(() => { setOpen(false); form.resetFields() }, [tenantID, form])
  const save = useMutation({
    mutationFn: (data: any) => billingEmployeeApi.saveFixedCost(tenantID, data),
    onSuccess: async () => { setOpen(false); message.success('渠道固定费用已保存'); await invalidate() },
    onError: error => message.error(extractApiError(error) || '保存渠道固定费用失败'),
  })
  const remove = useMutation({
    mutationFn: (id: string) => billingEmployeeApi.deleteFixedCost(tenantID, id),
    onSuccess: async () => { message.success('渠道固定费用已删除'); await invalidate() },
    onError: error => message.error(extractApiError(error) || '删除渠道固定费用失败'),
  })
  const edit = (cost?: any) => {
    setEditingID(cost?.id)
    form.resetFields()
    form.setFieldsValue({ provider_id: cost?.provider_id, currency: cost?.currency || currency, amount: Number(cost?.amount_micros || 0) / 1_000_000,
      period: cost?.period || 'month', effective_from: dayjs(cost?.effective_from), effective_to: cost?.effective_to ? dayjs(cost.effective_to) : undefined, note: cost?.note || '' })
    setOpen(true)
  }
  return <Card title="渠道固定费用" extra={<Button type="primary" disabled={!tenantID || query.isError || settings.isError || settings.isLoading} onClick={() => edit()}>新增渠道固定费用</Button>}>
    {(query.isError || settings.isError) && <Alert showIcon type="error" message="渠道固定费用或计价币种加载失败" action={<Button onClick={() => { void query.refetch(); void settings.refetch() }}>重试</Button>} />}
    <Table rowKey="id" locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无渠道固定费用" /> }} dataSource={query.data?.data?.data || []} loading={query.isLoading} scroll={{ x: 880 }} columns={[
      { title: '渠道', dataIndex: 'provider_name' }, { title: '金额', render: (_: unknown, cost: any) => formatMoneyMicros(cost.amount_micros, cost.currency) },
      { title: '周期', dataIndex: 'period', render: period => period === 'year' ? '年' : '月' }, { title: '生效日期（含）', dataIndex: 'effective_from' },
      { title: '结束日期（不含）', dataIndex: 'effective_to', render: value => value || '持续生效' }, { title: '备注', dataIndex: 'note' },
      { title: '操作', render: (_: unknown, cost: any) => <Space><Button type="link" onClick={() => edit(cost)}>编辑</Button><Popconfirm title="确认删除渠道固定费用？" description="删除后固定费用将从历史成本统计中移除，相关统计会重新计算；操作写入审计记录。" okText="确认删除" cancelText="取消" onConfirm={() => remove.mutate(cost.id)}><Button danger type="link" loading={remove.isPending}>删除</Button></Popconfirm></Space> },
    ]} />
    <Modal title="渠道固定费用" open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} confirmLoading={save.isPending} destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={values => save.mutate({ id: editingID, provider_id: values.provider_id, currency: values.currency,
        amount_micros: Math.round(values.amount * 1_000_000), period: values.period, effective_from: values.effective_from.format('YYYY-MM-DD'),
        effective_to: values.effective_to?.format('YYYY-MM-DD') || null, note: values.note || '' })}>
        <Form.Item name="provider_id" label="渠道" rules={[{ required: true }]}><Select showSearch optionFilterProp="label" options={(query.data?.data?.channels || []).map((channel: any) => ({ value: channel.provider_id, label: channel.provider_name }))} /></Form.Item>
        <Space wrap align="start"><Form.Item name="amount" label="金额" rules={[{ required: true }]}><TwoDecimalInput min={0} max={1000000000} /></Form.Item>
          <Form.Item name="period" label="周期" rules={[{ required: true }]}><Select style={{ width: 100 }} options={[{ value: 'month', label: '月' }, { value: 'year', label: '年' }]} /></Form.Item>
          <Form.Item name="currency" label="租户计价币种" rules={[{ required: true }]}><Select style={{ width: 120 }} options={[{ value: currency, label: currency }]} /></Form.Item></Space>
        <Space wrap align="start"><Form.Item name="effective_from" label="生效日期（含）" rules={[{ required: true }]}><DatePicker format="YYYY-MM-DD" /></Form.Item>
          <Form.Item name="effective_to" label="结束日期（不含）" dependencies={['effective_from']} rules={[({ getFieldValue }) => ({ validator(_, value) { return !value || value.isAfter(getFieldValue('effective_from'), 'day') ? Promise.resolve() : Promise.reject(new Error('结束日期必须晚于生效日期')) } })]}><DatePicker format="YYYY-MM-DD" /></Form.Item></Space>
        <Form.Item name="note" label="备注"><Input.TextArea maxLength={4000} /></Form.Item>
      </Form>
    </Modal>
  </Card>
}
