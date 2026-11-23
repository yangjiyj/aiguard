import TwoDecimalInput from './TwoDecimalInput'
import { timezoneLabel } from './billingFormat'
import { useEffect, useState } from 'react'
import { Alert, Button, Card, Form, Input, Modal, Select, Space, TimePicker, Typography } from 'antd'
import dayjs from 'dayjs'
import { PlusOutlined } from '@ant-design/icons'
import { buildTariffTemplate, hasLegacyTariffDates, legacyTariffDateMessage, newTariffRule, rulesFromPlan, serializeTariffRules, tariffEditorCopy, tariffTemplateOptions, TariffEditorRule } from './tariffTemplates'

const { Text } = Typography
const weekdayOptions = ['周一', '周二', '周三', '周四', '周五', '周六', '周日'].map((label, index) => ({ value: index + 1, label }))
const bands = [{ value: 'peak', label: '高峰' }, { value: 'flat', label: '标准' }, { value: 'valley', label: '低谷 / 优惠' }, { value: 'custom', label: '自定义' }]


type Props = {
  open: boolean
  plan?: any
  modelOptions: Array<{ value: string; label: string }>
  loading: boolean
  onCancel: () => void
  onSave: (payload: Record<string, unknown>, publish: boolean) => void
}

const timeValue = (value: string) => dayjs(`2000-01-01T${value === '24:00' ? '00:00' : value}:00`)

export default function TariffPlanEditor({ open, plan, modelOptions, loading, onCancel, onSave }: Props) {
  const [name, setName] = useState('模型时段计费')
  const [timezone, setTimezone] = useState('Asia/Shanghai')
  const [template, setTemplate] = useState('workday')
  const [targets, setTargets] = useState<string[]>([])
  const [focusModel, setFocusModel] = useState('')
  const [rules, setRules] = useState<TariffEditorRule[]>([])
  const [error, setError] = useState('')
  const readOnly = hasLegacyTariffDates(plan)
  const initialModel = modelOptions[0]?.value || ''
  useEffect(() => {
    if (!open) return
    const initialRules = plan ? rulesFromPlan(plan) : buildTariffTemplate('workday', initialModel ? [initialModel] : [])
    setName(plan?.name || '模型时段计费')
    setTimezone(plan?.timezone || 'Asia/Shanghai')
    setRules(initialRules)
    const model = initialRules[0]?.model_name || initialModel
    setFocusModel(model)
    setTargets(model ? [model] : [])
    setTemplate('workday')
    setError('')
  }, [open, plan, initialModel])

  const updateRule = (key: string, values: Partial<TariffEditorRule>) => {
    if (!readOnly) setRules((current) => current.map((rule) => rule.key === key ? { ...rule, ...values } : rule))
  }
  const configuredModels = [...new Set(rules.map((rule) => rule.model_name))]
  const editorOptions = [...modelOptions, ...configuredModels.filter((model) => !modelOptions.some((option) => option.value === model)).map((value) => ({ value, label: value }))]
  const visibleRules = rules.filter((rule) => rule.model_name === focusModel)
  const applyTemplate = () => {
    if (readOnly) return
    try {
      if (!targets.length) throw new Error('请先选择要应用模板的模型')
      const generated = buildTariffTemplate(template, targets)
      setRules((current) => [...current.filter((rule) => !targets.includes(rule.model_name)), ...generated])
      setFocusModel(targets[0])
      setError('')
    } catch (failure) { setError((failure as Error).message) }
  }
  const save = (publish: boolean) => {
    try {
      if (readOnly) throw new Error(legacyTariffDateMessage)
      if (!name.trim()) throw new Error('请输入方案名称')
      if (!timezone.trim()) throw new Error('请选择计费时区')
      const expiresAt = plan?.expires_at && (plan.status === 'draft' || Date.parse(plan.expires_at) > Date.now()) ? plan.expires_at : undefined
      onSave({ name: name.trim(), timezone: timezone.trim(),
        effective_at: plan?.status === 'draft' && plan.effective_at ? plan.effective_at : new Date().toISOString(),
        ...(expiresAt ? { expires_at: expiresAt } : {}), rules: serializeTariffRules(rules) }, publish)
      setError('')
    } catch (failure) { setError((failure as Error).message) }
  }
  const copyCurrentSchedule = () => {
    if (readOnly) return
    if (!targets.length || !visibleRules.length) { setError('请先配置当前模型，并选择要复制到的模型'); return }
    const copied = targets.flatMap((model) => visibleRules.map((rule) => newTariffRule(model, {
      name: rule.name, band: rule.band, weekdays: [...rule.weekdays],
      start_time: rule.start_time, end_time: rule.end_time, multiplier: rule.multiplier,
    })))
    setRules((current) => [...current.filter((rule) => !targets.includes(rule.model_name)), ...copied])
    setError('')
  }
  return <Modal width={1040} title={plan ? `${readOnly ? '查看' : '编辑'} ${plan.name} · v${plan.version}` : '新增模型时段计费方案'} open={open} onCancel={onCancel} destroyOnHidden
    footer={<Space><Button onClick={onCancel}>{tariffEditorCopy.cancel}</Button>{!readOnly && <><Button loading={loading} onClick={() => save(false)}>{plan && plan.status !== 'draft' ? tariffEditorCopy.saveVersion : tariffEditorCopy.saveDraft}</Button><Button type="primary" loading={loading} onClick={() => save(true)}>{tariffEditorCopy.publish}</Button></>}</Space>}>
    {readOnly && <Alert showIcon type="warning" style={{ marginBottom: 16 }} message={legacyTariffDateMessage} data-testid="legacy-tariff-read-only" />}
    <Form layout="vertical">
      <Space wrap align="start">
        <Form.Item label={tariffEditorCopy.name} required><Input aria-label={tariffEditorCopy.name} value={name} onChange={(event) => setName(event.target.value)} disabled={!!plan} maxLength={120} style={{ width: 300 }} /></Form.Item>
        <Form.Item label={tariffEditorCopy.timezone} required><Select aria-label={tariffEditorCopy.timezone} value={timezone} onChange={setTimezone} disabled={readOnly} showSearch style={{ width: 230 }} options={[{ value: 'Asia/Shanghai', label: '北京时间' }, { value: 'UTC', label: '协调世界时' }, { value: 'America/New_York', label: '纽约时间' }, { value: timezone, label: timezoneLabel(timezone) }].filter((option, index, all) => all.findIndex((item) => item.value === option.value) === index)} /></Form.Item>
      </Space>
      {!readOnly && <Card size="small" title="快速套用模板" style={{ marginBottom: 16 }}>
        <Space wrap align="start">
          <Form.Item label={tariffEditorCopy.template}><Select aria-label={tariffEditorCopy.template} style={{ width: 250 }} value={template} onChange={setTemplate} options={tariffTemplateOptions} /></Form.Item>
          <Form.Item label={tariffEditorCopy.applyModels}><Select aria-label={tariffEditorCopy.applyModels} mode="multiple" maxTagCount={3} showSearch optionFilterProp="label" style={{ width: 480 }} value={targets} onChange={setTargets} options={editorOptions} placeholder="可搜索并选择多个模型" /></Form.Item>
          <Form.Item label=" "><Button onClick={() => setTargets(editorOptions.map((option) => option.value))}>{tariffEditorCopy.selectAll}</Button></Form.Item>
          <Form.Item label=" "><Button type="primary" ghost onClick={applyTemplate}>{tariffEditorCopy.apply(targets.length)}</Button></Form.Item>
        </Space>
      </Card>}
      <Space wrap align="end" style={{ marginBottom: 12 }}>
        <Form.Item label={tariffEditorCopy.editModel} style={{ marginBottom: 0 }}><Select aria-label={tariffEditorCopy.editModel} value={focusModel || undefined} onChange={setFocusModel} showSearch optionFilterProp="label" style={{ width: 460 }} options={editorOptions} /></Form.Item>
        <Form.Item label=" " style={{ marginBottom: 0 }}><Text type="secondary">共 {configuredModels.length} 个模型 / {rules.length} 条规则</Text></Form.Item>
        {!readOnly && <><Form.Item label=" " style={{ marginBottom: 0 }}><Button aria-label={tariffEditorCopy.addPeriod} disabled={!focusModel} icon={<PlusOutlined />} onClick={() => setRules((current) => [...current, newTariffRule(focusModel)])}>{tariffEditorCopy.addPeriod}</Button></Form.Item>
          <Form.Item label=" " style={{ marginBottom: 0 }}><Button disabled={!visibleRules.length || !targets.length} onClick={copyCurrentSchedule}>{tariffEditorCopy.copySchedule}</Button></Form.Item></>}
      </Space>
      <Space direction="vertical" style={{ width: '100%', maxHeight: 430, overflowY: 'auto', paddingRight: 8 }}>
        {visibleRules.map((rule, index) => <Card size="small" key={rule.key} title={`时段 ${index + 1}`} extra={!readOnly && <Form.Item style={{ marginBottom: 0 }}><Button danger type="link" onClick={() => setRules((current) => current.filter((item) => item.key !== rule.key))}>删除</Button></Form.Item>}>
          <Space wrap align="start">
            <Form.Item label="时段名称" required><Input aria-label={tariffEditorCopy.ruleName(index + 1)} style={{ width: 220 }} value={rule.name} maxLength={120} disabled={readOnly} onChange={(event) => updateRule(rule.key, { name: event.target.value })} /></Form.Item>
            <Form.Item label="类型"><Select style={{ width: 140 }} value={rule.band} options={bands} disabled={readOnly} onChange={(band) => updateRule(rule.key, { band })} /></Form.Item>
            {rule.special_date ? <Form.Item label="历史日期"><Input aria-label={tariffEditorCopy.legacyDate(index + 1)} value={rule.special_date} readOnly style={{ width: 150 }} /></Form.Item> : <Form.Item label="适用星期" required><Select aria-label={tariffEditorCopy.weekday(index + 1)} mode="multiple" maxTagCount="responsive" style={{ width: 280 }} value={rule.weekdays} options={weekdayOptions} disabled={readOnly} onChange={(weekdays) => updateRule(rule.key, { weekdays })} /></Form.Item>}
            <Form.Item label="开始（含）" required><TimePicker aria-label={tariffEditorCopy.start(index + 1)} value={timeValue(rule.start_time)} format="HH:mm" allowClear={false} showNow={false} disabled={readOnly} onChange={time => updateRule(rule.key, { start_time: time?.format('HH:mm') || rule.start_time })} style={{ width: 120 }} /></Form.Item>
            <Form.Item label="结束（不含）" required extra={rule.end_time === '24:00' ? '次日 00:00' : '可跨零点'}><TimePicker aria-label={tariffEditorCopy.end(index + 1)} value={timeValue(rule.end_time)} format="HH:mm" allowClear={false} showNow={false} disabled={readOnly} onChange={time => { const value = time?.format('HH:mm'); if (value) updateRule(rule.key, { end_time: value === '00:00' ? '24:00' : value }) }} style={{ width: 120 }} /></Form.Item>
            <Form.Item label="计费倍率" required>{readOnly ? <Input aria-label={tariffEditorCopy.multiplier(index + 1)} value={String(rule.multiplier)} readOnly style={{ width: 130 }} /> : <TwoDecimalInput aria-label={tariffEditorCopy.multiplier(index + 1)} value={rule.multiplier} min={0.000001} max={1000} onChange={(multiplier) => updateRule(rule.key, { multiplier })} style={{ width: 130 }} />}</Form.Item>
          </Space>
        </Card>)}
        {!visibleRules.length && <Alert type="info" message="该模型未设置时段，按原价计费。" />}
      </Space>
    </Form>
    {error && <Alert showIcon type="error" message={error} style={{ marginTop: 16 }} />}
  </Modal>
}
