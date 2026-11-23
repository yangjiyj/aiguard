import { useCurrencyStore } from '../../stores/currency'
import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Divider, Drawer, Form, InputNumber, Radio, Select, Space, Switch, Typography } from 'antd'
import TwoDecimalInput from '../billing/TwoDecimalInput'
import type {
  ModelRoutingConfig,
  ModelRoutingCostBasis,
  ModelRoutingProviderOption,
  ModelRoutingValidationResult,
} from '../../services/api'

interface Props {
  open: boolean
  modelName?: string
  scope?: 'default' | 'model'
  initialConfig: ModelRoutingConfig
  providerOptions: ModelRoutingProviderOption[]
  validating: boolean
  saving: boolean
  validation?: ModelRoutingValidationResult
  canSave: boolean
  onClose: () => void
  onValidate: (config: ModelRoutingConfig) => void
  onSave: (config: ModelRoutingConfig) => void
  onDirty: (config: ModelRoutingConfig) => void
}

type LoadMode = 'failover' | 'weighted' | 'stability' | 'latency' | 'cost' | 'balanced'

const LOAD_MODES: Array<{ value: LoadMode; label: string; detail: string }> = [
  { value: 'failover', label: '主备切换', detail: '按顺序优先使用主上游，失败后切换备用' },
  { value: 'weighted', label: '按权重分流', detail: '按比例把请求分配到多个上游，可用于分摊容量' },
  { value: 'stability', label: '稳定优先', detail: '根据成功率和延迟，优先选择近期更稳定的上游' },
  { value: 'latency', label: '速度优先', detail: '优先选择近期响应更快的上游' },
  { value: 'cost', label: '成本优先', detail: '在可用上游中优先选择成本较低的线路' },
  { value: 'balanced', label: '综合均衡', detail: '综合稳定性、速度与已维护的成本信息动态选择' },
]

function cloneConfig(config: ModelRoutingConfig): ModelRoutingConfig {
  return JSON.parse(JSON.stringify(config)) as ModelRoutingConfig
}

function modeFromConfig(config: ModelRoutingConfig): LoadMode {
  if (config.strategy === 'weighted') return 'weighted'
  if (config.strategy === 'smart') {
    if (config.objective === 'latency') return 'latency'
    if (config.objective === 'cost') return 'cost'
    if (config.objective === 'balanced') return 'balanced'
    return 'stability'
  }
  return 'failover'
}

export default function RuleEditorDrawer(props: Props) {
  const [draft, setDraft] = useState<ModelRoutingConfig>(() => cloneConfig(props.initialConfig))
  const [mode, setModeState] = useState<LoadMode>(() => modeFromConfig(props.initialConfig))
  const [localError, setLocalError] = useState('')
  const [narrow, setNarrow] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 720px)').matches)
  const providerName = useMemo(() => new Map(props.providerOptions.map((item) => [item.route_ref, item.display_name])), [props.providerOptions])

  useEffect(() => {
    const media = window.matchMedia('(max-width: 720px)')
    const update = () => setNarrow(media.matches)
    update()
    media.addEventListener?.('change', update)
    return () => media.removeEventListener?.('change', update)
  }, [])

  useEffect(() => {
    if (props.open) {
      setDraft(cloneConfig(props.initialConfig))
      setModeState(modeFromConfig(props.initialConfig))
      setLocalError('')
    }
  }, [props.open, props.initialConfig])

  const change = (next: ModelRoutingConfig) => {
    setDraft(next)
    setLocalError('')
    props.onDirty(next)
  }

  const setMode = (nextMode: LoadMode) => {
    setModeState(nextMode)
    const providers = draft.providers.map((item, index) => ({ ...item, enabled: true, priority: item.priority || index + 1, weight: item.weight || Math.max(1, Math.floor(100 / draft.providers.length)) }))
    if (nextMode === 'failover') {
      change({ strategy: 'priority', cost_basis: 'none', providers })
      return
    }
    if (nextMode === 'weighted') {
      change({ strategy: 'weighted', cost_basis: 'none', providers })
      return
    }
    const objective = nextMode === 'stability' ? 'stability' : nextMode
    change({ strategy: 'smart', objective, cost_basis: nextMode === 'cost' ? (draft.cost_basis === 'none' ? 'relative' : draft.cost_basis) : 'none', providers })
  }

  const setCostBasis = (cost_basis: ModelRoutingCostBasis) => change({ ...draft, cost_basis })
  const updateProvider = (index: number, field: string, value: unknown) => change({ ...draft, providers: draft.providers.map((item, i) => i === index ? { ...item, [field]: value } : item) })

  const check = () => {
    const enabled = draft.providers.filter((item) => item.enabled)
    if (enabled.length < 2) {
      setLocalError('多路径负载至少需要启用两个上游。')
      return
    }
    if (draft.strategy === 'weighted' && enabled.some((item) => !item.weight || item.weight <= 0)) {
      setLocalError('每个参与分流的上游都需要填写大于 0 的权重。')
      return
    }
    if (draft.strategy === 'smart' && draft.objective === 'cost' && draft.cost_basis === 'none') {
      setLocalError('成本优先需要维护相对成本或实际采购价。')
      return
    }
    props.onValidate(draft)
  }

  const totalWeight = draft.providers.filter((item) => item.enabled).reduce((sum, item) => sum + (item.weight || 0), 0)

  return (
    <Drawer
      className="model-routing-drawer"
      title={props.scope === 'default' ? '配置系统默认负载方式' : props.modelName ? `配置多路径负载 · ${props.modelName}` : '配置多路径负载'}
      open={props.open}
      onClose={props.onClose}
      width={narrow ? '100vw' : 680}
      styles={{ wrapper: { maxWidth: '100vw' }, body: { overflowX: 'hidden' }, footer: { overflowX: 'hidden' } }}
      destroyOnHidden
      footer={<div className="model-routing-drawer-footer"><Button onClick={props.onClose}>取消</Button><Button onClick={check} loading={props.validating}>检查配置</Button><Button type="primary" disabled={!props.canSave} loading={props.saving} onClick={() => props.onSave(draft)}>保存配置</Button></div>}
    >
      <Alert
        type="info"
        showIcon
        message={props.scope === 'default' ? '适用于所有未单独配置的多上游模型' : `只在 ${props.modelName || '当前模型'} 的同名上游之间分配`}
        description={props.scope === 'default' ? '以后新增的多上游模型也会自动继承。运行时只使用当前模型实际存在的同名上游，不会切换成其他模型。' : '不会把请求切换成其他模型。上游异常时，系统会继续尝试本配置中其余可用上游。'}
      />
      <Form layout="vertical" className="model-routing-form">
        <Form.Item label="负载方式" required extra="选择请求在多个同名上游之间如何分配。">
          <Radio.Group value={mode} onChange={(event) => setMode(event.target.value)} className="model-routing-choice-grid">
            {LOAD_MODES.map((item) => <Radio.Button key={item.value} value={item.value}><span>{item.label}</span><small>{item.detail}</small></Radio.Button>)}
          </Radio.Group>
        </Form.Item>

        <Divider orientation="left">参与上游</Divider>
        <div className="model-routing-provider-list">
          {draft.providers.map((provider, index) => {
            const name = providerName.get(provider.route_ref) || `上游 ${index + 1}`
            return (
              <div className="model-routing-provider-row" key={provider.route_ref}>
                <div><Space><Switch size="small" checked={provider.enabled} aria-label={`${name}参与负载`} onChange={(enabled) => updateProvider(index, 'enabled', enabled)} /><Typography.Text strong>{name}</Typography.Text></Space><Typography.Text type="secondary">{mode === 'failover' ? (index === 0 ? '主上游' : `备用上游 ${index}`) : '参与请求分配'}</Typography.Text></div>
                {mode === 'failover' && <Space.Compact><Button disabled>优先级</Button><InputNumber min={1} disabled={!provider.enabled} value={provider.priority} aria-label={`${name}优先级`} onChange={(value) => updateProvider(index, 'priority', value || index + 1)} /></Space.Compact>}
                {mode === 'weighted' && <Space.Compact><Button disabled>权重</Button><InputNumber min={1} max={10000} disabled={!provider.enabled} value={provider.weight} aria-label={`${name}权重`} onChange={(value) => updateProvider(index, 'weight', value || 1)} /></Space.Compact>}
              </div>
            )
          })}
        </div>
        {mode === 'weighted' && <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>当前总权重 {totalWeight}；系统按各上游权重占比分流，无需强制合计为 100。</Typography.Paragraph>}

        {mode === 'cost' && <>
          <Divider orientation="left">成本依据</Divider>
          <Form.Item extra="成本仅由管理员维护；系统不会猜测采购价。">
            <Radio.Group value={draft.cost_basis || 'none'} onChange={(event) => setCostBasis(event.target.value)} className="model-routing-cost-options">
              <Radio value="relative">相对成本（低 / 中 / 高）</Radio>
              <Radio value="actual">实际采购价</Radio>
            </Radio.Group>
          </Form.Item>
          {draft.cost_basis === 'relative' && draft.providers.map((provider, index) => <Form.Item key={provider.route_ref} label={providerName.get(provider.route_ref) || `上游 ${index + 1}`}><Select value={provider.relative_cost} placeholder="选择相对成本" options={[{ value: 'low', label: '低' }, { value: 'medium', label: '中' }, { value: 'high', label: '高' }]} onChange={(value) => updateProvider(index, 'relative_cost', value)} /></Form.Item>)}
          {draft.cost_basis === 'actual' && draft.providers.map((provider, index) => <Form.Item key={provider.route_ref} label={providerName.get(provider.route_ref) || `上游 ${index + 1}`} extra="每百万 Token 的采购价"><Space wrap><Select style={{ width: 96 }} value={provider.actual_cost?.currency || useCurrencyStore.getState().tenantCurrency} options={[{ value: 'CNY', label: '人民币' }, { value: 'USD', label: '美元' }]} onChange={(currency) => updateProvider(index, 'actual_cost', { currency, input_per_million: provider.actual_cost?.input_per_million || 0, output_per_million: provider.actual_cost?.output_per_million || 0 })} /><TwoDecimalInput min={0} addonBefore="输入" value={provider.actual_cost?.input_per_million} onChange={(value) => updateProvider(index, 'actual_cost', { currency: provider.actual_cost?.currency || useCurrencyStore.getState().tenantCurrency, input_per_million: value || 0, output_per_million: provider.actual_cost?.output_per_million || 0 })} /><TwoDecimalInput min={0} addonBefore="输出" value={provider.actual_cost?.output_per_million} onChange={(value) => updateProvider(index, 'actual_cost', { currency: provider.actual_cost?.currency || useCurrencyStore.getState().tenantCurrency, input_per_million: provider.actual_cost?.input_per_million || 0, output_per_million: value || 0 })} /></Space></Form.Item>)}
        </>}
      </Form>
      {localError && <Alert type="error" showIcon message={localError} />}
      {props.validation && <Alert className="model-routing-validation" type={props.validation.valid ? 'success' : 'error'} showIcon message={props.validation.valid ? '配置检查通过' : '配置检查未通过'} description={<Space direction="vertical" size={2}><span>参与上游（{props.validation.provider_count} 条）：{props.validation.provider_names.join('、') || '无'}</span>{props.validation.warnings.map((warning) => <span key={warning}>{warning}</span>)}</Space>} />}
    </Drawer>
  )
}
