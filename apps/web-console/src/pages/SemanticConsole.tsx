import { useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Col,
  Divider,
  Form,
  Input,
  InputNumber,
  Radio,
  Row,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
  message,
} from 'antd'
import { ExperimentOutlined, SaveOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api, { providerApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { isSystemAdminRole } from '../utils/access'
import { judgeBackendLabel, verdictLabel } from '../utils/risk'

const { Title, Text, Paragraph } = Typography
const scopeOptions = [
  { key: 'inspect_user_input', label: '本轮用户输入', defaultValue: true, detail: '检测本轮用户发送的文字和附件。' },
  { key: 'inspect_model_output', label: '本轮模型输出', defaultValue: true, detail: '检测模型回复中的个人信息、密钥和违规内容。' },
  { key: 'inspect_tool_results', label: '工具与检索返回', defaultValue: true, detail: '检测工具、网页和知识检索带入的外部内容，包括间接提示注入。' },
  { key: 'inspect_builtin_context', label: '内置提示词与工具定义', defaultValue: false, detail: '检测协议中的系统提示词、开发者指令和工具定义；默认关闭。' },
  { key: 'inspect_history', label: '随请求携带的历史消息', defaultValue: false, detail: '重新检测此前轮次的消息；默认关闭，减少长会话重复告警与等待。' },
] as const
const booleanKeys = ['semantic_enabled', 'semantic_input_enabled', 'semantic_agent_enabled', 'fp_suppression_enabled', 'judge_allow_private_egress', ...scopeOptions.map((option) => option.key)] as const
const numericKeys = ['semantic_total_timeout', 'semantic_block_min_confidence'] as const
// 与 control-plane 默认值一致：未保存过时显示 0.85。
const DEFAULT_SEMANTIC_BLOCK_MIN_CONFIDENCE = 0.85
const brainStringKeys = ['judge_backend', 'judge_provider_id', 'judge_url', 'judge_model'] as const

type ProviderOption = { id: string; name: string }
type RuntimeComponent = {
  component: 'security-engine' | 'gateway-core' | 'proxy-server'
  status: string
  fresh: boolean
  config_loaded?: boolean
  judge_required?: boolean
  judge_operational?: boolean
  judge_consecutive_failures?: number
  judge_breaker_open?: boolean
  judge_last_attempt_at?: string
  judge_last_success_at?: string
  last_error?: string
}
type SemanticRuntime = {
  proxy_required?: boolean
  status: string
  runtime_verified: boolean
  components?: RuntimeComponent[]
}

const componentLabels: Record<string, string> = {
  'security-engine': '安全检测引擎',
  'gateway-core': '模型网关',
  'proxy-server': '正向代理',
}

const toBool = (value: unknown) => value === true || value === 'true'

function runtimePresentation(runtime: SemanticRuntime | undefined, failed: boolean) {
  if (failed || !runtime) return { label: '运行态不可验证', type: 'error' as const, verified: false }
  const components = runtime.components || []
  const engine = components.find((component) => component.component === 'security-engine')
  const gateway = components.find((component) => component.component === 'gateway-core')
  const proxy = components.find((component) => component.component === 'proxy-server')
  const judgeUnavailable = Boolean(
    engine?.fresh && engine.config_loaded && engine.judge_required === true && engine.judge_operational !== true,
  )
  if (judgeUnavailable) {
    return { label: '配置已加载，但语义裁判不可用', type: 'error' as const, verified: false }
  }
  const axesVerified = Boolean(
    engine?.fresh && gateway?.fresh && engine.config_loaded === true && gateway.config_loaded === true
    && (engine.judge_required === false || engine.judge_operational === true)
    && (!runtime.proxy_required || (proxy?.status === 'applied' && proxy.fresh && proxy.config_loaded && !proxy.last_error)),
  )
  if (runtime.status === 'applied' && runtime.runtime_verified && axesVerified) {
    return { label: '语义配置已验证生效', type: 'success' as const, verified: true }
  }
  if (runtime.status === 'applied' && runtime.runtime_verified && !axesVerified) {
    return { label: '组件仅回报配置版本，运行健康未验证', type: 'warning' as const, verified: false }
  }
  if (runtime.status === 'partially_applied') {
    return { label: '部分组件已加载', type: 'warning' as const, verified: false }
  }
  if (runtime.status === 'degraded') {
    return { label: '运行组件加载失败', type: 'error' as const, verified: false }
  }
  return { label: '等待运行组件加载', type: 'info' as const, verified: false }
}

function componentPresentation(component: RuntimeComponent) {
  if (component.component === 'security-engine' && component.fresh && component.config_loaded
    && component.judge_required === true && component.judge_operational !== true) {
    return { text: '配置已加载 · 裁判不可用', color: 'error' as const }
  }
  if (component.status === 'applied' && component.fresh && component.config_loaded === true) {
    return { text: '已加载', color: 'success' as const }
  }
  if (component.last_error) return { text: '运行失败', color: 'error' as const }
  return { text: '等待回执', color: 'warning' as const }
}

function SemanticConsole() {
  const [form] = Form.useForm()
  const queryClient = useQueryClient()
  const [loaded, setLoaded] = useState(false)
  const [testing, setTesting] = useState(false)
  // 研判服务地址与密钥决定受检内容发到哪里，只有系统管理员能配；安全员只能在内置研判与已登记的模型上游之间切换。
  const role = useAuthStore((state) => state.user?.role)
  const canConfigureJudgeEndpoint = isSystemAdminRole(role)
  const judgeBackend = (Form.useWatch('judge_backend', form) as string) || ''
  const judgeAllowPrivateEgress = Boolean(Form.useWatch('judge_allow_private_egress', form))

  const settingsQ = useQuery({
    queryKey: ['system-settings', 'semantic'],
    // 专用读取接口：只返回语义/研判相关键，并带 config_version（保存时带回，防止后保存的覆盖先保存的）。
    queryFn: () => api.get('/security/semantic/settings').then((response) => response.data),
  })
  const runtimeQ = useQuery({
    queryKey: ['semantic', 'runtime-status'],
    queryFn: () => api.get('/security/semantic/runtime-status').then((response) => response.data.runtime as SemanticRuntime),
    refetchInterval: 10_000,
  })
  const providersQ = useQuery({
    queryKey: ['providers', 'semantic-judge'],
    queryFn: () => providerApi.list(),
  })

  const settings = (settingsQ.data || {}) as Record<string, unknown>
  const configured = booleanKeys.some((key) => settings[key] !== undefined && settings[key] !== '')
    || Boolean(String(settings.judge_backend || '').trim())
  const providerOptions: ProviderOption[] = (providersQ.data?.data?.data || []) as ProviderOption[]
  const hasJudgeKey = Boolean(String(settings.judge_api_key || '').trim())
  const runtime = runtimePresentation(runtimeQ.data, runtimeQ.isError)

  useEffect(() => {
    if (!settingsQ.data || loaded) return
    const data = settingsQ.data as Record<string, unknown>
    form.setFieldsValue({
      semantic_enabled: toBool(data.semantic_enabled),
      semantic_input_enabled: toBool(data.semantic_input_enabled),
      semantic_agent_enabled: toBool(data.semantic_agent_enabled),
      fp_suppression_enabled: toBool(data.fp_suppression_enabled),
      judge_allow_private_egress: toBool(data.judge_allow_private_egress),
      semantic_total_timeout: data.semantic_total_timeout !== undefined && data.semantic_total_timeout !== ''
        ? Number(data.semantic_total_timeout)
        : undefined,
      semantic_block_min_confidence: data.semantic_block_min_confidence !== undefined && data.semantic_block_min_confidence !== ''
        ? Number(data.semantic_block_min_confidence)
        : DEFAULT_SEMANTIC_BLOCK_MIN_CONFIDENCE,
      judge_backend: String(data.judge_backend || '').trim() || undefined,
      judge_provider_id: String(data.judge_provider_id || '').trim() || undefined,
      judge_url: String(data.judge_url || '').trim(),
      judge_model: String(data.judge_model || '').trim(),
      judge_api_key: '',
      ...Object.fromEntries(scopeOptions.map((option) => [
        option.key,
        data[option.key] === undefined || data[option.key] === '' ? option.defaultValue : toBool(data[option.key]),
      ])),
    })
    setLoaded(true)
  }, [form, loaded, settingsQ.data])

  const configVersion = String((settingsQ.data as Record<string, unknown> | undefined)?.config_version || '')

  const buildPayload = (values: Record<string, unknown>) => {
    const payload: Record<string, unknown> = { expected_version: configVersion }
    booleanKeys.forEach((key) => { payload[key] = toBool(values[key]) })
    // 输出侧固定执行确定性数据/内容检测，不允许运行输入语义攻击裁判。
    payload.semantic_output_enabled = false
    numericKeys.forEach((key) => {
      if (values[key] !== undefined && values[key] !== null && values[key] !== '') payload[key] = Number(values[key])
    })
    brainStringKeys.forEach((key) => {
      // 安全员不发送出口相关键（judge_url）；后端也会拒绝，这里避免正常保存被无谓拦下。
      if (!canConfigureJudgeEndpoint && key === 'judge_url') return
      payload[key] = values[key] != null ? String(values[key]).trim() : ''
    })
    if (!canConfigureJudgeEndpoint) {
      delete payload.judge_allow_private_egress
    } else {
      const apiKey = String(values.judge_api_key || '').trim()
      if (apiKey) payload.judge_api_key = apiKey
    }
    return payload
  }

  const saveMutation = useMutation({
    // 专用接口：安全员也能保存；只接受语义/研判相关键，系统类配置仍须走 /system/settings（系统管理员）。
    mutationFn: (values: Record<string, unknown>) => api.put('/security/semantic/settings', buildPayload(values)),
    onSuccess: async () => {
      message.success('配置已保存，正在等待各检测组件确认生效')
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['system-settings', 'semantic'] }),
        queryClient.invalidateQueries({ queryKey: ['semantic', 'runtime-status'] }),
      ])
    },
    onError: (error: any) => {
      message.error('保存失败：' + (error?.response?.data?.error?.message || error?.message || '未知错误'))
      if (error?.response?.status === 409) {
        // 别人已经保存过：重新读取最新配置与版本号，用户核对后再保存。
        setLoaded(false)
        queryClient.invalidateQueries({ queryKey: ['system-settings', 'semantic'] })
      }
    },
  })

  const handleTest = async () => {
    setTesting(true)
    try {
      const values = form.getFieldsValue()
      const body: Record<string, unknown> = {
        judge_backend: String(values.judge_backend || '').trim(),
        judge_provider_id: String(values.judge_provider_id || '').trim(),
        judge_url: String(values.judge_url || '').trim(),
        judge_model: String(values.judge_model || '').trim(),
        judge_allow_private_egress: toBool(values.judge_allow_private_egress),
      }
      const apiKey = String(values.judge_api_key || '').trim()
      if (apiKey) body.judge_api_key = apiKey
      // The saved judge budget can be 60s; leave room for the server response.
      const response = await api.post('/security/semantic/test-judge', body, { timeout: 65_000 })
      const result = response.data || {}
      if (result.ok) {
        const verdict = result.verdict ? verdictLabel(result.verdict) : '已连通'
        const latency = result.latency_ms != null ? ` · ${(result.latency_ms / 1000).toFixed(1)}s` : ''
        message.success(`连接正常 · 裁判判定：${verdict}${latency}。这只证明裁判可达，不代表运行组件已加载配置。`)
      } else {
        message.error('测试失败：' + (result.error || '未知错误'))
      }
    } catch (error: any) {
      message.error('测试失败：' + (error?.response?.data?.error?.message || error?.message || '未知错误'))
    } finally {
      setTesting(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>语义检测控制台</Title>
        <Text style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
          配置期望态与运行态分开核验；保存成功、裁判可达都不等于网关和检测引擎已经生效。
        </Text>
      </div>

      <Card title="运行状态" size="small" style={{ marginBottom: 16 }}>
        <Alert
          showIcon
          type={runtime.type}
          message={runtime.label}
          description={runtime.label === '配置已加载，但语义裁判不可用'
            ? '基础规则仍运行，依赖大模型的语义判断暂不可用；裁判恢复前不会把语义检测显示为已生效。'
            : runtime.verified
              ? '当前部署要求的检测组件均已加载配置；启用裁判时，还需验证实际判定服务正常。'
              : '配置加载与裁判运行健康分别核验；任一分轴缺失或失败，页面都不会显示绿色生效。'}
        />
        <Space size={[8, 8]} wrap style={{ marginTop: 12 }}>
          {(runtimeQ.data?.components || []).map((component) => {
            const presentation = componentPresentation(component)
            return (
              <Tag key={component.component} color={presentation.color}>
                {componentLabels[component.component] || component.component}：{presentation.text}
              </Tag>
            )
          })}
        </Space>
      </Card>

      {!configured && !settingsQ.isLoading ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="尚未配置语义检测"
          description="语义开关按未配置显示，安全检测范围采用下方默认选项。请明确选择检测面、裁判后端和预算后保存。"
        />
      ) : null}
      {settingsQ.isError ? (
        <Alert type="error" showIcon style={{ marginBottom: 16 }} message="语义配置读取失败" description="页面不会用默认值冒充已配置状态。" />
      ) : null}

      <Form form={form} layout="vertical" onFinish={(values) => saveMutation.mutate(values)}>
        <Card title="安全检测范围" size="small" style={{ marginBottom: 16 }}>
          <Paragraph type="secondary">
            范围同时约束规则与模型检测。未勾选的内容不作为独立告警对象；相关上下文仍可用于解释本轮风险。
            来源无法识别的内容继续检测。关闭历史检测不会删除已有告警。
          </Paragraph>
          <Row gutter={24}>
            {scopeOptions.map((option) => (
              <Col xs={24} md={12} xl={8} key={option.key}>
                <Form.Item name={option.key} label={option.label} valuePropName="checked" extra={option.detail}>
                  <Switch checkedChildren="检测" unCheckedChildren="不检测" aria-label={option.label} />
                </Form.Item>
              </Col>
            ))}
          </Row>
          <Text type="secondary">尚未单独配置时采用上述默认范围；保存后以运行组件回执确认生效。</Text>
        </Card>
        <Row gutter={16}>
          <Col xs={24} xl={12}>
            <Card title="检测开关" size="small" style={{ marginBottom: 16 }}>
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message="语义命中默认记录并告警；只有「防护策略」里「智能分析命中时」选了拦截的策略，才会在防护模式下拦截达到阈值的高置信结论，分析不可用时一律放行。"
              />
              <Form.Item name="semantic_enabled" label="语义检测总开关" valuePropName="checked" extra="控制已纳入检测范围的输入与 Agent 语义判定；数据规则仍按检测范围运行。">
                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
              </Form.Item>
              <Space size="large" wrap>
                <Form.Item name="semantic_input_enabled" label="输入检测" valuePropName="checked" extra="仅对最新用户输入执行语义攻击判定。">
                  <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                </Form.Item>
                <Form.Item name="semantic_agent_enabled" label="Agent 检测" valuePropName="checked" extra="独立于输入开关，但仍受总开关约束。">
                  <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                </Form.Item>
              </Space>
              <Form.Item name="fp_suppression_enabled" label="规则命中语义复核" valuePropName="checked"
                extra="用命中句、邻近文本与当前任务复核意图类规则。两次复核均明确判为误报时撤回该命中；真实凭据与有效证件规则不由模型撤回。复核失败保留原证据。">
                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
              </Form.Item>
              <Alert
                type="success"
                showIcon
                style={{ marginBottom: 16 }}
                message="模型输出使用数据与内容安全检测"
                description="开启模型输出检测时，检查密钥、个人信息、配置泄露、文件和违规内容；输入侧越狱判定不套用到模型回复。"
              />
              <Divider style={{ margin: '8px 0 16px' }} />
              <Space size="large" wrap>
                <Form.Item name="semantic_total_timeout" label="总超时（秒）" rules={[{ required: true, message: '请填写总超时' }]} extra="单一预算覆盖分类、主裁判和复核；超时会记录结构化运行错误。">
                  <InputNumber min={1} max={60} style={{ width: 160 }} placeholder="1 到 60" />
                </Form.Item>
                <Form.Item
                  name="semantic_block_min_confidence"
                  label="拦截置信度阈值"
                  rules={[{ required: true, message: '请填写拦截置信度阈值' }, { type: 'number', min: 0.5, max: 1, message: '阈值范围 0.5 到 1.0' }]}
                  extra={<>
                    <div>只对「防护策略」里「智能分析命中时」选了拦截的策略生效：输入侧智能分析完整完成、且裁判置信度不低于该值时才拦截，低于该值记录并告警；分析超时、不可用或容量饱和时一律放行。默认 0.85。</div>
                    <div>上下文裁判置信度固定为 0.9：阈值 ≤0.9 时拦截，&gt;0.9 时只记录。</div>
                  </>}
                >
                  <InputNumber aria-label="拦截置信度阈值" min={0.5} max={1} step={0.01} precision={2} style={{ width: 160 }} placeholder="0.50 到 1.00" />
                </Form.Item>
              </Space>
            </Card>
          </Col>

          <Col xs={24} xl={12}>
            <Card title="检测大脑" size="small" style={{ marginBottom: 16 }}>
              <Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 16 }}>
                选择语义裁判。「{judgeBackendLabel('bundled')}」本地运行；也可复用模型上游或接入 OpenAI 兼容端点。
              </Paragraph>
              {!canConfigureJudgeEndpoint ? (
                <Alert type="info" showIcon style={{ marginBottom: 16 }}
                  message="研判服务地址与密钥由系统管理员配置"
                  description="受检内容会被发送到研判服务，所以地址、密钥与私网授权只有系统管理员可以修改。您可以在内置研判与系统管理员已登记的模型上游之间切换。" />
              ) : null}
              <Form.Item name="judge_backend" label="裁判后端" rules={[{ required: true, message: '请选择裁判后端' }]}>
                <Radio.Group>
                  <Space direction="vertical" size={8}>
                    <Radio value="bundled"><Text strong>{judgeBackendLabel('bundled')}</Text></Radio>
                    <Radio value="provider"><Text strong>{judgeBackendLabel('provider')}</Text></Radio>
                    {canConfigureJudgeEndpoint || judgeBackend === 'custom'
                      ? <Radio value="custom" disabled={!canConfigureJudgeEndpoint}><Text strong>{judgeBackendLabel('custom')}</Text></Radio>
                      : null}
                  </Space>
                </Radio.Group>
              </Form.Item>

              {judgeBackend === 'provider' ? (
                <>
                  <Form.Item name="judge_provider_id" label="模型上游" rules={[{ required: true, message: '请选择一个模型上游' }]}>
                    <Select style={{ maxWidth: 420 }} loading={providersQ.isLoading} options={providerOptions.map((provider) => ({ value: provider.id, label: provider.name }))} />
                  </Form.Item>
                  <Form.Item name="judge_model" label="模型名" rules={[{ required: true, message: '请填写模型名' }]}>
                    <Input style={{ maxWidth: 420 }} />
                  </Form.Item>
                </>
              ) : null}

              {judgeBackend !== 'bundled' && canConfigureJudgeEndpoint ? (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginBottom: 16 }}
                  message="私网裁判需要显式授权"
                  description="默认只允许公网 HTTPS。仅当裁判确实部署在受控私网时开启；开启后私网端点可使用 HTTP。回环、链路本地和云元数据地址始终禁止。"
                  action={(
                    <Form.Item name="judge_allow_private_egress" valuePropName="checked" noStyle>
                      <Switch aria-label="允许访问私网裁判" checkedChildren="已授权" unCheckedChildren="未授权" />
                    </Form.Item>
                  )}
                />
              ) : null}

              {judgeBackend === 'custom' && canConfigureJudgeEndpoint ? (
                <>
                  <Form.Item
                    name="judge_url"
                    label="端点地址"
                    dependencies={['judge_allow_private_egress']}
                    rules={[
                      { required: true, message: '请填写端点地址' },
                      judgeAllowPrivateEgress
                        ? { pattern: /^https?:\/\//i, message: '端点地址必须以 http:// 或 https:// 开头' }
                        : { pattern: /^https:\/\//i, message: '公网裁判端点必须使用 HTTPS；私网 HTTP 端点需先开启私网授权' },
                    ]}
                  >
                    <Input style={{ maxWidth: 520 }} placeholder="https://裁判服务/v1/chat/completions" />
                  </Form.Item>
                  <Form.Item name="judge_model" label="模型名" rules={[{ required: true, message: '请填写模型名' }]}>
                    <Input style={{ maxWidth: 420 }} />
                  </Form.Item>
                  <Form.Item name="judge_api_key" label={hasJudgeKey ? '密钥（已配置，留空不修改）' : '密钥'}>
                    <Input.Password style={{ maxWidth: 420 }} />
                  </Form.Item>
                </>
              ) : null}
            </Card>

            <Card title="测试与保存" size="small" style={{ marginBottom: 16 }}>
              <Paragraph type="secondary" style={{ fontSize: 12 }}>
                测试连接只验证当前裁判端点可达；保存后仍需等待运行状态卡中的两个组件回执。
              </Paragraph>
              <Space>
                <Button icon={<ExperimentOutlined />} onClick={handleTest} loading={testing}>测试连接</Button>
                <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saveMutation.isPending}>保存</Button>
              </Space>
            </Card>
          </Col>
        </Row>
      </Form>
    </div>
  )
}

export default SemanticConsole
