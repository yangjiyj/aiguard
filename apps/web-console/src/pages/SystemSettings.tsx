import { useState, useEffect } from 'react'
import { Form, Input, InputNumber, Button, message, Typography, Switch, Divider, Select, Space, Alert } from 'antd'
import { SaveOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { billingEmployeeApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useCurrencyStore } from '../stores/currency'
import { isSystemAdminRole } from '../utils/access'
import { useAccess } from '../hooks/useAccess'
import CurrencySwitch from '../components/billing/CurrencySwitch'
import { normalizeGatewayBase, parseGatewayEndpoints } from '../utils/gatewayAccess'
import { gatewayAddressRisks } from '../utils/clientBaseUrl'
import CurrencySelector from '../components/CurrencySelector'
import { normalizeSecurityExecutionMode, securityModeLabel } from '../services/securityExecutionMode'
import { DetectionExecutionSettings, FailureHandlingSettings } from './system-settings/SecuritySettingsSections'

const { Title, Text } = Typography
const booleanSettingKeys = ['allow_registration', 'content_audit_enabled', 'tool_audit_enabled', 'chat_portal_enabled', 'alert_ttl_enabled', 'ai_content_explicit_label_enabled', 'ai_content_watermark_enabled', 'response_cache_enabled']
const AI_LABEL_AGENT_TYPES_KEY = 'ai_content_label_agent_types'
const AI_LABEL_AGENT_TYPE_OPTIONS = [{ value: 'enterprise-portal', label: '企业 AI 门户' }]

const parseStringList = (value: unknown): string[] => {
  if (Array.isArray(value)) return value.map(String)
  if (typeof value !== 'string' || value.trim() === '') return []
  try {
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) ? parsed.map(String) : []
  } catch {
    return []
  }
}

// 生效客户端类型在服务端存为 JSON 字符串数组，表单里用多选标签编辑。
const parseAgentTypes = (value: unknown): string[] => {
  if (Array.isArray(value)) return value.map(String)
  if (typeof value !== 'string' || value.trim() === '') return ['enterprise-portal']
  try {
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) ? parsed.map(String) : ['enterprise-portal']
  } catch {
    return ['enterprise-portal']
  }
}
const numericSettingKeys = ['log_retention_days', 'alert_group_ttl_days', 'response_cache_ttl_seconds', 'response_cache_max_temperature']
const RESPONSE_CACHE_SHARED_KEY = 'response_cache_shared_project_ids'

const toBooleanSetting = (value: unknown, defaultValue = false) => {
  if (value === undefined || value === null || value === '') return defaultValue
  return value === true || value === 'true'
}

const normalizeSettings = (settings: Record<string, unknown>) => {
  const normalized = { ...settings, gateway_public_endpoints: parseGatewayEndpoints(settings.gateway_public_endpoints).map(({name,url})=>({name,url})), gateway_public_url_mode: ['configured','current_host'].includes(String(settings.gateway_public_url_mode)) ? settings.gateway_public_url_mode : 'current_origin' } as Record<string, unknown>
  booleanSettingKeys.forEach((key) => {
    normalized[key] = toBooleanSetting(settings[key])
  })
  numericSettingKeys.forEach((key) => {
    const numeric = Number(settings[key])
    normalized[key] = Number.isFinite(numeric) && numeric > 0 ? numeric : undefined
  })
  normalized[AI_LABEL_AGENT_TYPES_KEY] = parseAgentTypes(settings[AI_LABEL_AGENT_TYPES_KEY])
  normalized[RESPONSE_CACHE_SHARED_KEY] = parseStringList(settings[RESPONSE_CACHE_SHARED_KEY])
  // 0 是合法的最高 temperature（只缓存确定性请求），不能被上面的正数过滤当成未配置。
  const maxTemperature = Number(settings.response_cache_max_temperature)
  normalized.response_cache_max_temperature = Number.isFinite(maxTemperature) && maxTemperature >= 0 ? maxTemperature : 1
  if (normalized.response_cache_ttl_seconds === undefined) normalized.response_cache_ttl_seconds = 3600
  // 服务端总会回填实际生效的天数；旧版本服务端未返回时按默认 14 天展示，避免必填校验挡住其他设置的保存。
  if (normalized.alert_group_ttl_days === undefined) normalized.alert_group_ttl_days = 14
  return normalized
}

const serializeSettings = (settings: Record<string, unknown>) => {
  const serialized = { ...settings }
  booleanSettingKeys.forEach((key) => {
    serialized[key] = toBooleanSetting(settings[key])
  })
  if (Array.isArray(serialized[RESPONSE_CACHE_SHARED_KEY])) {
    serialized[RESPONSE_CACHE_SHARED_KEY] = JSON.stringify(serialized[RESPONSE_CACHE_SHARED_KEY])
  }
  // 清空缓存靠递增代号，由按钮单独提交，表单保存不回写旧值。
  delete serialized.response_cache_generation
  if (Array.isArray(serialized[AI_LABEL_AGENT_TYPES_KEY])) {
    serialized[AI_LABEL_AGENT_TYPES_KEY] = JSON.stringify(serialized[AI_LABEL_AGENT_TYPES_KEY])
  }
  numericSettingKeys.forEach((key) => {
    if (serialized[key] !== undefined && serialized[key] !== null && serialized[key] !== '') {
      serialized[key] = Number(serialized[key])
    }
  })
  return serialized
}

function SystemSettings() {
  const queryClient = useQueryClient()
  const user = useAuthStore(state => state.user)
  const access = useAccess()
  const tenantID = user?.tenant_id || ''
  const canManageSystem = isSystemAdminRole(user?.role)
  const canManageCurrency = ['platform_admin', 'admin', 'tenant_owner', 'tenant_admin'].includes(user?.role || '')
  // 切换系统币种会整体改标钱包并作废其他币种价格，只有平台管理员可以操作；其余管理员只读当前币种。
  const canSwitchCurrency = user?.role === 'platform_admin'
  const currencyQ = useQuery({ queryKey: ['employee-settings', tenantID], queryFn: () => billingEmployeeApi.settings(tenantID), enabled: canManageCurrency })
  const systemCurrency = currencyQ.data?.data?.data?.currency
  useEffect(() => { if (systemCurrency) useCurrencyStore.getState().setTenantCurrency(systemCurrency) }, [systemCurrency])
  const refreshCurrency = () => {
    void queryClient.invalidateQueries({ queryKey: ['employee-settings', tenantID] })
    void queryClient.invalidateQueries({ queryKey: ['employee-billing-settings', tenantID] })
    void queryClient.invalidateQueries({ queryKey: ['billing-customers', tenantID] })
    void queryClient.invalidateQueries({ queryKey: ['billing-prices', tenantID] })
    void queryClient.invalidateQueries({ queryKey: ['upstream-rates', tenantID] })
    void queryClient.invalidateQueries({ queryKey: ['channel-fixed-costs', tenantID] })
  }
  const [settingsForm] = Form.useForm()
  const [loaded, setLoaded] = useState(false)
  const [testingLse, setTestingLse] = useState(false)
  const alertTTLEnabled = Form.useWatch('alert_ttl_enabled', settingsForm)
  const alertTTLDays = Form.useWatch('alert_group_ttl_days', settingsForm)
  const alertTTLDaysText = Number.isInteger(alertTTLDays) && alertTTLDays > 0 ? alertTTLDays : 'N'
  const publicBaseUrl = Form.useWatch('gateway_public_base_url', settingsForm)
  const publicBaseUrlRisks = gatewayAddressRisks(publicBaseUrl)

  const settingsQ = useQuery({ queryKey: ['system-settings'], queryFn: () => api.get('/system/settings').then(r => r.data), enabled: canManageSystem })
  const securityExecutionMode = normalizeSecurityExecutionMode(settingsQ.data)

  useEffect(() => {
    if (settingsQ.data && !loaded) { settingsForm.setFieldsValue(normalizeSettings(settingsQ.data)); setLoaded(true) }
  }, [settingsQ.data, loaded, settingsForm])

  // 清空缓存：只提交递增后的代号，不带表单里其他未保存的改动。
  const clearCacheM = useMutation({
    mutationFn: () => api.put('/system/settings', { response_cache_generation: String((Number(settingsQ.data?.response_cache_generation) || 0) + 1) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system-settings'] })
      message.success('已清空缓存，约 30 秒内生效')
    },
    onError: (error: any) => message.error(error?.response?.data?.error?.message || '清空失败'),
  })
  const saveM = useMutation({
    mutationFn: (d: Record<string, unknown>) => api.put('/system/settings', d),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system-settings'] })
      message.success('配置已保存，运行节点正在刷新')
    },
    onError: (error: any) => {
      message.error(error?.response?.data?.error?.message || '保存失败')
      // 恢复服务端原状态，避免界面显示已开启但运行态未生效的假成功。
      if (settingsQ.data) settingsForm.setFieldsValue(normalizeSettings(settingsQ.data))
    },
  })

  const handleTestLse = async () => {
    setTestingLse(true)
    try {
      const res = await api.post('/system/lse/test', { lse_base_url: settingsForm.getFieldValue('lse_base_url') })
      const d = res.data || {}
      if (d.ok) message.success((d.message || '连接成功') + (d.latency_ms != null ? ` · ${d.latency_ms}ms` : ''))
      else message.error('测试失败：' + (d.message || '未知错误'))
    } catch (e: any) {
      message.error('测试失败：' + (e?.response?.data?.error?.message || e?.message || ''))
    } finally {
      setTestingLse(false)
    }
  }

  // 平台级安全员只看到与防护相关的两个区块。
  if (user?.role === 'security_officer') {
    return (
      <div>
        <div className="page-header">
          <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>系统设置</Title>
        </div>
        <div className="content-card">
          <div style={{ maxWidth: 640, padding: '0 20px 20px' }}>
            <FailureHandlingSettings canManage={access.canManagePlatformSecuritySettings} />
            <DetectionExecutionSettings canManage={access.canManagePlatformSecuritySettings} />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>系统设置</Title>
        <Text style={{ fontSize: 13, color: 'var(--text-secondary)' }}>配置系统币种和控制台设置</Text>
      </div>
      <div className="content-card">
        <div style={{ maxWidth: 640, paddingTop: 8, padding: '20px' }}>
          {canManageSystem && <Form form={settingsForm} onFinish={(v) => saveM.mutate(serializeSettings(v))} layout="vertical">
            <Form.Item name="gateway_public_base_url" label="对外调用地址（Base URL）"
              extra={<>
                <div>固定地址模式下优先使用此地址；按当前入口模式下仍可从入口列表选择。填写客户端可访问的域名、IP、实际端口和路径前缀。</div>
                <div>此处按 OpenAI 协议填写（带一层 /v1）；Anthropic 协议客户端（如 Claude Code）不要带 /v1，控制台会在接入说明里自动给出对应地址。</div>
                {publicBaseUrlRisks.map(text => <Alert key={text} type="warning" showIcon style={{ marginTop: 6 }} message={text} />)}
              </>}
              rules={[{validator: async (_, value: string | undefined) => {
                if (value?.trim() && !normalizeGatewayBase(value)) throw new Error('请输入不含账号密码、查询参数或片段的完整 HTTP 或 HTTPS 地址')
              }}]}
            >
              <Input placeholder="https://客户域名/v1" />
            </Form.Item>
            <Form.Item name="gateway_public_url_mode" label="调用地址选择方式" extra="网页和 API 可以使用不同协议与端口。跟随主机时，使用上方 Base URL 的 API 协议、端口和路径，并沿用当前访问的域名或 IP。">
              <Select options={[{value:'current_host',label:'跟随访问主机，使用 API 协议和端口'},{value:'current_origin',label:'使用与网页相同的入口'},{value:'configured',label:'优先使用固定默认地址'}]}/>
            </Form.Item>
            <Text strong>其他网络的调用入口</Text>
            <Form.List name="gateway_public_endpoints">
              {(fields, {add, remove}) => <>
                {fields.map(field => <div key={field.key} style={{marginTop:12,padding:12,border:'1px solid var(--border-color)',borderRadius:6}}>
                  <Form.Item name={[field.name,'name']} label="入口名称" rules={[{required:true,message:'请输入入口名称'},{max:80,message:'入口名称最多 80 个字符'}]}><Input placeholder="例如：客户内网、VPN、外网域名"/></Form.Item>
                  <Form.Item name={[field.name,'url']} label="入口 Base URL" rules={[{required:true,message:'请输入入口地址'},{validator:async(_,value)=>{if(value&&!normalizeGatewayBase(value))throw new Error('请输入合法的 HTTP 或 HTTPS 调用地址')}}]}><Input placeholder="http://内网地址:实际端口/v1"/></Form.Item>
                  <Button danger size="small" onClick={()=>remove(field.name)}>删除入口</Button>
                </div>)}
                <Space style={{margin:'12px 0 16px'}}><Button onClick={()=>add({name:'',url:''})} disabled={fields.length>=20}>添加调用入口</Button></Space>
              </>}
            </Form.List>
            <Typography.Paragraph type="secondary" style={{fontSize:12}}>配置地址后，请确保相应网络能解析域名、访问端口，且反向代理将 /v1、/v1beta 和 /mcp 转发到网关。HTTPS 应使用客户端信任且包含该域名的证书。</Typography.Paragraph>
            <Text strong>LSE 集成配置</Text>
            <Form.Item name="lse_base_url" label="LSE 服务地址"><Input placeholder="100.64.0.21" /></Form.Item>
            <Form.Item><Button onClick={handleTestLse} loading={testingLse}>测试连接</Button></Form.Item>
            <Form.Item
              name="log_retention_days"
              label="日志与内容留存天数"
              extra={(
                <>
                  <div>到期自动清理：访问记录明细、内容留存（请求、响应和文件内容）、内容审计、工具调用审计。</div>
                  <div>不会清理：安全事件及其关联的访问记录、告警、操作审计与审计完整性记录；计费记录长期保留，不受此设置影响。</div>
                  <div>为防误删，最少保留 30 天。</div>
                </>
              )}
              rules={[
                { required: true, message: '请输入日志与内容留存天数' },
                { type: 'number', min: 30, max: 3650, message: '留存天数需在 30 到 3650 天之间（最少保留 30 天）' },
              ]}
            ><InputNumber min={30} max={3650} precision={0} style={{ width: '100%' }} placeholder="例如: 90" /></Form.Item>
            <Form.Item name="allow_registration" label="开放自助注册" valuePropName="checked" extra="私有化部署通常关闭，由管理员统一创建账号和分配权限。">
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item name="content_audit_enabled" label="启用内容审计" valuePropName="checked" extra="记录用户输入、模型输出和安全检测结论，用于复盘、追责和合规审查。">
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item name="tool_audit_enabled" label="启用工具调用审计" valuePropName="checked" extra="记录 Agent 调用文件、命令、网络、MCP 等工具的行为和风险结果。">
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              name="alert_ttl_enabled"
              label="自动关闭陈旧告警"
              valuePropName="checked"
              extra={`只自动关闭 ${alertTTLDaysText} 天无新发生的输入侧告警，高危类型（密钥泄露、诱饵命中等）不自动关闭`}
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              name="alert_group_ttl_days"
              label="自动关闭天数"
              extra={alertTTLEnabled ? '每小时检查一次，修改后无需重启。' : '开启自动关闭后生效；关闭时不会自动关闭任何告警。'}
              rules={[
                { required: true, message: '请输入自动关闭天数' },
                { type: 'number', min: 1, max: 365, message: '自动关闭天数需在 1 到 365 天之间' },
              ]}
            ><InputNumber min={1} max={365} precision={0} style={{ width: '100%' }} placeholder="例如: 14" /></Form.Item>
            <div
              className="system-settings-policy-status"
              aria-label="安全策略状态"
              style={{ margin: '20px 0' }}
            >
              <Text strong>安全策略状态</Text>
              <div style={{ marginTop: 8 }}>
                <span>当前安全执行模式</span><span aria-hidden="true">：</span>
                <span style={{ fontWeight: 600 }}>{securityModeLabel(securityExecutionMode?.effective_mode)}</span>
              </div>
              <Text type="secondary">安全执行模式由策略中心统一维护，此处仅展示当前实际模式。</Text>
              <div style={{ marginTop: 8 }}>
                <a href="/security/policies?section=overview">前往策略中心配置</a>
              </div>
            </div>
            <Divider style={{ margin: '20px 0' }} />
            <div style={{ marginBottom: 12 }}>
              <Text strong style={{ color: 'var(--text-primary)' }}>AI 生成内容标识</Text>
              <div><Text type="secondary">按《人工智能生成合成内容标识办法》给模型回复加标识。只对下方选中的客户端生效，编码助手、Agent 等程序调用不受影响。</Text></div>
            </div>
            <Form.Item name="ai_content_explicit_label_enabled" label="显式标识" valuePropName="checked" extra="在回复末尾另起一行加上标识文字。">
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              name="ai_content_explicit_label_text"
              label="标识文字"
              extra="显示时自动加全角括号。"
              rules={[
                { max: 40, message: '标识文字最多 40 个字符' },
                { pattern: /^[^\r\n\t]*$/, message: '标识文字不能换行' },
              ]}
            ><Input placeholder="以上内容由 AI 生成" /></Form.Item>
            <Form.Item name="ai_content_watermark_enabled" label="隐式水印" valuePropName="checked" extra="在回复里加入看不见的字符，记录这次请求。泄露的文本可在「内容留证 → 泄露溯源」中反查来源。">
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item name={AI_LABEL_AGENT_TYPES_KEY} label="生效客户端" extra="选择需要加标识的客户端类型；也可输入自研前端声明的客户端类型。">
              <Select mode="tags" options={AI_LABEL_AGENT_TYPE_OPTIONS} placeholder="选择或输入客户端类型" maxCount={16} />
            </Form.Item>
            <Divider style={{ margin: '20px 0' }} />
            <div style={{ marginBottom: 12 }}>
              <Text strong style={{ color: 'var(--text-primary)' }}>响应缓存</Text>
              <div><Text type="secondary">相同的问题直接返回上次的回答，不再调用模型、不计费。只缓存纯文本问答；带工具、图片、文件或命中安全策略的请求不缓存。安全策略变更后旧缓存自动失效。</Text></div>
            </div>
            <Form.Item name="response_cache_enabled" label="启用响应缓存" valuePropName="checked" extra="默认每个用户只能命中自己问过的问题。">
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              name="response_cache_ttl_seconds"
              label="缓存有效期（秒）"
              rules={[{ type: 'number', min: 60, max: 86400, message: '有效期需在 60 到 86400 秒之间' }]}
            ><InputNumber min={60} max={86400} precision={0} style={{ width: '100%' }} /></Form.Item>
            <Form.Item
              name="response_cache_max_temperature"
              label="可缓存的最高 temperature"
              extra="请求的 temperature 高于这个值时不缓存；未指定 temperature 按 1 计算。"
              rules={[{ type: 'number', min: 0, max: 2, message: '需在 0 到 2 之间' }]}
            ><InputNumber min={0} max={2} step={0.1} style={{ width: '100%' }} /></Form.Item>
            <Form.Item name={RESPONSE_CACHE_SHARED_KEY} label="同应用内共享缓存" extra="填写应用 ID。名单内的应用，同一应用的用户共享缓存，命中时按当前用户身份重新做一次输出检测。适合客服、知识库问答等公共场景。">
              <Select mode="tags" placeholder="输入应用 ID" tokenSeparators={[',', ' ']} maxCount={200} />
            </Form.Item>
            <Form.Item label="清空缓存" extra="立即让全部已缓存的回答失效，约 30 秒内生效。">
              <Button onClick={() => clearCacheM.mutate()} loading={clearCacheM.isPending}>清空全部缓存</Button>
            </Form.Item>
            <Divider style={{ margin: '20px 0' }} />
            <div style={{ marginBottom: 12 }}>
              <Text strong style={{ color: 'var(--text-primary)' }}>Chat / SSO 门户</Text>
            </div>
            <Form.Item
              name="chat_portal_enabled"
              label="启用 Chat / SSO 门户"
              valuePropName="checked"
              extra="开启后，员工可通过企业 SSO 登录网页版对话门户，门户流量经本网关审计、分组与限额。关闭时门户网页不对外暴露（访问返回“门户未启用”）。离线部署下门户随安装包一起部署，是否对外暴露只由本开关决定；开关变更约 10 秒内生效。"
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item><Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saveM.isPending}>保存设置</Button></Form.Item>
          </Form>}
          <FailureHandlingSettings canManage={access.canManagePlatformSecuritySettings} />
          <DetectionExecutionSettings canManage={access.canManagePlatformSecuritySettings} />
          <Divider style={{ margin: '24px 0' }} />
          <div style={{ marginBottom: 8 }}>
            <Text strong style={{ color: 'var(--text-primary)' }}>货币设置</Text>
            <Text style={{ fontSize: 12, color: 'var(--text-tertiary)', marginLeft: 8 }}>系统币种用于钱包、模型定价和计费。不进行汇率换算，切换时金额数字保持不变；历史计费事实保留原币种。</Text>
          </div>
          {canManageCurrency && <Space direction="vertical" style={{ width: '100%', marginBottom: 16 }}>
            {currencyQ.isError ? <Alert type="error" message="系统币种读取失败" action={<Button onClick={() => void currencyQ.refetch()}>重新加载币种</Button>} /> : <Text>当前系统币种：{systemCurrency || '加载中…'}</Text>}
            {canSwitchCurrency && systemCurrency && !currencyQ.isError && <CurrencySwitch tenantID={tenantID} currency={systemCurrency} onSuccess={refreshCurrency} />}
          </Space>}
          <div style={{ marginBottom: 8 }}><Text>查看币种（仅影响当前浏览器的历史用量筛选，不修改系统币种）</Text></div>
          <CurrencySelector />
        </div>
      </div>
    </div>
  )
}

export default SystemSettings
