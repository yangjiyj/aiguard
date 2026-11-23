import { Alert, Input, Select, Switch } from 'antd'
import type { SecurityPolicyRedaction } from '../../services/securityPoliciesApi'
import './RedactionConfigFields.css'

const templates = [
  { value: '<MASKED>', label: '默认隐藏（<MASKED>）' },
  { value: 'xxx', label: '统一替换（xxx）' },
  { value: '[姓名]', label: '姓名标记' },
  { value: '[手机号]', label: '手机号标记' },
  { value: '[邮箱]', label: '邮箱标记' },
  { value: '[证件号]', label: '证件号标记' },
  { value: '[企业敏感数据]', label: '企业数据标记' },
]

export default function RedactionConfigFields({ value, disabled, onChange }: {
  value: SecurityPolicyRedaction
  disabled: boolean
  onChange: (value: SecurityPolicyRedaction) => void
}) {
  return <section className="policy-redaction-config" aria-label="脱敏替换配置">
    <p className="text-muted">支持网关 API 与反向代理文本。正向代理不修改正文，脱敏动作仅告警并按原文放行；图片像素和文件字节不替换或还原。</p>
    <label>快速选择替换模板<Select aria-label="脱敏替换模板" value={templates.some((item) => item.value === value.replacement) ? value.replacement : undefined} placeholder="自定义替换文本" disabled={disabled} options={templates} onChange={(replacement) => onChange({ ...value, replacement })} /></label>
    <label>替换文本<Input aria-label="脱敏替换文本" maxLength={128} disabled={disabled} value={value.replacement} placeholder="例如：[客户编号]" onChange={(event) => onChange({ ...value, replacement: event.target.value })} /></label>
    <div className="policy-drawer-switch"><span><strong>响应自动还原</strong><small>模型返回本次请求的脱敏标记时，为当前调用者还原原值。</small></span><Switch aria-label="脱敏响应自动还原" disabled={disabled} checked={value.restore_response} onChange={(restore_response) => onChange({ ...value, restore_response })} /></div>
    <Alert type="info" showIcon message={value.restore_response ? '上游收到带类型和随机编号的标记；流式响应在完整检查后还原。映射仅在本次请求内使用。' : '上游和调用者均收到替换文本，原值不会从响应恢复。'} />
  </section>
}
