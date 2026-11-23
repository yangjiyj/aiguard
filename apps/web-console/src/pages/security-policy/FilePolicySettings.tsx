import { useEffect, useState } from 'react'
import { Alert, Button, Popconfirm, message } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { contentSecurityApi, securitySystemSettingsApi, systemSettingsApi, type ContentFilePolicy, type FileRiskAction } from '../../services/api'
import { formatExceptionExpiry } from '../../utils/exceptions'
import ContentExceptionModal from '../../components/protection/ContentExceptionModal'
import { useAccess } from '../../hooks/useAccess'
import { extractApiError } from '../../utils/apiError'
import { FILE_LIMITS, ZIP_LIMITS, type ZipLimitField } from '../../utils/securityLimits'

type FilePolicySettingsProps = {
  canManage: boolean
  showExceptions?: boolean
}

type ContentExceptionSettingsProps = {
  canManage: boolean
}

type ContentExceptionRecord = {
  id: string
  scope_type?: string
  scope_name?: string
  scope_ref?: string
  decision?: string
  reason?: string
  rule_ref?: string
  rule_name?: string
  expires_at?: string | null
  enabled?: boolean
}

type RiskActionField =
  | 'executable_action'
  | 'disguised_executable_action'
  | 'script_action'
  | 'unknown_action'
  | 'zip_bomb_action'
  | 'unverified_file_reference_action'
  | 'file_reference_lookup_failure_action'

export type FilePolicyDraft = {
  allowed_types: string[]
  review_types: string[]
  blocked_types: string[]
  max_file_mb: number
  max_attachments: number
  max_zip_ratio: number
} & Record<RiskActionField, FileRiskAction> & Partial<Record<ZipLimitField, number>>

// 与控制面默认一致：三个类型名单都为空（后端 GET 总会明确返回，这里只在字段缺失时兜底）。
// eslint-disable-next-line react-refresh/only-export-components
export const DEFAULT_FILE_POLICY: FilePolicyDraft = {
  allowed_types: [],
  review_types: [],
  blocked_types: [],
  max_file_mb: 20,
  max_attachments: 10,
  max_zip_ratio: 100,
  executable_action: 'alert_allow',
  disguised_executable_action: 'alert_allow',
  script_action: 'alert_allow',
  unknown_action: 'alert_allow',
  zip_bomb_action: 'alert_allow',
  unverified_file_reference_action: 'alert_allow',
  file_reference_lookup_failure_action: 'alert_allow',
}

const FILE_TYPE_OPTIONS = [
  { value: 'txt', label: 'TXT' },
  { value: 'csv', label: 'CSV' },
  { value: 'json', label: 'JSON' },
  // 文本与源码类型，与安全引擎 file_inspector.py 的 _DECLARED_TEXT 及其别名一致。
  ...['md', 'markdown', 'yaml', 'yml', 'toml', 'ini', 'xml', 'html', 'css', 'log', 'sql',
    'py', 'js', 'ts', 'tsx', 'jsx', 'go', 'java', 'c', 'h', 'cpp', 'cs', 'rb', 'php', 'rs', 'kt', 'swift', 'scala', 'vue',
  ].map((value) => ({ value, label: value.toUpperCase() })),
  { value: 'docx', label: 'DOCX' },
  { value: 'pptx', label: 'PPTX' },
  { value: 'xlsx', label: 'XLSX' },
  { value: 'pdf', label: '文本型 PDF' },
  { value: 'zip', label: 'ZIP' },
  { value: 'rar', label: 'RAR' },
  { value: '7z', label: '7Z' },
]

// 规则 ID 以安全引擎 file_inspector.py 实际产出为准。
const RISK_ROWS: Array<{ field: RiskActionField; label: string; ruleId?: string }> = [
  { field: 'executable_action', label: '可执行文件 / 动态库', ruleId: 'file-executable' },
  { field: 'disguised_executable_action', label: '伪装可执行文件', ruleId: 'file-disguised-exec' },
  { field: 'script_action', label: '脚本', ruleId: 'file-script' },
  { field: 'unknown_action', label: '未知类型', ruleId: 'file-unknown' },
  { field: 'zip_bomb_action', label: '压缩炸弹', ruleId: 'file-zip-bomb' },
  { field: 'unverified_file_reference_action', label: '未核验的文件引用', ruleId: 'file-id-unverified' },
  { field: 'file_reference_lookup_failure_action', label: '文件引用核验失败' },
]

const RISK_ACTION_OPTIONS: Array<{ value: FileRiskAction; label: string }> = [
  { value: 'allow', label: '允许' },
  { value: 'alert_allow', label: '告警放行' },
  { value: 'block', label: '禁止' },
]

// 引擎文件类型“禁止”命中的规则编号带类型（file_inspector.blocked_type_rule_id）。
const blockedTypeRuleId = (type: string) => `file-policy-blocked-type:${type}`

const EXECUTABLE_POLICY_ALIASES = ['executable', 'exe', 'dll', 'pe', 'elf', 'macho', 'macho_fat']
// 这些类型由上面的高风险行单独配置动作，不再放进允许/禁止清单。
const RISK_TYPE_TOKENS = [...EXECUTABLE_POLICY_ALIASES, 'script', 'unknown']

type FileTypeAction = 'allowed' | 'blocked'
type UploadFailureAction = 'forward_alert' | 'block'

const FILE_ACTION_OPTIONS: Array<{ value: FileTypeAction; label: string }> = [
  { value: 'allowed', label: '允许发送' },
  { value: 'blocked', label: '禁止发送' },
]

const toBoolean = (value: unknown): boolean => value === true || value === 'true'

function arrayValue(value: unknown, fallback: string[]): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : fallback
}

function riskAction(value: unknown): FileRiskAction {
  return value === 'allow' || value === 'alert_allow' || value === 'block' ? value : 'alert_allow'
}

function positiveInt(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : undefined
}

// eslint-disable-next-line react-refresh/only-export-components
export function filePolicyDraft(value?: ContentFilePolicy): FilePolicyDraft {
  const allowedTypes = arrayValue(value?.allowed_types, DEFAULT_FILE_POLICY.allowed_types)
  const reviewTypes = arrayValue(value?.review_types, DEFAULT_FILE_POLICY.review_types)
  const blockedTypes = arrayValue(value?.blocked_types, DEFAULT_FILE_POLICY.blocked_types)
  const draft: FilePolicyDraft = {
    allowed_types: [...new Set([...allowedTypes, ...reviewTypes])].filter((item) => !RISK_TYPE_TOKENS.includes(item)),
    review_types: [],
    blocked_types: [...new Set(blockedTypes.filter((item) => !RISK_TYPE_TOKENS.includes(item)))],
    max_file_mb: value?.max_file_mb || DEFAULT_FILE_POLICY.max_file_mb,
    max_attachments: value?.max_attachments || DEFAULT_FILE_POLICY.max_attachments,
    max_zip_ratio: value?.max_zip_ratio || DEFAULT_FILE_POLICY.max_zip_ratio,
    executable_action: riskAction(value?.executable_action),
    disguised_executable_action: riskAction(value?.disguised_executable_action),
    script_action: riskAction(value?.script_action),
    unknown_action: riskAction(value?.unknown_action),
    zip_bomb_action: riskAction(value?.zip_bomb_action),
    unverified_file_reference_action: riskAction(value?.unverified_file_reference_action),
    file_reference_lookup_failure_action: riskAction(value?.file_reference_lookup_failure_action),
  }
  for (const { field } of ZIP_LIMITS) {
    const limit = positiveInt(value?.[field])
    if (limit !== undefined) draft[field] = limit
  }
  return draft
}

function actionForType(draft: FilePolicyDraft, type: string): FileTypeAction {
  if (draft.blocked_types.includes(type)) return 'blocked'
  return 'allowed'
}

function exceptionList(value: unknown): ContentExceptionRecord[] {
  const raw = value as { items?: unknown; data?: unknown } | undefined
  const list = Array.isArray(raw)
    ? raw
    : Array.isArray(raw?.items)
      ? raw.items
      : Array.isArray(raw?.data)
        ? raw.data
        : []
  return list.filter((item): item is ContentExceptionRecord => Boolean(
    item && typeof item === 'object' && typeof (item as ContentExceptionRecord).id === 'string',
  ))
}

function scopeLabel(value?: string, name?: string): string {
  if (name?.trim()) return name
  if (!value || value === 'tenant') return '全单位'
  return '对象已删除'
}

function ruleLabel(name?: string, reference?: string): string {
  if (name?.trim()) return name
  return reference ? '对象已删除' : '作用域级'
}

function decisionLabel(value?: string): string {
  return value === 'allow' ? '放行' : '告警并发送'
}

export function ContentExceptionSettings({ canManage }: ContentExceptionSettingsProps) {
  const exceptionsQuery = useQuery({
    queryKey: ['content-security', 'exceptions'],
    queryFn: () => contentSecurityApi.listExceptions(),
  })
  const [exceptions, setExceptions] = useState<ContentExceptionRecord[]>([])

  useEffect(() => {
    setExceptions(exceptionList(exceptionsQuery.data?.data))
  }, [exceptionsQuery.data])

  const deleteException = async (id: string) => {
    try {
      await contentSecurityApi.deleteException(id)
      message.success('内容例外已删除')
      setExceptions((current) => current.filter((item) => item.id !== id))
      await exceptionsQuery.refetch()
    } catch {
      message.error('内容例外删除失败，原例外仍保留')
    }
  }

  if (exceptionsQuery.isError) {
    return <Alert type="error" showIcon message="内容例外读取失败" description="没有取得当前内容例外，页面不会使用默认值代替。" />
  }

  return (
    <section className="file-policy-exceptions" aria-label="内容例外">
      <div className="file-policy-section-title">
        <strong>内容例外</strong>
        <span>保留范围、原因和到期时间；删除会请求服务端确认。</span>
      </div>
      {exceptions.length === 0 ? <p>暂无内容例外。</p> : (
        <ul>
          {exceptions.map((item) => (
            <li key={item.id} data-testid="content-exception-row">
              <div>
                <strong>{scopeLabel(item.scope_type, item.scope_name)}</strong>
                <span>{decisionLabel(item.decision)} · {ruleLabel(item.rule_name, item.rule_ref)} · {formatExceptionExpiry(item.expires_at)}</span>
                <span>{item.reason || '未填写原因'}</span>
              </div>
              {canManage ? (
                <Popconfirm
                  title="确认删除此内容例外？"
                  okText="确认删除"
                  cancelText="取消"
                  onConfirm={() => deleteException(item.id)}
                >
                  <Button size="small" danger aria-label="删除内容例外">删除</Button>
                </Popconfirm>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function FilePolicySettings({ canManage, showExceptions = true }: FilePolicySettingsProps) {
  const settingsQuery = useQuery({
    queryKey: ['system-settings'],
    queryFn: () => systemSettingsApi.get().then((response) => response.data),
  })
  const filePolicyQuery = useQuery({
    queryKey: ['content-security', 'file-policy'],
    queryFn: () => contentSecurityApi.getFilePolicy(),
  })
  const [draft, setDraft] = useState<FilePolicyDraft>(DEFAULT_FILE_POLICY)
  const [fileContentDlpEnabled, setFileContentDlpEnabled] = useState(false)
  const [uploadFailureAction, setUploadFailureAction] = useState<UploadFailureAction>('forward_alert')
  const [exceptionRule, setExceptionRule] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [saving, setSaving] = useState(false)
  // 用户改过但还没保存成功时不拿服务端值覆盖（含系统设置缓存刷新）；保存全部成功后再同步。
  const [dirty, setDirty] = useState(false)
  const editDraft = (update: (current: FilePolicyDraft) => FilePolicyDraft) => {
    setDirty(true)
    setDraft(update)
  }

  const uploadFailureFromSettings = (settings?: Record<string, unknown>): UploadFailureAction => (
    settings?.upload_inspection_failure_action === 'block' ? 'block' : 'forward_alert'
  )

  useEffect(() => {
    if (settingsQuery.isLoading || filePolicyQuery.isLoading || dirty) return
    const filePolicyResponse = filePolicyQuery.data as any
    setDraft(filePolicyDraft(filePolicyResponse?.allowed_types ? filePolicyResponse : filePolicyResponse?.data))
    setFileContentDlpEnabled(toBoolean(settingsQuery.data?.file_content_dlp_enabled))
    setUploadFailureAction(uploadFailureFromSettings(settingsQuery.data))
    setLoaded(true)
  }, [filePolicyQuery.data, filePolicyQuery.isLoading, settingsQuery.data, settingsQuery.isLoading, dirty])

  const setTypeAction = (type: string, action: FileTypeAction) => {
    editDraft((current) => ({
      ...current,
      allowed_types: [...current.allowed_types.filter((item) => item !== type), ...(action === 'allowed' ? [type] : [])],
      review_types: current.review_types.filter((item) => item !== type),
      blocked_types: [...current.blocked_types.filter((item) => item !== type), ...(action === 'blocked' ? [type] : [])],
    }))
  }

  const updateLimit = (field: 'max_file_mb' | 'max_attachments' | 'max_zip_ratio' | ZipLimitField, value: string) => {
    editDraft((current) => ({ ...current, [field]: value === '' ? undefined : Number(value) }))
  }

  const disabled = !canManage || !loaded || saving
  // 上传检测失败是全平台共享的安全键，只有平台级角色能改。
  // 正文检测开关写 /system/settings，只有系统管理员能改。
  const access = useAccess()
  const canWritePlatform = access.canManagePlatformSecuritySettings

  const save = async () => {
    if (!canManage || !loaded || saving) return
    const outOfRange = (Object.keys(FILE_LIMITS) as Array<keyof typeof FILE_LIMITS>).some((field) => {
      const value = draft[field]
      return !Number.isInteger(value) || value < FILE_LIMITS[field].min || value > FILE_LIMITS[field].max
    })
    if (outOfRange) {
      message.error('文件限制必须为：单文件 1-100 MB、单次 1-100 个、压缩比 1-1000 倍')
      return
    }
    const zipLimitError = ZIP_LIMITS.find(({ field, max }) => {
      const value = draft[field]
      return value !== undefined && (!Number.isInteger(value) || value < 1 || value > max)
    })
    if (zipLimitError) {
      message.error(`${zipLimitError.label}必须是 1-${zipLimitError.max} 的整数`)
      return
    }
    setSaving(true)
    // 分步保存：文件策略 → 正文检测开关 → 上传检测失败；记下已成功的步骤，失败时告诉用户哪些已保存。
    const saved: string[] = []
    let succeeded = false
    try {
      const payload: ContentFilePolicy = {
        allowed_types: draft.allowed_types,
        review_types: draft.review_types,
        blocked_types: draft.blocked_types,
        max_file_mb: draft.max_file_mb,
        max_attachments: draft.max_attachments,
        max_zip_ratio: draft.max_zip_ratio,
      }
      for (const { field } of RISK_ROWS) payload[field] = draft[field]
      for (const { field } of ZIP_LIMITS) if (draft[field] !== undefined) payload[field] = draft[field]
      await contentSecurityApi.updateFilePolicy(payload)
      saved.push('文件类型与高风险文件')
      // 只写改动过的键：正文检测开关走 /system/settings；上传检测失败是平台级安全键，走安全设置接口。
      if (access.canWriteSystemSettings && fileContentDlpEnabled !== toBoolean(settingsQuery.data?.file_content_dlp_enabled)) {
        await systemSettingsApi.update({ file_content_dlp_enabled: fileContentDlpEnabled })
        saved.push('正文检测开关')
      }
      if (canWritePlatform && uploadFailureAction !== uploadFailureFromSettings(settingsQuery.data)) {
        await securitySystemSettingsApi.update({ upload_inspection_failure_action: uploadFailureAction })
        saved.push('上传检测失败')
      }
      message.success('文件管控已保存')
      succeeded = true
    } catch (error) {
      const reason = extractApiError(error) || '保存失败'
      message.error(saved.length > 0 ? `已保存：${saved.join('、')}；未保存：${reason}` : `未保存：${reason}`)
    }
    try {
      // 重新拉取服务端值：全部成功时以服务端为准回填；失败时保留用户输入，只更新比对基准，可直接重试。
      const [policyResult, settingsResult] = await Promise.all([filePolicyQuery.refetch(), settingsQuery.refetch()])
      if (succeeded) {
        const fresh = policyResult.data as { data?: ContentFilePolicy } & ContentFilePolicy | undefined
        setDraft(filePolicyDraft(fresh?.allowed_types ? fresh : fresh?.data))
        setFileContentDlpEnabled(toBoolean(settingsResult.data?.file_content_dlp_enabled))
        setUploadFailureAction(uploadFailureFromSettings(settingsResult.data))
        setDirty(false)
      }
    } finally {
      setSaving(false)
    }
  }

  if (settingsQuery.isError || filePolicyQuery.isError) {
    return <Alert type="error" showIcon message="文件管控读取失败" description="没有取得完整文件配置，页面不会使用默认值代替。" />
  }

  return (
    <div className="file-policy-settings">
      <section className="file-policy-send-section" aria-labelledby="file-policy-send-title">
        <div className="file-policy-section-title">
          <div>
            <h2 id="file-policy-send-title">网页 AI 附件准入</h2>
            <p>仅控制网页 AI、Chat 门户和 API 中以真实附件、文件引用或 multipart 形式发送的文件。编码智能体读取本地文件后形成的文本或工具结果不适用，需由敏感数据和智能体行为策略管控。</p>
          </div>
        </div>
        <div className="file-policy-send-list">
          {FILE_TYPE_OPTIONS.map((option) => {
            const blocked = actionForType(draft, option.value) === 'blocked'
            return (
              <div key={option.value} className={blocked ? 'file-policy-send-row file-policy-send-row-with-action' : 'file-policy-send-row'}>
                <span className="file-policy-type-name">{option.label}</span>
                <select
                  aria-label={`${option.label}发送方式`}
                  value={actionForType(draft, option.value)}
                  disabled={disabled}
                  onChange={(event) => setTypeAction(option.value, event.target.value as FileTypeAction)}
                >
                  {FILE_ACTION_OPTIONS.map((action) => <option key={action.value} value={action.value}>{action.label}</option>)}
                </select>
                {blocked ? (
                  <Button size="small" disabled={!canManage} aria-label={`${option.label}加例外`} onClick={() => setExceptionRule(blockedTypeRuleId(option.value))}>加例外</Button>
                ) : null}
              </div>
            )
          })}
        </div>
        <div className="file-policy-send-list file-policy-risk-list" aria-label="高风险文件">
          {RISK_ROWS.map((row) => (
            <div key={row.field} className="file-policy-send-row" data-testid={`file-risk-${row.field}`}>
              <span className="file-policy-type-name">{row.label}</span>
              <select
                aria-label={`${row.label}处理方式`}
                value={draft[row.field]}
                disabled={disabled}
                onChange={(event) => {
                  const value = event.target.value as FileRiskAction
                  editDraft((current) => ({ ...current, [row.field]: value }))
                }}
              >
                {RISK_ACTION_OPTIONS.map((action) => <option key={action.value} value={action.value}>{action.label}</option>)}
              </select>
              {row.ruleId ? (
                <Button size="small" disabled={!canManage} aria-label={`${row.label}加例外`} onClick={() => setExceptionRule(row.ruleId!)}>加例外</Button>
              ) : null}
              {row.field === 'zip_bomb_action' ? (
                <span className="file-policy-zip-limits">
                  {ZIP_LIMITS.map(({ field, label, max }) => (
                    <label key={field}>{label}<input aria-label={label} type="number" min={1} max={max} placeholder="默认" value={draft[field] ?? ''} disabled={disabled} onChange={(event) => updateLimit(field, event.target.value)} /></label>
                  ))}
                </span>
              ) : null}
            </div>
          ))}
          <div className="file-policy-send-row">
            <span className="file-policy-type-name">上传检测失败</span>
            <select
              aria-label="上传检测失败处理方式"
              value={uploadFailureAction}
              disabled={disabled || !canWritePlatform}
              onChange={(event) => { setDirty(true); setUploadFailureAction(event.target.value as UploadFailureAction) }}
            >
              <option value="forward_alert">转发并告警</option>
              <option value="block">拦截</option>
            </select>
          </div>
        </div>
      </section>
      <details className="file-policy-advanced">
        <summary>其他限制（可选）</summary>
        <div className="file-policy-switch-row">
          <div>
            <strong>文件正文敏感数据检测</strong>
            <span>开启后检查文件正文中的敏感信息。</span>
          </div>
          <input
            type="checkbox"
            aria-label="文件正文敏感数据检测"
            checked={fileContentDlpEnabled}
            disabled={disabled || !access.canWriteSystemSettings}
            onChange={(event) => { setDirty(true); setFileContentDlpEnabled(event.target.checked) }}
          />
        </div>
        <p className="file-policy-support-note">正文检测支持 TXT、CSV、JSON、DOCX、PPTX、XLSX 和文本型 PDF；图片 OCR、扫描 PDF、旧版 Office 和压缩包递归检测不在支持范围内。</p>
        <p className="file-policy-support-note">正文命中按命中规则在策略中心配置的动作处理（配置为阻断才阻断）。</p>
        <div className="file-policy-limits">
          <label>单个文件大小（MB）<input aria-label="单个文件大小（MB）" type="number" min={1} max={100} value={draft.max_file_mb} disabled={disabled} onChange={(event) => updateLimit('max_file_mb', event.target.value)} /></label>
          <label>单次文件数量<input aria-label="单次文件数量" type="number" min={1} max={100} value={draft.max_attachments} disabled={disabled} onChange={(event) => updateLimit('max_attachments', event.target.value)} /></label>
          <label>压缩比上限<input aria-label="压缩比上限" type="number" min={1} max={1000} value={draft.max_zip_ratio} disabled={disabled} onChange={(event) => updateLimit('max_zip_ratio', event.target.value)} /></label>
        </div>
      </details>
      <Button type="primary" aria-label="保存网页 AI 附件准入" loading={saving} disabled={!canManage || !loaded} onClick={save}>保存网页 AI 附件准入</Button>
      {exceptionRule ? <ContentExceptionModal ruleId={exceptionRule} onClose={() => setExceptionRule(null)} /> : null}
      {showExceptions ? <ContentExceptionSettings canManage={canManage} /> : null}
    </div>
  )
}

export default FilePolicySettings
