import { useEffect, useMemo, useState } from 'react'
import { Card, Form, Input, Button, Tag, Modal, Space, Typography, Alert, Descriptions, Select, Switch } from 'antd'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { message } from 'antd'
import {
  identityApi,
  identitySourcesApi,
  DEFAULT_IDENTITY_SOURCE_ALIAS,
  NEW_IDENTITY_SOURCE,
  type IdentitySourceWithAlias,
} from '../services/api'
import { EnterprisePageHeader } from '../components/EnterpriseUI'
import DepartmentMappings from '../components/identity/DepartmentMappings'

const { Text } = Typography

const IDENTITY_ERROR_MESSAGES: Record<string, string> = {
  identity_runtime_unavailable: '身份服务暂不可用，本地管理员登录不受影响',
  identity_runtime_unauthorized: '身份服务授权异常，请联系平台运维人员',
  identity_publish_conflict: '配置已发生变化，请刷新后重试',
  identity_publish_failed: '身份配置发布失败，原有登录配置未切换',
  identity_rollback_failed: '身份配置恢复失败，请暂停操作并联系平台运维人员',
  identity_runtime_drifted: '运行配置与当前设置不一致，请按当前配置修复',
  emergency_admin_required: '请先保留一个可使用密码登录的本地管理员',
  identity_manage_realm_required:
    '启用「首次登录不弹资料页」需要给身份运行服务账号授予 manage-realm 权限，请联系平台运维人员，详见升级文档（identity-nonstandard-oidc）；当前登录配置未切换',
  // 采纳现场运行态
  adopt_target_not_active: '同一登录入口下已有启用中的身份源，运行配置属于启用中的那一条，请改为采纳它',
  runtime_not_found: '运行环境中没有该身份源的配置，无可采纳内容',
  adopt_target_not_adoptable: '仅启用中或已停用的身份源可采纳（当前处于编辑中，请先发布或放弃草稿）',
  signature_none_requires_https: '选择「不校验签名」时，token 端点必须是 https',
}

function identityMutationError(error: any, fallback: string): string {
  const code = error?.response?.data?.error?.code
  if (typeof code === 'string' && IDENTITY_ERROR_MESSAGES[code]) {
    return IDENTITY_ERROR_MESSAGES[code]
  }
  return fallback
}

function toArr(r: any): any[] {
  if (Array.isArray(r?.data)) return r.data
  if (Array.isArray(r?.items)) return r.items
  if (Array.isArray(r)) return r
  return []
}

type IdentityTestFeedback = {
  type: 'success' | 'error'
  message: string
  // 非阻断的发现性提示（例如 IdP 使用对称签名），不影响测试结果
  hints?: string[]
}

type AdoptResult = {
  signature_mode?: string
  username_claim?: string
  skip_profile_review?: boolean
  unresolved: string[]
  sameAlias: number
}

// 用户名取值：落到后端 username_claim；其余值视为已保存的自定义声明，原样保留展示。
const USERNAME_CLAIM_OPTIONS = [
  { value: 'preferred_username', label: 'preferred_username（默认）' },
  { value: 'email', label: '邮箱（email）' },
  { value: 'sub', label: '用户唯一标识（sub）' },
]

const SIGNATURE_MODE_OPTIONS = [
  { value: 'jwks', label: '按 IdP 公钥验签（JWKS，推荐）' },
  { value: 'none', label: '不校验签名' },
]

// W9 9.8：与后端 normalizeIdentityScopes 同口径（RFC 6749 scope-token；必须含 openid；≤256）。
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/
function validateScopes(value: unknown): Promise<void> {
  const raw = typeof value === 'string' ? value.replace(/^[ \t]+|[ \t]+$/g, '') : ''
  if (raw === '') return Promise.resolve()
  // 只按 ASCII 空格/制表符切分，与后端一致：U+00A0 等 Unicode 空白留在 token 内并被拒绝
  const tokens = raw.split(/[ \t]+/)
  if (tokens.some((t) => !SCOPE_TOKEN.test(t))) {
    return Promise.reject(new Error('Scopes 只允许以空格分隔的标准 scope 名称'))
  }
  if (!tokens.includes('openid')) {
    return Promise.reject(new Error('Scopes 必须包含 openid'))
  }
  if (Array.from(new Set(tokens)).join(' ').length > 256) {
    return Promise.reject(new Error('Scopes 不能超过 256 个字符'))
  }
  return Promise.resolve()
}

function aliasOf(s: IdentitySourceWithAlias): string {
  return s.source_alias || DEFAULT_IDENTITY_SOURCE_ALIAS
}

export default function SsoConfig() {
  const qc = useQueryClient()
  const [form] = Form.useForm()
  const [testFeedback, setTestFeedback] = useState<IdentityTestFeedback | null>(null)
  const [adoptResult, setAdoptResult] = useState<AdoptResult | null>(null)
  // W9 9.2：当前编辑的身份源。默认身份源走原有接口（不带 source），其余身份源显式带 source。
  const [selected, setSelected] = useState<string>(DEFAULT_IDENTITY_SOURCE_ALIAS)
  const isDefault = selected === DEFAULT_IDENTITY_SOURCE_ALIAS
  const isNew = selected === NEW_IDENTITY_SOURCE
  const signatureMode = Form.useWatch('signature_mode', form)
  const usernameClaim = Form.useWatch('username_claim', form)

  const sourcesQ = useQuery({ queryKey: ['identity-sources'], queryFn: () => identityApi.getSources() })
  const statusQ = useQuery({
    queryKey: ['identity-status', selected],
    queryFn: () => (isDefault ? identityApi.getStatus() : identitySourcesApi.getStatus(selected)),
    enabled: !isNew,
  })

  const allSources: IdentitySourceWithAlias[] = toArr(sourcesQ.data?.data)
  const sourceOptions = useMemo(() => {
    const seen = new Map<string, string>()
    seen.set(DEFAULT_IDENTITY_SOURCE_ALIAS, '')
    for (const s of allSources) {
      const a = aliasOf(s)
      // 同一身份源有多个版本时，优先展示启用中的名称
      if (!seen.get(a) || s.status === 'active') seen.set(a, s.display_name)
    }
    return Array.from(seen.entries()).map(([value, name]) => ({
      value,
      label: value === DEFAULT_IDENTITY_SOURCE_ALIAS ? `默认身份源${name ? `（${name}）` : ''}` : name || value,
    }))
  }, [allSources])
  const sources = isNew ? [] : allSources.filter((s) => aliasOf(s) === selected)
  const status = isNew ? undefined : statusQ.data?.data
  const draft = sources.find((s) => s.status === 'draft' || s.status === 'tested')
  const active = sources.find((s) => s.status === 'active')

  const canActivate = !!draft && draft.status === 'tested'
  // IdP 同时支持 RS256 的发现性提示：选了「不校验签名」时在风险提示里同样给出
  const rs256Hint = (testFeedback?.hints ?? draft?.last_test_result?.hints ?? active?.last_test_result?.hints ?? [])
    .find((h) => h.includes('RS256'))

  useEffect(() => {
    if (!draft) {
      form.resetFields()
      return
    }
    form.setFieldsValue({
      display_name: draft.display_name,
      issuer_url: draft.issuer_url,
      client_id: draft.client_id,
      client_secret: undefined,
      scopes: draft.scopes,
      subject_claim: draft.subject_claim,
      username_claim: draft.username_claim,
      name_claim: draft.name_claim,
      email_claim: draft.email_claim,
      phone_claim: draft.phone_claim,
      dept_code_claim: draft.dept_code_claim,
      dept_name_claim: draft.dept_name_claim,
      groups_claim: draft.groups_claim,
      signature_mode: draft.signature_mode || 'jwks',
      skip_profile_review: !!draft.skip_profile_review,
    })
  }, [draft, form])

  const saveMutation = useMutation({
    mutationFn: (v: any) => (isDefault ? identityApi.saveDraft(v) : identitySourcesApi.saveDraft(selected, v)),
    onSuccess: (response: any) => {
      message.success('草稿已保存')
      const created = response?.data?.source_alias
      if (isNew && typeof created === 'string' && created) setSelected(created)
      qc.invalidateQueries({ queryKey: ['identity-sources'] })
      qc.invalidateQueries({ queryKey: ['identity-status'] })
    },
    onError: (e: any) => message.error(identityMutationError(e, '保存失败')),
  })

  const testMutation = useMutation({
    mutationFn: () => (isDefault ? identityApi.testConnection() : identitySourcesApi.testConnection(selected)),
    onMutate: () => setTestFeedback(null),
    onSuccess: (response) => {
      const result = response?.data as { success?: boolean; error?: string; hints?: string[] } | undefined
      const success = result?.success === true
      const resultMessage = typeof result?.error === 'string' && result.error.trim()
        ? result.error
        : success ? '身份源连接测试通过' : '身份源连接测试未通过'
      const hints = Array.isArray(result?.hints) ? result!.hints!.filter((h) => typeof h === 'string' && h) : []
      setTestFeedback({ type: success ? 'success' : 'error', message: resultMessage, hints })
      if (success) {
        message.success(resultMessage)
      } else {
        message.error(resultMessage)
      }
      qc.invalidateQueries({ queryKey: ['identity-sources'] })
      qc.invalidateQueries({ queryKey: ['identity-status'] })
    },
    onError: (e: any) => {
      const errorMessage = identityMutationError(e, '测试失败')
      setTestFeedback({ type: 'error', message: errorMessage })
      message.error(errorMessage)
    },
  })

  const activateMutation = useMutation({
    mutationFn: () => (isDefault ? identityApi.activate() : identitySourcesApi.activate(selected)),
    onSuccess: () => {
      message.success('身份源已启用')
      qc.invalidateQueries({ queryKey: ['identity-sources'] })
      qc.invalidateQueries({ queryKey: ['identity-status'] })
    },
    onError: (e: any) => message.error(identityMutationError(e, '启用失败')),
  })

  const disableMutation = useMutation({
    mutationFn: (confirm: boolean) =>
      isDefault ? identityApi.disable(confirm) : identitySourcesApi.disable(selected, confirm),
    onSuccess: () => {
      message.success('身份源已停用')
      qc.invalidateQueries({ queryKey: ['identity-sources'] })
      qc.invalidateQueries({ queryKey: ['identity-status'] })
    },
    onError: (e: any) => message.error(identityMutationError(e, '停用失败')),
  })

  // 采纳现场运行态：只读取运行配置并回写到产品配置，不修改身份服务。
  const adoptMutation = useMutation({
    mutationFn: (sourceId: string) => identityApi.adoptRuntime(sourceId),
    onSuccess: (response: any) => {
      const data = response?.data ?? {}
      const sameAlias = Array.isArray(data.same_alias_sources) ? data.same_alias_sources.length : 0
      setAdoptResult({
        signature_mode: data.adopted?.signature_mode,
        username_claim: data.adopted?.username_claim,
        skip_profile_review: data.adopted?.skip_profile_review,
        unresolved: Array.isArray(data.unresolved) ? data.unresolved : [],
        sameAlias,
      })
      message.success('已采纳现场运行配置，请再点「按当前配置修复」使其变为生效中')
      qc.invalidateQueries({ queryKey: ['identity-sources'] })
      qc.invalidateQueries({ queryKey: ['identity-status'] })
    },
    onError: (e: any) => {
      // 采纳期间配置被他人修改：用更贴切的文案，其余沿用统一映射
      if (e?.response?.data?.error?.code === 'identity_publish_conflict') {
        message.error('配置已被他人修改，请刷新后重试')
        return
      }
      message.error(identityMutationError(e, '采纳失败，请稍后重试'))
    },
  })
  const DRIFT_FIELD_LABELS: Record<string, string> = {
    signature_mode: 'id_token 验签方式',
    username_claim: '用户名取值',
    skip_profile_review: '首次登录不弹资料页',
  }
  const adoptRecommended = !!status?.adopt_recommended
  const driftLabels = (status?.drift_fields ?? []).map((k: string) => DRIFT_FIELD_LABELS[k] ?? k).join('、')
  const adoptButton = status?.publish_status === 'drifted' && active ? (
    <Button
      type={adoptRecommended ? 'primary' : undefined}
      loading={adoptMutation.isPending}
      onClick={() => Modal.confirm({
        title: '采纳现场运行态',
        content: '只读取运行配置并回写到产品配置，不修改身份服务。完成后需再点「按当前配置修复」，身份源才会变为生效中。注意：「首次登录不弹资料页」是整个登录入口级的设置，采纳到的开关状态反映的是整个登录入口的现状，而不只是这一个身份源。',
        okText: '确认采纳',
        cancelText: '取消',
        onOk: () => adoptMutation.mutateAsync(active.id).catch(() => undefined),
      })}
    >
      采纳现场运行态
    </Button>
  ) : null

  const reconcileMutation = useMutation({
    mutationFn: () => (isDefault ? identityApi.reconcile() : identitySourcesApi.reconcile(selected)),
    onSuccess: () => {
      message.success('身份配置已修复')
      qc.invalidateQueries({ queryKey: ['identity-sources'] })
      qc.invalidateQueries({ queryKey: ['identity-status'] })
    },
    onError: (e: any) => message.error(identityMutationError(e, '修复失败')),
  })

  const statusTag = useMemo(() => {
    switch (status?.publish_status) {
      case 'publishing':
        return <Tag color="processing">发布中</Tag>
      case 'drifted':
        return <Tag color="orange">配置需修复</Tag>
      case 'error':
        return <Tag color="red">发布异常</Tag>
      case 'disabled':
        return <Tag>已停用</Tag>
      case 'active':
        return <Tag color="green">已启用</Tag>
      default:
        break
    }
    if (active || status?.has_active) return <Tag color="green">已启用</Tag>
    if (draft?.status === 'tested') return <Tag color="blue">测试通过</Tag>
    if (draft) return <Tag color="orange">草稿</Tag>
    return <Tag>未配置</Tag>
  }, [active, draft, status?.has_active, status?.publish_status])



  return (
    <div>
      <EnterprisePageHeader
        eyebrow="身份与访问"
        title="登录与单点登录"
        description="统一企业身份源接入，支持标准 OIDC 协议与部门属性映射"
      />

      <Card style={{ marginTop: 16, marginBottom: 16 }}>
        <Descriptions column={3} size="small">
          <Descriptions.Item label="当前状态">{statusTag}</Descriptions.Item>
          <Descriptions.Item label="启用中">{active?.display_name || status?.active_display_name || '—'}</Descriptions.Item>
          <Descriptions.Item label="草稿">{draft?.display_name || '—'}</Descriptions.Item>
          <Descriptions.Item label="应急管理员">
            {status?.emergency_admin_available ? <Tag color="green">可用</Tag> : <Tag color="red">不可用</Tag>}
          </Descriptions.Item>
        </Descriptions>
        {status && !status.emergency_admin_available && (
          <Alert style={{ marginTop: 12 }} type="warning" message="未检测到应急管理员，停用单点登录后可能无法登录" />
        )}
        {status?.runtime_message && (
          <Alert
            style={{ marginTop: 12 }}
            type={status.drift ? 'warning' : 'info'}
            message={status.runtime_message}
            showIcon
          />
        )}
      </Card>

      <Card
        title="企业 SSO 配置"
        style={{ marginBottom: 16 }}
        extra={
          <Space>
            <Text type="secondary">身份源</Text>
            <Select
              aria-label="选择身份源"
              style={{ minWidth: 220 }}
              value={selected}
              onChange={(v) => {
                setTestFeedback(null)
                setAdoptResult(null)
                setSelected(v)
              }}
              options={[...sourceOptions, { value: NEW_IDENTITY_SOURCE, label: '+ 新增身份源' }]}
            />
          </Space>
        }
      >
        {isNew && (
          <Alert
            style={{ marginBottom: 12 }}
            type="info"
            showIcon
            message="新增身份源"
            description="保存草稿后生成该身份源独立的回调地址，需登记到对应的企业 IdP；新增身份源不影响已启用的身份源。"
          />
        )}
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            dept_code_claim: 'department_code', dept_name_claim: 'department_name', groups_claim: 'groups',
            signature_mode: 'jwks', username_claim: 'preferred_username', skip_profile_review: false,
          }}
          onFinish={(v) => saveMutation.mutate(v)}
        >
          <Form.Item name="display_name" label="显示名称" rules={[{ required: true, message: '请输入显示名称' }]}>
            <Input placeholder="如：企业统一身份" maxLength={128} />
          </Form.Item>
          <Form.Item name="issuer_url" label="Issuer 地址" rules={[{ required: true, message: '请输入 OIDC Issuer 地址' }]}>
            <Input placeholder="https://idp.example.com/realms/example" />
          </Form.Item>
          <Form.Item name="client_id" label="Client ID" rules={[{ required: true, message: '请输入 Client ID' }]}>
            <Input />
          </Form.Item>
          <Form.Item
            name="client_secret"
            label="Client Secret"
            extra={draft?.client_secret_set ? <Text type="secondary">已设置，留空表示不修改</Text> : undefined}
          >
            <Input.Password placeholder={draft?.client_secret_set ? '留空保留当前密钥' : '输入 Client Secret'} />
          </Form.Item>
          <Form.Item
            name="scopes"
            label="Scopes"
            extra="以空格分隔，必须包含 openid；留空使用默认值 openid profile email。部门/用户组等声明需要 IdP 额外授权的 scope 时在此追加。"
            rules={[{ validator: (_rule, value) => validateScopes(value) }]}
          >
            <Input placeholder="openid profile email" />
          </Form.Item>

          <Form.Item
            name="signature_mode"
            label="id_token 验签方式"
            extra="默认按 IdP 公开的密钥（JWKS）校验 id_token 签名。仅当 IdP 使用对称密钥（如 HS256）签名、无法按公钥验签时才需要改选。"
          >
            <Select aria-label="id_token 验签方式" options={SIGNATURE_MODE_OPTIONS} />
          </Form.Item>
          {signatureMode === 'none' && (
            <Alert
              style={{ marginBottom: 24 }}
              type="error"
              showIcon
              message="风险提示：不校验 id_token 签名"
              description={
                <div>
                  <div>仅在由本服务端经 HTTPS 直连令牌端点换取 token 时可用；一旦令牌来源不可信，存在被伪造 id_token 的风险。默认关闭，确认 IdP 无法提供公钥验签时再启用。</div>
                  {rs256Hint && <div style={{ marginTop: 8 }}>{rs256Hint}</div>}
                </div>
              }
            />
          )}
          <Form.Item
            name="username_claim"
            label="用户名取值"
            extra="登录后用哪个字段作为用户名。IdP 不返回 preferred_username 时请选择邮箱。"
          >
            <Select
              aria-label="用户名取值"
              options={
                usernameClaim && !USERNAME_CLAIM_OPTIONS.some((o) => o.value === usernameClaim)
                  ? [...USERNAME_CLAIM_OPTIONS, { value: usernameClaim, label: `${usernameClaim}（已保存的自定义取值）` }]
                  : USERNAME_CLAIM_OPTIONS
              }
            />
          </Form.Item>
          <Form.Item
            name="skip_profile_review"
            label="首次登录不弹资料页"
            valuePropName="checked"
            extra="开启后用户首次通过该身份源登录时直接进入，不再要求补全姓名等资料。该设置作用于整个登录入口，之后关闭本选项不会还原已开启的设置。"
          >
            <Switch aria-label="首次登录不弹资料页" />
          </Form.Item>

          <Form.Item name="dept_code_claim" label="部门编码字段" extra="身份源中保存部门编码的属性名；用于匹配下方部门映射。留空使用 department_code。">
            <Input placeholder="department_code" maxLength={128} />
          </Form.Item>
          <Form.Item name="dept_name_claim" label="部门名称字段" extra="身份源中保存部门名称的属性名。留空使用 department_name。">
            <Input placeholder="department_name" maxLength={128} />
          </Form.Item>
          <Form.Item name="groups_claim" label="用户组字段" extra="身份源中保存用户组列表的属性名；用于匹配下方用户组规则。留空使用 groups。">
            <Input placeholder="groups" maxLength={128} />
          </Form.Item>

          <Form.Item label="回调地址">
            {status?.callback_url ? (
              <Space direction="vertical" size={8}>
              <Text code copyable>{status.callback_url}</Text>
              {status.callback_url.startsWith('http://') && (
                <Alert
                  style={{ marginTop: 8 }}
                  type="warning"
                  message="当前为私有部署/测试回调地址"
                  description="这是基于部署主机 IP 的 HTTP 地址，企业 IdP 可能要求 HTTPS 或稳定域名；正式交付建议配置域名与 HTTPS。"
                  showIcon
                />
              )}
              </Space>
            ) : isNew ? (
              <Text type="secondary">保存草稿后生成</Text>
            ) : (
              <Alert
                type="warning"
                message="部署尚未配置公开 SSO 地址"
                description="请联系平台运维人员完成公开访问地址配置后，再将回调地址登记到企业身份源。"
                showIcon
              />
            )}
          </Form.Item>

          <Space>
            <Button type="primary" htmlType="submit" loading={saveMutation.isPending}>保存草稿</Button>
            <Button loading={testMutation.isPending} onClick={() => testMutation.mutate()}>测试连接</Button>
            <Button
              type="primary"
              disabled={!canActivate}
              loading={activateMutation.isPending}
              onClick={() => activateMutation.mutate()}
            >
              确认启用
            </Button>
            {adoptRecommended && adoptButton}
            {status?.drift && (
              <Button
                loading={reconcileMutation.isPending}
                onClick={() => Modal.confirm({
                  title: '确认修复',
                  content: adoptRecommended
                    ? `将用平台保存的配置覆盖身份服务中的当前设置（${driftLabels}），可能导致单点登录失败。如这些差异是现场有意调整，请先采纳现场运行态。`
                    : '将按 JJDGuard 当前已保存配置覆盖运行中的身份设置。修复完成前，原有本地管理员登录不受影响。',
                  okText: '确认修复',
                  okButtonProps: adoptRecommended ? { danger: true } : undefined,
                  cancelText: '取消',
                  onOk: () => reconcileMutation.mutateAsync(),
                })}
              >
                按当前配置修复
              </Button>
            )}
            {!adoptRecommended && adoptButton}
            {(active || status?.has_active) && (
              <Button
                danger
                onClick={() => Modal.confirm({
                  title: '确认停用',
                  content: '停用后用户将无法通过该身份源登录，请确认应急管理员可用。',
                  okText: '确认停用',
                  okButtonProps: { danger: true },
                  onOk: () => disableMutation.mutate(true),
                })}
              >
                停用
              </Button>
            )}
          </Space>
          {testFeedback && (
            <Alert
              style={{ marginTop: 12 }}
              type={testFeedback.type}
              message={testFeedback.message}
              showIcon
            />
          )}
          {adoptResult && (
            <Alert
              style={{ marginTop: 12 }}
              type="info"
              showIcon
              closable
              onClose={() => setAdoptResult(null)}
              message="已采纳现场运行配置（尚未生效，请再点「按当前配置修复」）"
              description={
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  <li>id_token 验签方式：{adoptResult.signature_mode === 'none' ? '不校验签名' : '按 IdP 公钥验签'}</li>
                  <li>用户名取值：{adoptResult.username_claim || '—'}</li>
                  <li>首次登录不弹资料页：{adoptResult.skip_profile_review ? '是' : '否'}</li>
                  {adoptResult.unresolved.includes('username_claim') && (
                    <li>未能从现场配置确定用户名取值，已保留原设置，请核对。</li>
                  )}
                  {adoptResult.sameAlias > 0 && (
                    <li>同一登录入口下还有 {adoptResult.sameAlias} 条其他身份源记录，未被改动，请确认是否需要清理。</li>
                  )}
                </ul>
              }
            />
          )}
          {testFeedback?.hints && testFeedback.hints.length > 0 && (
            <Alert
              style={{ marginTop: 12 }}
              type="warning"
              showIcon
              message="配置建议（不影响测试结果）"
              description={
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {testFeedback.hints.map((h) => <li key={h}>{h}</li>)}
                </ul>
              }
            />
          )}
        </Form>
      </Card>

      <DepartmentMappings key={selected} sources={sources} />
    </div>
  )
}
