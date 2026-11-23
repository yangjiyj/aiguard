import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import api, { contentSecurityApi } from '../services/api'
import { securityPoliciesApi, type SecurityPolicy } from '../services/securityPoliciesApi'
import {
  findSensitiveItemPolicies,
  SENSITIVE_DATA_CATEGORIES,
} from '../pages/security-policy/policyCenterModel'
import PolicyCenterScene from '../pages/security-policy/PolicyCenterScene'
import SensitiveDataPolicy from '../pages/security-policy/SensitiveDataPolicy'
import FilePolicySettings from '../pages/security-policy/FilePolicySettings'
import { useAuthStore } from '../stores/auth'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      error: vi.fn(),
    },
  }
})

const capability = (category: string, allowedActions: SecurityPolicy['action'][] = ['audit', 'mask', 'block']) => ({
  category,
  name: category,
  kind: 'static' as const,
  enabled: true,
  binding_mode: 'any' as const,
  supported_stages: ['input', 'output'],
  allowed_actions: allowedActions,
  mask_capable: allowedActions.includes('mask'),
})

const policy = (
  id: string,
  categories: string[],
  overrides: Partial<SecurityPolicy> = {},
): SecurityPolicy => ({
  id,
  name: '内部名称不作为映射依据',
  description: '',
  scene: 'data_leak',
  severity: 'high',
  action: 'mask',
  enabled: true,
  source: 'system',
  ownership: 'platform',
  origin: 'preloaded',
  detection_basis: 'capability',
  detection_configured: true,
  detection_ready: true,
  runtime_active: true,
  capabilities: categories.map((category) => capability(category)),
  ...overrides,
})

const queryWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('策略中心内容与文件配置', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('按完整目录映射 6 类 31 项，API Key 部分能力不能匹配', () => {
    const items = SENSITIVE_DATA_CATEGORIES.flatMap((category) => category.items)
    expect(SENSITIVE_DATA_CATEGORIES.map((category) => category.key)).toEqual([
      'identity_documents',
      'contact_location',
      'credentials',
      'financial',
      'health_biometrics',
      'enterprise_sensitive',
    ])
    expect(items).toHaveLength(31)
    expect(items.every((item) => item.capabilityCategories.length > 0)).toBe(true)

    const apiKeyItem = items.find((item) => item.key === 'api_key')
    expect(apiKeyItem?.capabilityCategories).toEqual([
      'generic_api_key',
      'openai_key',
      'anthropic_key',
      'github_token',
    ])
    expect(findSensitiveItemPolicies([
      policy('api-key-full', apiKeyItem!.capabilityCategories),
      policy('api-key-unconfigured', apiKeyItem!.capabilityCategories, { detection_configured: false }),
      policy('api-key-partial', ['generic_api_key', 'openai_key']),
    ], apiKeyItem!)).toHaveLength(1)
    expect(findSensitiveItemPolicies([
      policy('api-key-partial', ['generic_api_key', 'openai_key']),
    ], apiKeyItem!)).toHaveLength(0)

    const privateKeyItem = items.find((item) => item.key === 'certificate_private_key')
    expect(privateKeyItem).toMatchObject({
      capabilityCategories: ['ssh_private_key', 'openssh_private_key'],
      allowMultiplePolicies: true,
    })
    expect(findSensitiveItemPolicies([
      policy('private-key', ['ssh_private_key'], { name: '证书/私钥检测' }),
      policy('openssh-key', ['openssh_private_key'], { name: 'SSH 密钥检测' }),
    ], privateKeyItem!)).toHaveLength(2)
  })

  it('Prompt 注入只提供告警并发送和阻止请求，并且保存只提交本场景', async () => {
    const user = userEvent.setup()
    const batch = vi.spyOn(securityPoliciesApi, 'batch').mockResolvedValue({ data: {} } as never)
    render(
      <PolicyCenterScene
        sceneKey="prompt-injection"
        policies={[
          policy('prompt-1', ['phone_cn'], { scene: 'prompt_injection', action: 'audit', name: '提示注入一' }),
          policy('prompt-2', ['id_card_cn'], { scene: 'prompt_leak', action: 'block', name: '提示泄露二' }),
          policy('content-1', ['email'], { scene: 'content_safety', action: 'audit', name: '内容安全' }),
        ]}
        auditOnly={false}
        runtimeVerified
        runtimeStatus="verified"
        canManage
        onSaved={vi.fn()}
      />,
    )

    expect(screen.getByText('当前配置不一致')).toBeInTheDocument()
    const action = screen.getByRole('combobox', { name: 'Prompt 注入处置动作' })
    expect(screen.queryByRole('option', { name: '脱敏后发送' })).not.toBeInTheDocument()
    await user.selectOptions(action, 'block')
    await user.click(screen.getByRole('button', { name: '保存 Prompt 注入配置' }))

    await waitFor(() => expect(batch).toHaveBeenCalledWith([
      { id: 'prompt-1', action: 'block' },
      { id: 'prompt-2', action: 'block' },
    ]))
  })

  it('首次打开只读取已有敏感数据动作，记录模式同时显示配置动作和实际动作', async () => {
    const batch = vi.spyOn(securityPoliciesApi, 'batch').mockResolvedValue({ data: {} } as never)
    const sensitivePolicies = [
      policy('phone', ['phone_cn'], { action: 'mask', name: '手机号策略' }),
      policy('id-card', ['id_card_cn'], { action: 'mask', name: '身份证策略' }),
      policy('email', ['email'], { action: 'mask', name: '邮箱策略' }),
    ]
    render(
      <SensitiveDataPolicy
        policies={sensitivePolicies}
        auditOnly
        runtimeVerified
        runtimeStatus="verified"
        canManage
        onSaved={vi.fn()}
      />,
      { wrapper: queryWrapper() },
    )

    expect(await screen.findByRole('heading', { name: '分类保护策略' })).toBeInTheDocument()
    const identityRow = screen.getByText('身份与证件').closest<HTMLElement>('[role="row"]')
    expect(identityRow).not.toBeNull()
    expect(within(identityRow!).getByText('2 / 7')).toBeInTheDocument()
    expect(within(identityRow!).getByText('脱敏后发送')).toBeInTheDocument()
    expect(within(identityRow!).getByText('仅记录')).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: '身份与证件' })).not.toBeInTheDocument()
    expect(batch).not.toHaveBeenCalled()
  })

  it('31 项能力全部接入时六个分类均显示完整保护', async () => {
    const productionActions: Record<string, SecurityPolicy['action']> = {
      bank_card: 'mask',
      credit_card_cvv: 'block',
      bank_statement: 'mask',
      insurance: 'mask',
      classified_file: 'block',
      internal_project_code: 'audit',
      sensitive_code: 'mask',
      education: 'audit',
      criminal_record: 'mask',
    }
    const completePolicies = SENSITIVE_DATA_CATEGORIES.flatMap((category) => (
      category.items.map((item) => policy(
        `complete-${item.key}`,
        item.capabilityCategories,
        { name: item.policyNames?.[0] ?? item.label, action: productionActions[item.key] ?? category.defaultAction },
      ))
    ))

    render(
      <SensitiveDataPolicy
        policies={completePolicies}
        auditOnly={false}
        runtimeVerified
        runtimeStatus="verified"
        canManage
        onSaved={vi.fn()}
      />,
      { wrapper: queryWrapper() },
    )

    expect(await screen.findByRole('heading', { name: '分类保护策略' })).toBeInTheDocument()
    for (const [expected, count] of Object.entries({ '7 / 7': 1, '6 / 6': 2, '4 / 4': 1, '3 / 3': 1, '5 / 5': 1 })) {
      expect(screen.getAllByText(expected)).toHaveLength(count)
    }
    expect(screen.getAllByText('已保护')).toHaveLength(6)
    const financialRow = screen.getByText('财务与保险').closest<HTMLElement>('[role="row"]')
    expect(financialRow).not.toBeNull()
    expect(within(financialRow!).getByText('按具体策略')).toBeInTheDocument()
    expect(within(financialRow!).getByText('按具体策略执行')).toBeInTheDocument()
    expect(screen.queryByText('部分保护')).not.toBeInTheDocument()
    expect(screen.queryByText('目录待接入')).not.toBeInTheDocument()
  })

  it('证书与 OpenSSH 私钥是同一保护项的明确子策略，可一起保存', async () => {
    const user = userEvent.setup()
    const batch = vi.spyOn(securityPoliciesApi, 'batch').mockResolvedValue({ data: {} } as never)
    render(
      <SensitiveDataPolicy
        policies={[
          policy('private-key', ['ssh_private_key'], { name: '证书/私钥检测', action: 'block' }),
          policy('openssh-key', ['openssh_private_key'], { name: 'SSH 密钥检测', action: 'audit' }),
        ]}
        auditOnly={false}
        runtimeVerified
        runtimeStatus="verified"
        canManage
        onSaved={vi.fn()}
      />,
      { wrapper: queryWrapper() },
    )

    const credentialsRow = (await screen.findByText('账号与凭据')).closest<HTMLElement>('[role="row"]')
    expect(credentialsRow).not.toBeNull()
    expect(within(credentialsRow!).getByText('1 / 6')).toBeInTheDocument()
    await user.click(within(credentialsRow!).getByRole('button', { name: /配置$/ }))

    expect(screen.queryByText('存在重复识别配置，暂不能批量保存')).not.toBeInTheDocument()
    const privateKeyCard = (await screen.findByText('证书/私钥')).closest<HTMLElement>('div')
    expect(privateKeyCard).not.toBeNull()
    expect(within(privateKeyCard!).getByText('已接入')).toBeInTheDocument()

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '账号与凭据处置动作' }))
    const blockOption = await screen.findByText('阻止发送', { selector: '.ant-select-item-option-content' })
    fireEvent.click(blockOption.parentElement!)
    await user.click(screen.getByRole('button', { name: '保存并应用' }))
    await user.click(await screen.findByRole('button', { name: '确认保存并应用' }))

    await waitFor(() => expect(batch).toHaveBeenCalledWith([
      { id: 'private-key', action: 'block' },
      { id: 'openssh-key', action: 'block' },
    ]))
  })

  it('新规则包等待回执时不再把全部分类显示成未运行', async () => {
    const completePolicies = SENSITIVE_DATA_CATEGORIES.flatMap((category) => (
      category.items.map((item) => policy(
        `pending-${item.key}`,
        item.capabilityCategories,
        { name: item.policyNames?.[0] ?? item.label, action: category.defaultAction },
      ))
    ))

    render(
      <SensitiveDataPolicy
        policies={completePolicies}
        auditOnly={false}
        runtimeVerified={false}
        runtimeStatus="pending"
        canManage
        onSaved={vi.fn()}
      />,
      { wrapper: queryWrapper() },
    )

    expect(await screen.findByRole('heading', { name: '分类保护策略' })).toBeInTheDocument()
    expect(screen.getAllByText('新配置同步中')).toHaveLength(6)
    expect(screen.getAllByText('原配置继续运行')).toHaveLength(6)
    expect(screen.queryByText('运行待确认')).not.toBeInTheDocument()
  })

  it('敏感数据类别保存只更新该类别成员', async () => {
    const user = userEvent.setup()
    const batch = vi.spyOn(securityPoliciesApi, 'batch').mockResolvedValue({ data: {} } as never)
    render(
      <SensitiveDataPolicy
        policies={[
          policy('phone', ['phone_cn'], { name: '手机号策略' }),
          policy('id-card', ['id_card_cn'], { name: '身份证策略' }),
          policy('email', ['email'], { name: '邮箱策略' }),
          policy('bank', ['bank_card_cn'], { name: '银行卡策略', action: 'block' }),
        ]}
        auditOnly={false}
        runtimeVerified
        runtimeStatus="verified"
        canManage
        onSaved={vi.fn()}
      />,
      { wrapper: queryWrapper() },
    )

    const identityRow = (await screen.findByText('身份与证件')).closest<HTMLElement>('[role="row"]')
    expect(identityRow).not.toBeNull()
    await user.click(within(identityRow!).getByRole('button', { name: /配置$/ }))
    fireEvent.mouseDown(await screen.findByRole('combobox', { name: '身份与证件处置动作' }))
    const blockOption = await screen.findByText('阻止发送', { selector: '.ant-select-item-option-content' })
    fireEvent.click(blockOption.parentElement!)
    await user.click(screen.getByRole('button', { name: '保存并应用' }))
    expect(await screen.findByText('确认保存身份与证件配置')).toBeInTheDocument()
    expect(screen.getByText(/已接入保护项统一调整/)).toHaveTextContent('阻止发送')
    await user.click(await screen.findByRole('button', { name: '确认保存并应用' }))

    await waitFor(() => expect(batch).toHaveBeenCalledWith([
      { id: 'phone', action: 'block' },
      { id: 'id-card', action: 'block' },
    ]))
    expect(batch.mock.calls[0][0]).not.toContainEqual({ id: 'bank', action: 'block' })
  })

  it('文件管控固定 100 MB、100 个、1000 倍，例外删除成功刷新且失败保留原行', async () => {
    const user = userEvent.setup()
    // 2.9.22 起正文检测开关只有系统管理员能改。
    useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true })
    vi.spyOn(api, 'get').mockResolvedValue({
      data: { file_content_dlp_enabled: false },
    } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(contentSecurityApi, 'getFilePolicy').mockResolvedValue({
      data: {
        allowed_types: ['txt'],
        review_types: ['docx'],
        blocked_types: ['exe'],
        max_file_mb: 20,
        max_attachments: 10,
        max_zip_ratio: 100,
      },
    } as never)
    vi.spyOn(contentSecurityApi, 'updateFilePolicy').mockResolvedValue({ data: {} } as never)
    let exceptionItems = [{
      id: 'exception-internal-id',
      scope_type: 'tenant',
      decision: 'audit',
      reason: '业务样本观察',
      rule_ref: '内部规则引用',
      expires_at: null,
      enabled: true,
    }, {
      id: 'exception-second',
      scope_type: 'project',
      decision: 'allow',
      reason: '第二条例外',
      rule_ref: '另一条规则',
      expires_at: null,
      enabled: true,
    }]
    vi.spyOn(contentSecurityApi, 'listExceptions').mockImplementation(async () => ({
      data: { items: exceptionItems },
    } as never))
    const deleteException = vi.spyOn(contentSecurityApi, 'deleteException').mockImplementation(async (id) => {
      exceptionItems = exceptionItems.filter((item) => item.id !== id)
      return { data: {} } as never
    })

    render(<FilePolicySettings canManage />, { wrapper: queryWrapper() })

    expect(await screen.findByLabelText('文件正文敏感数据检测')).not.toBeChecked()
    expect(screen.getByLabelText('单个文件大小（MB）')).toHaveValue(20)
    expect(screen.getByLabelText('单次文件数量')).toHaveValue(10)
    expect(screen.getByLabelText('压缩比上限')).toHaveValue(100)
    await user.click(screen.getByLabelText('文件正文敏感数据检测'))
    await user.clear(screen.getByLabelText('单个文件大小（MB）'))
    await user.type(screen.getByLabelText('单个文件大小（MB）'), '100')
    await user.clear(screen.getByLabelText('单次文件数量'))
    await user.type(screen.getByLabelText('单次文件数量'), '100')
    await user.clear(screen.getByLabelText('压缩比上限'))
    await user.type(screen.getByLabelText('压缩比上限'), '1000')
    await user.click(screen.getByRole('button', { name: '保存网页 AI 附件准入' }))

    await waitFor(() => expect(contentSecurityApi.updateFilePolicy).toHaveBeenCalledWith(expect.objectContaining({
      max_file_mb: 100,
      max_attachments: 100,
      max_zip_ratio: 1000,
    })))
    expect(api.put).toHaveBeenCalledWith('/system/settings', { file_content_dlp_enabled: true })

    expect(screen.queryByText('exception-internal-id')).not.toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: '删除内容例外' })[0])
    expect(await screen.findByText('确认删除此内容例外？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(deleteException).toHaveBeenCalledWith('exception-internal-id'))

    deleteException.mockRejectedValueOnce(new Error('delete failed'))
    await user.click(screen.getByRole('button', { name: '删除内容例外' }))
    await user.click(await screen.findByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(screen.getByText('第二条例外')).toBeInTheDocument())
  })

  it('每种文件类型只有一个发送结果，保存时转换为后端三组清单', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'get').mockResolvedValue({ data: { file_content_dlp_enabled: false } } as never)
    vi.spyOn(contentSecurityApi, 'getFilePolicy').mockResolvedValue({
      data: {
        allowed_types: ['txt'],
        review_types: ['docx'],
        blocked_types: ['exe'],
        max_file_mb: 20,
        max_attachments: 10,
        max_zip_ratio: 100,
      },
    } as never)
    vi.spyOn(contentSecurityApi, 'listExceptions').mockResolvedValue({ data: { items: [] } } as never)
    const update = vi.spyOn(contentSecurityApi, 'updateFilePolicy').mockResolvedValue({ data: {} } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)

    render(<FilePolicySettings canManage />, { wrapper: queryWrapper() })

    expect(await screen.findByRole('heading', { name: '网页 AI 附件准入' })).toBeInTheDocument()
    expect(screen.getByText(/真实附件、文件引用或 multipart/)).toBeInTheDocument()
    expect(screen.getByText(/编码智能体读取本地文件后形成的文本或工具结果不适用/)).toBeInTheDocument()
    expect(screen.queryByText('仅约束经过网关上传的原始文件')).not.toBeInTheDocument()
    expect(screen.queryByRole('option', { name: '发送前确认' })).not.toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByLabelText('TXT发送方式')).toHaveValue('allowed')
      expect(screen.getByLabelText('DOCX发送方式')).toHaveValue('allowed')
      expect(screen.getByLabelText('DOCX发送方式')).toBeEnabled()
      // 2.9.22：未知类型、可执行、脚本不再锁定为禁止，改到“高风险文件”行单独配置，缺省告警放行。
      expect(screen.getByLabelText('未知类型处理方式')).toHaveValue('alert_allow')
      expect(screen.getByLabelText('未知类型处理方式')).toBeEnabled()
      expect(screen.getByLabelText('可执行文件 / 动态库处理方式')).toHaveValue('alert_allow')
      expect(screen.getByLabelText('可执行文件 / 动态库处理方式')).toBeEnabled()
    })

    expect(screen.getByLabelText('DOCX发送方式')).toHaveValue('allowed')
    await user.selectOptions(screen.getByLabelText('DOCX发送方式'), 'blocked')
    await waitFor(() => expect(screen.getByLabelText('DOCX发送方式')).toHaveValue('blocked'))
    await user.click(screen.getByRole('button', { name: '保存网页 AI 附件准入' }))

    // 2.9.22：exe 等可执行别名不再进 blocked_types，改由 executable_action 表达。
    await waitFor(() => expect(update).toHaveBeenCalledWith(expect.objectContaining({
      allowed_types: ['txt'],
      review_types: [],
      blocked_types: ['docx'],
      executable_action: 'alert_allow',
      unknown_action: 'alert_allow',
      script_action: 'alert_allow',
    })))
  })
})
