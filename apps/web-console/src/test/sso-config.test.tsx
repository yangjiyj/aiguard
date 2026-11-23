import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { Modal } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import SsoConfig from '../pages/SsoConfig'
import * as api from '../services/api'
import { identityDepartmentMappingsApi } from '../services/identityDepartmentMappings'

// antd 的 Modal.confirm 是命令式 portal，RTL cleanup 不会自动移除它，避免跨用例污染。
afterEach(() => {
  Modal.destroyAll()
})

// SsoConfig 页规格测试（TDD）

const EMPTY_STATUS = {
  has_active: false,
  has_draft: false,
  emergency_admin_available: true,
  callback_url: 'https://sso.example.com/sso/realms/jjdguard/broker/enterprise/endpoint',
  publish_status: 'not_published',
  applied_version: 0,
  drift: false,
  runtime_available: true,
}

describe('SsoConfig 页面', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    vi.restoreAllMocks()
    vi.spyOn(identityDepartmentMappingsApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    // 默认全部返回空，测试内可覆盖
    vi.spyOn(api.identityApi, 'getSources').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'getStatus').mockResolvedValue({ data: EMPTY_STATUS } as any)
    vi.spyOn(api.identityApi, 'getDeptMappings').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'saveDraft').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'testConnection').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'activate').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'disable').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'reconcile').mockResolvedValue({ data: {} } as any)
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <SsoConfig />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  it('renders configuration form with title', async () => {
    renderPage()
    expect(await screen.findByText('企业 SSO 配置')).toBeInTheDocument()
    expect(screen.getByText('显示名称')).toBeInTheDocument()
    expect(screen.getByText('Issuer 地址')).toBeInTheDocument()
    expect(screen.getByText('Client ID')).toBeInTheDocument()
  })

  it('displays callback url', async () => {
    renderPage()
    expect(await screen.findByText(/回调地址/)).toBeInTheDocument()
    expect(screen.getByText('https://sso.example.com/sso/realms/jjdguard/broker/enterprise/endpoint')).toBeInTheDocument()
  })

  it('fills form after async draft load', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{
        id: 'is_draft', display_name: '异步企业 IdP', status: 'draft', protocol: 'oidc',
        issuer_url: 'https://async-idp.example.com', client_id: 'async-client',
        client_secret_set: true, scopes: 'openid profile email', callback_url: '/admin/v1/identity/oidc/callback',
      }] },
    } as any)

    renderPage()
    expect(await screen.findByDisplayValue('异步企业 IdP')).toBeInTheDocument()
    expect(screen.getByDisplayValue('https://async-idp.example.com')).toBeInTheDocument()
    expect(screen.getByDisplayValue('async-client')).toBeInTheDocument()
  })

  it('save draft calls api', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    fireEvent.change(screen.getByLabelText('显示名称'), { target: { value: '企业 IdP' } })
    fireEvent.change(screen.getByLabelText('Issuer 地址'), { target: { value: 'https://idp.example.com' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'test-client' } })
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    await waitFor(() => expect(api.identityApi.saveDraft).toHaveBeenCalled())
  })

  // W9 9.8：Scopes 输入已存在，但没有任何校验；缺 openid 要到发布时才笼统失败
  it('scopes 缺少 openid 时阻止保存并提示，合法值原样提交', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    fireEvent.change(screen.getByLabelText('显示名称'), { target: { value: 'Enterprise IdP' } })
    fireEvent.change(screen.getByLabelText('Issuer 地址'), { target: { value: 'https://idp.example.com' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'test-client' } })
    fireEvent.change(screen.getByLabelText('Scopes'), { target: { value: 'profile email' } })
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    expect(await screen.findByText('Scopes 必须包含 openid')).toBeInTheDocument()
    expect(api.identityApi.saveDraft).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText('Scopes'), { target: { value: 'openid "x"' } })
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    expect(await screen.findByText('Scopes 只允许以空格分隔的标准 scope 名称')).toBeInTheDocument()
    expect(api.identityApi.saveDraft).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText('Scopes'), { target: { value: 'openid profile email groups' } })
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    await waitFor(() => expect(api.identityApi.saveDraft).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.identityApi.saveDraft).mock.calls[0][0]).toMatchObject({ scopes: 'openid profile email groups' })
  })

  it('scopes 输入框展示默认值与 openid 必填说明', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    expect(screen.getByText(/必须包含 openid/)).toBeInTheDocument()
    expect(screen.getByLabelText('Scopes')).toHaveAttribute('placeholder', 'openid profile email')
  })

  it('test connection button exists', async () => {
    renderPage()
    expect(await screen.findByRole('button', { name: /测试连接/ })).toBeInTheDocument()
  })

  it('activate requires tested status', async () => {
    renderPage()
    const btn = await screen.findByRole('button', { name: /启用/ })
    expect(btn).toBeDisabled()
  })

  it('disable shows confirm modal', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{ id: 'is_a', display_name: '企业 IdP', status: 'active', protocol: 'oidc', issuer_url: 'https://idp.example.com', client_id: 'c', client_secret_set: true, callback_url: '/admin/v1/identity/oidc/callback' }] },
    } as any)

    renderPage()
    // 等待数据加载（display_name 出现说明 sources 已渲染）
    await screen.findByText('企业 IdP')
    const _btns = screen.getAllByRole('button')
    const disableBtn = _btns.find((b: any) => b.textContent && b.textContent.includes('停'))
    if (!disableBtn) throw new Error('no disable button; buttons=' + JSON.stringify(_btns.map((b:any)=>b.textContent)))
    fireEvent.click(disableBtn)
    // Modal.confirm 弹出后，对话框标题或内容出现
    expect(await screen.findByText(/停用后用户将无法通过该身份源登录/)).toBeInTheDocument()
  })

  it('no secret in dom', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{ id: 'is_1', display_name: 'Leak Test', protocol: 'oidc', issuer_url: 'https://idp.example.com', client_id: 'c', client_secret_set: true, status: 'draft', callback_url: '/admin/v1/identity/oidc/callback' }] },
    } as any)

    const { container } = renderPage()
    await screen.findByText('Leak Test')
    expect(container.textContent).not.toContain('topsecret-abc-xyz')
    expect(container.textContent).not.toContain('enc:v1:')
  })

  it('dept mapping table renders', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{ id: 'is_mapping', display_name: '映射身份源', status: 'active', protocol: 'oidc' }] },
    } as any)
    vi.mocked(identityDepartmentMappingsApi.list).mockResolvedValue({
      data: { data: [{ id: 'dm_1', source_type: 'oidc', source_id: 'is_mapping', external_group: 'rd', match_type: 'department', department_id: 't1', department_name: '研发部', priority: 100, enabled: true }] },
    } as any)

    renderPage()
    expect(await screen.findByText('部门属性映射')).toBeInTheDocument()
    expect(await screen.findByText('rd')).toBeInTheDocument()
  })

  it('no keycloak terminology', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    const body = document.body.textContent || ''
    expect(body).not.toMatch(/Keycloak/i)
    expect(body).not.toMatch(/master realm/i)
    expect(body).not.toMatch(/client.*mapper/i)
  })
})

describe('SsoConfig 运行态发布体验', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    vi.restoreAllMocks()
    vi.spyOn(identityDepartmentMappingsApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'getSources').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'getStatus').mockResolvedValue({ data: EMPTY_STATUS } as any)
    vi.spyOn(api.identityApi, 'getDeptMappings').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'saveDraft').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'testConnection').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'activate').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'disable').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'reconcile').mockResolvedValue({ data: {} } as any)
  })

  const renderPage = () => render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <SsoConfig />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('uses only the server callback and hides internal implementation terms', async () => {
    renderPage()
    expect(await screen.findByText(EMPTY_STATUS.callback_url)).toBeInTheDocument()
    const body = document.body.textContent || ''
    expect(body).not.toContain('/admin/v1/identity/oidc/callback')
    expect(body).not.toMatch(/Keycloak|master realm|client mapper|chat-idp|admin\/realms/i)
  })

  it('explains when the public callback has not been configured', async () => {
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({
      data: { ...EMPTY_STATUS, callback_url: '', runtime_available: false },
    } as any)
    renderPage()
    expect(await screen.findByText('部署尚未配置公开 SSO 地址')).toBeInTheDocument()
  })
  it('shows the generated HTTP callback and its private deployment warning', async () => {
    const generatedCallback = 'http://10.0.0.5:8180/sso/realms/jjdguard/broker/enterprise/endpoint'
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({
      data: { ...EMPTY_STATUS, callback_url: generatedCallback },
    } as any)
    renderPage()
    expect(await screen.findByText(generatedCallback)).toBeInTheDocument()
    expect(screen.getByText('当前为私有部署/测试回调地址')).toBeInTheDocument()
    expect(screen.getByText(/企业 IdP 可能要求 HTTPS 或稳定域名/)).toBeInTheDocument()
  })

  it('shows drift and requires confirmation before reconcile', async () => {
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({
      data: {
        ...EMPTY_STATUS,
        has_active: true,
        active_display_name: '企业 IdP',
        publish_status: 'drifted',
        drift: true,
        runtime_message: '运行配置与当前设置不一致，可按当前配置修复',
      },
    } as any)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '按当前配置修复' }))
    fireEvent.click(await screen.findByRole('button', { name: '确认修复' }))
    await waitFor(() => expect(api.identityApi.reconcile).toHaveBeenCalledTimes(1))
  })

  it('never displays raw internal mutation errors', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{
        id: 'tested', display_name: '企业 IdP', status: 'tested', protocol: 'oidc',
        issuer_url: 'https://idp.example.com', client_id: 'client', client_secret_set: true,
      }] },
    } as any)
    vi.mocked(api.identityApi.activate).mockRejectedValue({
      response: { data: { error: { code: 'identity_publish_failed', message: 'Keycloak admin/realms secret leaked' } } },
    })
    renderPage()
    const activateButton = await screen.findByRole('button', { name: '确认启用' })
    await waitFor(() => expect(activateButton).not.toBeDisabled())
    fireEvent.click(activateButton)
    await waitFor(() => expect(api.identityApi.activate).toHaveBeenCalled())
    expect(document.body.textContent).not.toMatch(/Keycloak|admin\/realms|secret leaked/i)
    expect(await screen.findByText('身份配置发布失败，原有登录配置未切换')).toBeInTheDocument()
  })
})
  it('shows a failed OIDC test result returned with HTTP 200', async () => {
    vi.spyOn(api.identityApi, 'getSources').mockResolvedValue({
      data: { data: [{
        id: 'is_failed_test', display_name: '企业 IdP', protocol: 'oidc',
        issuer_url: 'http://idp.example.test', client_id: 'client', client_secret_set: true,
        status: 'draft', callback_url: '/callback',
      }] },
    } as any)
    vi.spyOn(api.identityApi, 'testConnection').mockResolvedValue({
      data: {
        success: false,
        error: '身份源地址与发现文档不一致',
        stages: [{ name: '校验签发方一致性', status: 'failed', message: '签发方地址与发现文档不一致' }],
      },
    } as any)
    vi.spyOn(api.identityApi, 'getStatus').mockResolvedValue({ data: EMPTY_STATUS } as any)
    vi.spyOn(api.identityApi, 'getDeptMappings').mockResolvedValue({ data: { data: [] } } as any)

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const renderPage = () => render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <SsoConfig />
        </QueryClientProvider>
      </MemoryRouter>,
    )

    renderPage()
    await screen.findByDisplayValue('企业 IdP')
    fireEvent.click(await screen.findByRole('button', { name: /测试连接/ }))

    expect(await screen.findByText('身份源地址与发现文档不一致')).toBeInTheDocument()
  })

describe('SsoConfig 验签方式 / 用户名取值 / 首登资料页', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    vi.restoreAllMocks()
    vi.spyOn(identityDepartmentMappingsApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'getSources').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'getStatus').mockResolvedValue({ data: EMPTY_STATUS } as any)
    vi.spyOn(api.identityApi, 'getDeptMappings').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'saveDraft').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'testConnection').mockResolvedValue({ data: {} } as any)
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <SsoConfig />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  const fillRequired = () => {
    fireEvent.change(screen.getByLabelText('显示名称'), { target: { value: '企业 IdP' } })
    fireEvent.change(screen.getByLabelText('Issuer 地址'), { target: { value: 'https://idp.example.com' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'test-client' } })
  }

  const choose = async (name: string, optionText: string) => {
    fireEvent.mouseDown(screen.getByRole('combobox', { name }))
    const options = await screen.findAllByText(optionText)
    fireEvent.click(options[options.length - 1])
  }

  it('三项新控件默认值：JWKS 验签 / preferred_username / 不跳过资料页，且不显示风险提示', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    expect(screen.getByText('id_token 验签方式')).toBeInTheDocument()
    expect(screen.getByText('按 IdP 公钥验签（JWKS，推荐）')).toBeInTheDocument()
    expect(screen.getByText('用户名取值')).toBeInTheDocument()
    expect(screen.getByText('preferred_username（默认）')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '首次登录不弹资料页' })).not.toBeChecked()
    expect(screen.queryByText(/被伪造 id_token/)).not.toBeInTheDocument()
  })

  it('默认保存：提交 jwks / preferred_username / false（与旧行为一致）', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    fillRequired()
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    await waitFor(() => expect(api.identityApi.saveDraft).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.identityApi.saveDraft).mock.calls[0][0]).toMatchObject({
      signature_mode: 'jwks', username_claim: 'preferred_username', skip_profile_review: false,
    })
  })

  it('选择「不校验签名」后显示醒目的风险提示，并随草稿一起提交', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    fillRequired()
    await choose('id_token 验签方式', '不校验签名')
    const alert = await screen.findByText(/被伪造 id_token/)
    expect(alert.textContent).toMatch(/HTTPS 直连令牌端点/)
    expect(alert.textContent).toMatch(/默认关闭/)
    await choose('用户名取值', '邮箱（email）')
    fireEvent.click(screen.getByRole('switch', { name: '首次登录不弹资料页' }))
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    await waitFor(() => expect(api.identityApi.saveDraft).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.identityApi.saveDraft).mock.calls[0][0]).toMatchObject({
      signature_mode: 'none', username_claim: 'email', skip_profile_review: true,
    })
  })

  it('已保存草稿的三项选项回填；自定义用户名取值原样保留', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{
        id: 'is_opts', display_name: '客户A IdP', status: 'draft', protocol: 'oidc',
        issuer_url: 'https://idp.example.com', client_id: 'c', client_secret_set: true, scopes: 'openid',
        username_claim: 'login_name', signature_mode: 'none', skip_profile_review: true, callback_url: '/cb',
      }] },
    } as any)
    renderPage()
    await screen.findByDisplayValue('客户A IdP')
    expect(await screen.findByText(/被伪造 id_token/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '首次登录不弹资料页' })).toBeChecked()
    expect(screen.getByText('login_name（已保存的自定义取值）')).toBeInTheDocument()
  })

  it('测试连接返回发现性提示时以非阻断形式展示，且不改变测试结论', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{
        id: 'is_hint', display_name: '企业 IdP', status: 'draft', protocol: 'oidc',
        issuer_url: 'https://idp.example.com', client_id: 'c', client_secret_set: true, callback_url: '/cb',
      }] },
    } as any)
    vi.mocked(api.identityApi.testConnection).mockResolvedValue({
      data: {
        success: true, error: '',
        hints: [
          '该 IdP 使用对称签名（HS256 等），无法按公钥验签；如确认可信，可将「id_token 验签方式」选为「不校验签名」。',
          '该 IdP 未声明支持 preferred_username，建议将「用户名取值」改为邮箱。',
        ],
      },
    } as any)
    renderPage()
    await screen.findByDisplayValue('企业 IdP')
    fireEvent.click(await screen.findByRole('button', { name: /测试连接/ }))
    expect(await screen.findByText('身份源连接测试通过')).toBeInTheDocument()
    expect(await screen.findByText('配置建议（不影响测试结果）')).toBeInTheDocument()
    expect(screen.getByText(/使用对称签名/)).toBeInTheDocument()
    expect(screen.getByText(/建议将「用户名取值」改为邮箱/)).toBeInTheDocument()
  })

  it('没有提示时不展示建议区', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{
        id: 'is_nohint', display_name: '企业 IdP', status: 'draft', protocol: 'oidc',
        issuer_url: 'https://idp.example.com', client_id: 'c', client_secret_set: true, callback_url: '/cb',
      }] },
    } as any)
    vi.mocked(api.identityApi.testConnection).mockResolvedValue({ data: { success: true } } as any)
    renderPage()
    await screen.findByDisplayValue('企业 IdP')
    fireEvent.click(await screen.findByRole('button', { name: /测试连接/ }))
    expect(await screen.findByText('身份源连接测试通过')).toBeInTheDocument()
    expect(screen.queryByText('配置建议（不影响测试结果）')).not.toBeInTheDocument()
  })

  it('新增文案不出现内部实现术语', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    await choose('id_token 验签方式', '不校验签名')
    const body = document.body.textContent || ''
    expect(body).not.toMatch(/Keycloak/i)
    expect(body).not.toMatch(/validateSignature|useJwksUrl|update\.profile/i)
  })
})

describe('SsoConfig 采纳现场运行态 / 权限提示 / RS256 建议', () => {
  let queryClient: QueryClient
  const ACTIVE_SOURCE = {
    id: 'ids_active_1', display_name: '客户A IdP', status: 'active', protocol: 'oidc',
    issuer_url: 'https://idp.example.com', client_id: 'c', client_secret_set: true, scopes: 'openid',
    signature_mode: 'jwks', skip_profile_review: false, callback_url: '/cb',
  }
  const DRIFTED_STATUS = {
    ...EMPTY_STATUS, has_active: true, active_display_name: '客户A IdP',
    publish_status: 'drifted', drift: true, runtime_message: '运行配置与当前设置不一致，可按当前配置修复',
  }

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    vi.restoreAllMocks()
    vi.spyOn(identityDepartmentMappingsApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'getSources').mockResolvedValue({ data: { data: [ACTIVE_SOURCE] } } as any)
    vi.spyOn(api.identityApi, 'getStatus').mockResolvedValue({ data: DRIFTED_STATUS } as any)
    vi.spyOn(api.identityApi, 'getDeptMappings').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'saveDraft').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'testConnection').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'activate').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'reconcile').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'adoptRuntime').mockResolvedValue({
      data: {
        success: true,
        adopted: { signature_mode: 'none', username_claim: 'email', skip_profile_review: true },
        unresolved: [], same_alias_sources: [{ id: 'ids_old', status: 'disabled', version: 5, publish_status: 'disabled' }],
        publish_status: 'drifted', drift: true,
      },
    } as any)
  })

  afterEach(() => {
    Modal.destroyAll()
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <SsoConfig />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  // antd 弹窗关闭有动画，前一个用例的弹窗可能还留在 DOM 里：一律点最后（最新）出现的按钮。
  const clickLast = async (name: string) => {
    const els = await screen.findAllByRole('button', { name })
    fireEvent.click(els[els.length - 1])
  }
  const lastText = async (re: RegExp) => {
    const els = await screen.findAllByText(re)
    return els[els.length - 1]
  }

  it('仅在 drifted 且存在启用中身份源时显示「采纳现场运行态」', async () => {
    renderPage()
    expect(await screen.findByRole('button', { name: '采纳现场运行态' })).toBeInTheDocument()
  })

  it('adopt_recommended 时采纳按钮在修复按钮之前且为主按钮，修复确认框给出覆盖警告', async () => {
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({
      data: { ...DRIFTED_STATUS, adopt_recommended: true, drift_fields: ['signature_mode', 'username_claim'] },
    } as any)
    renderPage()
    const adopt = await screen.findByRole('button', { name: '采纳现场运行态' })
    const repair = await screen.findByRole('button', { name: '按当前配置修复' })
    expect(adopt.compareDocumentPosition(repair) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(adopt.className).toMatch(/ant-btn-primary/)
    fireEvent.click(repair)
    expect(await lastText(/将用平台保存的配置覆盖身份服务中的当前设置（id_token 验签方式、用户名取值），可能导致单点登录失败。如这些差异是现场有意调整，请先采纳现场运行态。/)).toBeInTheDocument()
    const ok = (await screen.findAllByRole('button', { name: '确认修复' })).pop()!
    expect(ok.className).toMatch(/ant-btn-dangerous|ant-btn-color-dangerous/)
  })

  it('adopt_recommended 为假时保持原按钮顺序与原确认文案', async () => {
    renderPage()
    const repair = await screen.findByRole('button', { name: '按当前配置修复' })
    const adopt = await screen.findByRole('button', { name: '采纳现场运行态' })
    expect(repair.compareDocumentPosition(adopt) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    fireEvent.click(repair)
    expect(await lastText(/将按 JJDGuard 当前已保存配置覆盖运行中的身份设置/)).toBeInTheDocument()
  })

  it('配置正常（非 drifted）时不显示采纳按钮', async () => {
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({
      data: { ...DRIFTED_STATUS, publish_status: 'active', drift: false, runtime_message: '' },
    } as any)
    renderPage()
    expect(await screen.findByText('已启用', { selector: '.ant-tag' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '采纳现场运行态' })).not.toBeInTheDocument()
  })

  it('采纳需二次确认，文案说明只读不改身份服务；确认后以身份源 ID 调用并展示结果与后续步骤', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '采纳现场运行态' }))
    expect(await lastText(/只读取运行配置并回写到产品配置，不修改身份服务/)).toBeInTheDocument()
    expect((await lastText(/再点「按当前配置修复」/)).textContent).toMatch(/再点「按当前配置修复」/)
    expect(api.identityApi.adoptRuntime).not.toHaveBeenCalled()
    await clickLast('确认采纳')
    await waitFor(() => expect(api.identityApi.adoptRuntime).toHaveBeenCalledWith('ids_active_1'))
    expect(await screen.findByText(/已采纳现场运行配置（尚未生效/)).toBeInTheDocument()
    expect(screen.getByText(/用户名取值：email/)).toBeInTheDocument()
    expect(screen.getByText(/不校验签名/, { selector: 'li' })).toBeInTheDocument()
    expect(screen.getByText(/还有 1 条其他身份源记录，未被改动/)).toBeInTheDocument()
    expect(api.identityApi.reconcile).not.toHaveBeenCalled()
  })

  it('取消确认不调用采纳接口', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '采纳现场运行态' }))
    await clickLast('取 消')
    expect(api.identityApi.adoptRuntime).not.toHaveBeenCalled()
  })

  it('409 冲突给出中文提示，且不展示内部术语', async () => {
    vi.mocked(api.identityApi.adoptRuntime).mockRejectedValue({
      response: { status: 409, data: { error: { code: 'adopt_target_not_active', message: 'Keycloak conflict' } } },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '采纳现场运行态' }))
    await clickLast('确认采纳')
    expect(await screen.findByText('同一登录入口下已有启用中的身份源，运行配置属于启用中的那一条，请改为采纳它')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/Keycloak/i)
  })

  it('确认弹窗说明「首次登录不弹资料页」是整个登录入口级设置', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '采纳现场运行态' }))
    const text = await lastText(/只读取运行配置并回写到产品配置/)
    expect(text.textContent).toMatch(/「首次登录不弹资料页」是整个登录入口级的设置/)
  })

  it('采纳期间配置被他人修改（并发冲突）给出刷新提示', async () => {
    vi.mocked(api.identityApi.adoptRuntime).mockRejectedValue({
      response: { status: 409, data: { error: { code: 'identity_publish_conflict', message: 'x' } } },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '采纳现场运行态' }))
    await clickLast('确认采纳')
    expect(await screen.findByText('配置已被他人修改，请刷新后重试')).toBeInTheDocument()
  })

  it('编辑中的身份源不可采纳：给出明确中文提示', async () => {
    vi.mocked(api.identityApi.adoptRuntime).mockRejectedValue({
      response: { status: 409, data: { error: { code: 'adopt_target_not_adoptable', message: 'x' } } },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '采纳现场运行态' }))
    await clickLast('确认采纳')
    expect(await screen.findByText('仅启用中或已停用的身份源可采纳（当前处于编辑中，请先发布或放弃草稿）')).toBeInTheDocument()
  })

  it('保存草稿时「不校验签名」+ 非 https 被后端拦截，界面展示中文原因', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({ data: { data: [] } } as any)
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({ data: EMPTY_STATUS } as any)
    vi.mocked(api.identityApi.saveDraft).mockRejectedValue({
      response: { status: 400, data: { error: { code: 'signature_none_requires_https', message: 'x' } } },
    })
    renderPage()
    await screen.findByText('企业 SSO 配置')
    fireEvent.change(screen.getByLabelText('显示名称'), { target: { value: '企业 IdP' } })
    fireEvent.change(screen.getByLabelText('Issuer 地址'), { target: { value: 'http://10.0.0.5/oidc' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'c' } })
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    expect(await screen.findByText('选择「不校验签名」时，token 端点必须是 https')).toBeInTheDocument()
  })

  it('其他失败给出中文兜底提示', async () => {
    vi.mocked(api.identityApi.adoptRuntime).mockRejectedValue({ response: { status: 500, data: {} } })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '采纳现场运行态' }))
    await clickLast('确认采纳')
    expect(await screen.findByText('采纳失败，请稍后重试')).toBeInTheDocument()
  })

  it('启用 skip 因缺少 manage-realm 被拒绝时给出清晰中文提示，而非笼统发布失败', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{ ...ACTIVE_SOURCE, id: 'ids_t', status: 'tested', skip_profile_review: true }] },
    } as any)
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({ data: EMPTY_STATUS } as any)
    vi.mocked(api.identityApi.activate).mockRejectedValue({
      response: { status: 502, data: { error: { code: 'identity_manage_realm_required', message: 'x' } } },
    })
    renderPage()
    const activate = await screen.findByRole('button', { name: '确认启用' })
    await waitFor(() => expect(activate).not.toBeDisabled())
    fireEvent.click(activate)
    const text = await screen.findByText(/需要给身份运行服务账号授予 manage-realm 权限/)
    expect(text.textContent).toMatch(/详见升级文档/)
  })

  it('选了「不校验签名」且 IdP 支持 RS256 时，风险提示里同样出现 RS256 建议', async () => {
    const hint = '该 IdP 同时支持 RS256，建议在 IdP 应用里把 id_token 签名改为 RS256 后使用公钥验签，「不校验签名」仅作兜底。'
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{
        ...ACTIVE_SOURCE, id: 'ids_d', status: 'draft', signature_mode: 'none',
        last_test_result: { success: true, stages: [], hints: [hint] },
      }] },
    } as any)
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({ data: EMPTY_STATUS } as any)
    renderPage()
    await screen.findByDisplayValue('客户A IdP')
    const risk = await screen.findByText(/被伪造 id_token/)
    expect(risk.closest('.ant-alert')?.textContent).toContain('同时支持 RS256')
    expect(risk.closest('.ant-alert')?.textContent).toContain('仅作兜底')
  })

  it('选 none 但 IdP 不支持 RS256（无该提示）时风险提示里没有 RS256 建议', async () => {
    vi.mocked(api.identityApi.getSources).mockResolvedValue({
      data: { data: [{ ...ACTIVE_SOURCE, id: 'ids_d2', status: 'draft', signature_mode: 'none' }] },
    } as any)
    vi.mocked(api.identityApi.getStatus).mockResolvedValue({ data: EMPTY_STATUS } as any)
    renderPage()
    await screen.findByDisplayValue('客户A IdP')
    const risk = await screen.findByText(/被伪造 id_token/)
    expect(risk.closest('.ant-alert')?.textContent).not.toContain('RS256')
  })
})
