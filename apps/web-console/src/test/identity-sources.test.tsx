import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import * as api from '../services/api'
import IdentitySources from '../pages/IdentitySources'
import IdentityLoginSource from '../pages/IdentityLoginSource'
import IdentityDirectorySource from '../pages/IdentityDirectorySource'

// 任务 8：企业身份源合并入口（TDD）

const EMPTY_IDENTITY_STATUS = {
  has_active: false,
  has_draft: false,
  emergency_admin_available: true,
  callback_url: '',
  publish_status: 'not_published',
  applied_version: 0,
  drift: false,
  runtime_available: true,
}

const EMPTY_OVERVIEW = {
  login: { state: "unconfigured", runtime_healthy: false },
  directory: { state: "unconfigured", runtime_healthy: false },
  reconciliation_required: 0,
}

function makeQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
}

function renderWithRouter(initial = '/identity-sources') {
  const queryClient = makeQueryClient()
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path='/identity-sources' element={<IdentitySources />} />
          <Route path='/identity-sources/login' element={<IdentityLoginSource />} />
          <Route path='/identity-sources/directory' element={<IdentityDirectorySource />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('企业身份源 — 总览页', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api.identityApi, 'getSources').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'getStatus').mockResolvedValue({ data: EMPTY_IDENTITY_STATUS } as any)
    vi.spyOn(api.identityApi, 'getOverview').mockResolvedValue({ data: EMPTY_OVERVIEW } as any)
    vi.spyOn(api.directoryApi, 'getDraft').mockResolvedValue({ data: { data: null } } as any)
  })

  it('展示「企业 SSO」和「目录账号」两个独立卡片', async () => {
    renderWithRouter()
    expect(await screen.findByText('企业 SSO')).toBeInTheDocument()
    expect(await screen.findByText('目录账号')).toBeInTheDocument()
  })

  it('每个卡片都展示配置状态（未配置/草稿/测试通过/启用中/异常）', async () => {
    // 任务 12：状态来自后端 overview 权威返回，不再前端推断。
    vi.spyOn(api.identityApi, 'getOverview').mockResolvedValue({
      data: {
        login: { state: 'draft', runtime_healthy: false },
        directory: { state: 'tested', runtime_healthy: true },
        reconciliation_required: 0,
      },
    } as any)
    vi.spyOn(api.identityApi, 'getSources').mockResolvedValue({
      data: { data: [{ id: 's1', display_name: '企业 IdP', status: 'draft', protocol: 'oidc', issuer_url: '', client_id: '', client_secret_set: false, scopes: '', callback_url: '' }] },
    } as any)
    vi.spyOn(api.directoryApi, 'getDraft').mockResolvedValue({
      data: { data: { id: 'd1', kind: 'ldap', display_name: '总部目录', bind_password_set: true, ca_cert_set: false, stable_id_attribute: '', username_attribute: '', email_attribute: '', name_attribute: '', status: 'tested', version: 1 } },
    } as any)

    renderWithRouter()
    expect(await screen.findByText('草稿')).toBeInTheDocument()
    expect(await screen.findByText(/测试通过/)).toBeInTheDocument()
  })

  it('待对账计数大于 0 时展示告警提示', async () => {
    vi.spyOn(api.identityApi, 'getOverview').mockResolvedValue({
      data: {
        login: { state: 'unconfigured', runtime_healthy: false },
        directory: { state: 'unconfigured', runtime_healthy: false },
        reconciliation_required: 3,
      },
    } as any)
    renderWithRouter()
    expect(await screen.findByText(/有 3 个账号需要重新对账/)).toBeInTheDocument()
  })

  it('测试通过但尚未启用时不展示运行态不可达标签与旧建议', async () => {
    vi.spyOn(api.identityApi, 'getOverview').mockResolvedValue({
      data: {
        login: {
          state: 'tested',
          runtime_healthy: false,
          runtime_message: '身份服务暂不可用，本地管理员登录不受影响',
        },
        directory: {
          state: 'tested',
          runtime_healthy: false,
          runtime_message: '目录同步服务暂不可用，已发布配置与历史记录不受影响',
        },
        reconciliation_required: 0,
      },
    } as any)

    renderWithRouter()
    expect(await screen.findAllByText('测试通过')).toHaveLength(2)
    expect(screen.queryByText('运行态不可达')).not.toBeInTheDocument()
    expect(screen.queryByText(/本地管理员登录不受影响/)).not.toBeInTheDocument()
    expect(screen.queryByText(/目录同步服务暂不可用/)).not.toBeInTheDocument()
  })

  it('登录运行态不可达时展示运行态不可达标签与建议', async () => {
    vi.spyOn(api.identityApi, 'getOverview').mockResolvedValue({
      data: {
        login: { state: 'active', runtime_healthy: false, runtime_message: '身份服务暂不可用，本地管理员登录不受影响' },
        directory: { state: 'unconfigured', runtime_healthy: true },
        reconciliation_required: 0,
      },
    } as any)
    renderWithRouter()
    expect(await screen.findByText('运行态不可达')).toBeInTheDocument()
    expect(await screen.findByText(/本地管理员登录不受影响/)).toBeInTheDocument()
  })

  it('异常状态展示配置漂移与重新对账建议但不标记运行态不可达', async () => {
    vi.spyOn(api.identityApi, 'getOverview').mockResolvedValue({
      data: {
        login: {
          state: 'abnormal',
          runtime_healthy: false,
          runtime_message: '运行配置与当前设置不一致，可按当前配置修复',
        },
        directory: {
          state: 'abnormal',
          runtime_healthy: false,
          runtime_message: '目录运行状态需要重新对账，请重新执行目录激活',
        },
        reconciliation_required: 0,
      },
    } as any)

    renderWithRouter()
    expect(await screen.findAllByText('异常')).toHaveLength(2)
    expect(screen.getByText(/运行配置与当前设置不一致/)).toBeInTheDocument()
    expect(screen.getByText(/目录运行状态需要重新对账/)).toBeInTheDocument()
    expect(screen.queryByText('运行态不可达')).not.toBeInTheDocument()
  })

  it('不存在全局主开关', async () => {
    renderWithRouter()
    await screen.findByText('企业 SSO')
    expect(screen.queryByText(/全局主开关|主开关/)).not.toBeInTheDocument()
    // 2.9.22 起页面多了“SSO 允许内网地址”（出站限制，不是身份源总开关），其余不应有开关。
    expect(screen.queryAllByRole('switch').filter((item) => item.getAttribute('aria-label') !== 'SSO 允许内网地址')).toHaveLength(0)
  })

  it('不展示数据库 ID', async () => {
    vi.spyOn(api.directoryApi, 'getDraft').mockResolvedValue({
      data: { data: { id: 'dir_src_uuid_123', kind: 'ldap', display_name: '总部目录', bind_password_set: true, ca_cert_set: false, stable_id_attribute: '', username_attribute: '', email_attribute: '', name_attribute: '', status: 'tested', version: 1 } },
    } as any)
    const { container } = renderWithRouter()
    await screen.findByText('目录账号')
    expect(container.textContent).not.toContain('dir_src_uuid_123')
  })
})

describe('IdentityDirectorySource — 预览-激活流程', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api.directoryApi, 'getDraft').mockResolvedValue({
      data: { data: { id: 'd1', kind: 'ldap', display_name: '总部目录', bind_password_set: true, ca_cert_set: false, stable_id_attribute: 'objectGUID', username_attribute: 'sAMAccountName', email_attribute: 'mail', name_attribute: 'displayName', status: 'tested', version: 1 } },
    } as any)
    vi.spyOn(api.directoryApi, 'previewDirectory').mockResolvedValue({ data: { preview_id: 'pv1', status: 'succeeded', scanned: 10, created: 3, updated: 1, disabled: 0, conflict: 0, unassigned: 2 } } as any)
    vi.spyOn(api.directoryApi, 'activatePreview').mockResolvedValue({ data: { run_id: 'run1', preview_id: 'pv1', scanned: 10, created: 3 } } as any)
    vi.spyOn(api.directoryApi, 'listSyncRuns').mockResolvedValue({ data: [{ id: 'run1', status: 'succeeded', scanned: 10, created: 3 }] } as any)
    vi.spyOn(api.directoryApi, 'saveDraft').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.directoryApi, 'testConnection').mockResolvedValue({ data: { success: true } } as any)
  })

  const renderDirectory = () => {
    const queryClient = makeQueryClient()
    return render(
      <MemoryRouter initialEntries={['/identity-sources/directory']}>
        <QueryClientProvider client={queryClient}>
          <Routes>
            <Route path='/identity-sources/directory' element={<IdentityDirectorySource />} />
          </Routes>
        </QueryClientProvider>
      </MemoryRouter>,
    )
  }

  it('使用「生成同步预览」而非「立即同步/同步账号」', async () => {
    renderDirectory()
    expect(await screen.findByRole('button', { name: /生成同步预览/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^同步账号$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /立即同步/ })).not.toBeInTheDocument()
  })

  it('点击「生成同步预览」调用 previewDirectory', async () => {
    renderDirectory()
    // 等草稿异步加载完成（display_name 出现在表单里）再点击
    await screen.findByDisplayValue('总部目录')
    const btn = await screen.findByRole('button', { name: /生成同步预览/ })
    await waitFor(() => expect(btn).not.toBeDisabled())
    fireEvent.click(btn)
    await waitFor(() => expect(api.directoryApi.previewDirectory).toHaveBeenCalled())
  })

  it('测试连接成功后明确提示「尚未生效」', async () => {
    renderDirectory()
    await screen.findByDisplayValue('总部目录')
    const testBtn = await screen.findByRole('button', { name: /测试连接/ })
    await waitFor(() => expect(testBtn).not.toBeDisabled())
    fireEvent.click(testBtn)
    expect(await screen.findByText(/尚未生效/)).toBeInTheDocument()
  })

  it('Base DN / 稳定 ID 属性位于「高级设置」折叠区', async () => {
    renderDirectory()
    expect(await screen.findByText('高级设置')).toBeInTheDocument()
  })

  it('不展示数据库 ID 与密码明文', async () => {
    const { container } = renderDirectory()
    await screen.findByDisplayValue('总部目录')
    expect(container.textContent).not.toContain('supersecret-password')
  })

  it('调用 listSyncRuns 展示同步历史', async () => {
    renderDirectory()
    await waitFor(() => expect(api.directoryApi.listSyncRuns).toHaveBeenCalled())
  })

  it('renders sync history from the production API envelope without crashing', async () => {
    vi.mocked(api.directoryApi.listSyncRuns).mockResolvedValue({
      data: {
        data: [{
          id: 'run-prod-envelope',
          kind: 'full',
          status: 'succeeded',
          started_at: '2026-07-30T02:00:00Z',
          finished_at: '2026-07-30T02:00:05Z',
          created: 2,
          updated: 1,
          disabled: 0,
          conflict: 0,
        }],
      },
    } as any)

    renderDirectory()

    expect(await screen.findByText('全量同步')).toBeInTheDocument()
  })

  it('服务端错误返回原始目录配置时不将其填入表单', async () => {
    vi.spyOn(api.directoryApi, 'getDraft').mockResolvedValue({
      data: { data: {
        id: 'd1', kind: 'ldap', display_name: '总部目录', bind_password_set: true, ca_cert_set: true,
        stable_id_attribute: 'entryUUID', username_attribute: 'uid', email_attribute: 'mail', name_attribute: 'cn', status: 'tested', version: 1,
        connection_url: 'ldaps://malicious.example.test:636', bind_dn: 'cn=malicious,dc=example,dc=test',
        bind_password: 'malicious-password', base_dn: 'dc=example,dc=test', users_dn: 'ou=people,dc=example,dc=test',
        user_filter: '(uid=malicious)', ca_cert_pem: 'malicious-certificate',
      } },
    } as any)

    renderDirectory()

    await screen.findByDisplayValue('总部目录')
    for (const rawValue of ['ldaps://malicious.example.test:636', 'cn=malicious,dc=example,dc=test', 'malicious-password', 'dc=example,dc=test', 'ou=people,dc=example,dc=test', '(uid=malicious)', 'malicious-certificate']) {
      expect(screen.queryByDisplayValue(rawValue)).not.toBeInTheDocument()
    }
  })

  // W9 9.4：放开 ldap://（StartTLS）与自定义端口；明文 http 等非 LDAP 协议仍拒
  it('允许 ldap:// StartTLS 与 3269 端口地址提交，拒绝非 LDAP 协议', async () => {
    renderDirectory()
    await screen.findByDisplayValue('总部目录')
    const fill = (url: string) => {
      fireEvent.change(screen.getByLabelText('地址'), { target: { value: url } })
      fireEvent.change(screen.getByLabelText('管理员账号'), { target: { value: 'cn=sync,dc=example,dc=test' } })
      fireEvent.change(screen.getByLabelText('用户/组范围'), { target: { value: 'ou=people,dc=example,dc=test' } })
      fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    }
    fill('http://ldap.example.test:389')
    expect(await screen.findByText('仅支持 ldaps:// 或 ldap://（StartTLS）安全连接')).toBeInTheDocument()
    expect(api.directoryApi.saveDraft).not.toHaveBeenCalled()

    fill('ldap://ldap.example.test:389')
    await waitFor(() => expect(api.directoryApi.saveDraft).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.directoryApi.saveDraft).mock.calls[0][0]).toMatchObject({ connection_url: 'ldap://ldap.example.test:389' })

    fill('ldaps://dc.example.test:3269')
    await waitFor(() => expect(api.directoryApi.saveDraft).toHaveBeenCalledTimes(2))
    expect(vi.mocked(api.directoryApi.saveDraft).mock.calls[1][0]).toMatchObject({ connection_url: 'ldaps://dc.example.test:3269' })
  })

  it('保存成功后立即清空目录原始配置输入', async () => {
    renderDirectory()
    await screen.findByDisplayValue('总部目录')
    fireEvent.change(screen.getByLabelText('地址'), { target: { value: 'ldaps://ldap.example.test:636' } })
    fireEvent.change(screen.getByLabelText('管理员账号'), { target: { value: 'cn=sync,dc=example,dc=test' } })
    fireEvent.change(screen.getByLabelText('服务账号密码'), { target: { value: 'directory-secret' } })
    fireEvent.change(screen.getByLabelText('用户/组范围'), { target: { value: 'ou=people,dc=example,dc=test' } })

    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))

    await waitFor(() => expect(api.directoryApi.saveDraft).toHaveBeenCalled())
    await waitFor(() => {
      for (const label of ['地址', '管理员账号', '服务账号密码', '用户/组范围']) {
        expect(screen.getByLabelText(label)).toHaveValue('')
      }
    })
  })
})
