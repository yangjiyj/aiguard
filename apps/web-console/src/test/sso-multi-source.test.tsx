import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { Modal } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import SsoConfig from '../pages/SsoConfig'
import * as api from '../services/api'
import { identityDepartmentMappingsApi } from '../services/identityDepartmentMappings'

// W9 9.2：多身份源并存。默认身份源继续走原接口，其余身份源显式带 source。
afterEach(() => {
  Modal.destroyAll()
})

const STATUS = (alias: string) => ({
  has_active: true,
  has_draft: false,
  emergency_admin_available: true,
  callback_url: `https://sso.example.com/sso/realms/jjdguard/broker/${alias}/endpoint`,
  publish_status: 'active',
  drift: false,
  runtime_available: true,
})

const SOURCES = [
  { id: 'is_def', source_alias: 'enterprise', display_name: 'HQ IdP', status: 'active', protocol: 'oidc', issuer_url: 'https://hq.example.com', client_id: 'hq', client_secret_set: true, scopes: 'openid', callback_url: '' },
  { id: 'is_sub', source_alias: 'jjd-sub000000001', display_name: 'Branch IdP', status: 'tested', protocol: 'oidc', issuer_url: 'https://branch.example.com', client_id: 'br', client_secret_set: true, scopes: 'openid', callback_url: '' },
]

describe('SsoConfig 多身份源', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.restoreAllMocks()
    vi.spyOn(identityDepartmentMappingsApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'getSources').mockResolvedValue({ data: { data: SOURCES } } as any)
    vi.spyOn(api.identityApi, 'getStatus').mockResolvedValue({ data: STATUS('enterprise') } as any)
    vi.spyOn(api.identityApi, 'getDeptMappings').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.identityApi, 'saveDraft').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identityApi, 'activate').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.identitySourcesApi, 'getStatus').mockImplementation(async (s: string) => ({ data: STATUS(s) }) as any)
    vi.spyOn(api.identitySourcesApi, 'saveDraft').mockResolvedValue({ data: { source_alias: 'jjd-new000000001' } } as any)
    vi.spyOn(api.identitySourcesApi, 'activate').mockResolvedValue({ data: {} } as any)
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <SsoConfig />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  const pick = async (label: RegExp) => {
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '选择身份源' }))
    const opts = await screen.findAllByText(label)
    fireEvent.click(opts[opts.length - 1])
  }

  it('默认只编辑默认身份源，其余身份源可切换并按 source 调用', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    expect(await screen.findByText('https://sso.example.com/sso/realms/jjdguard/broker/enterprise/endpoint')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /启用/ })).toBeDisabled()

    await pick(/Branch IdP/)
    expect(await screen.findByDisplayValue('https://branch.example.com')).toBeInTheDocument()
    expect(await screen.findByText('https://sso.example.com/sso/realms/jjdguard/broker/jjd-sub000000001/endpoint')).toBeInTheDocument()
    const activate = screen.getByRole('button', { name: /启用/ })
    await waitFor(() => expect(activate).not.toBeDisabled())
    fireEvent.click(activate)
    await waitFor(() => expect(api.identitySourcesApi.activate).toHaveBeenCalledWith('jjd-sub000000001'))
    expect(api.identityApi.activate).not.toHaveBeenCalled()
  })

  it('新增身份源以 source=new 保存，不改写默认身份源', async () => {
    renderPage()
    await screen.findByText('企业 SSO 配置')
    await pick(/新增身份源/)
    expect(await screen.findByText('保存草稿后生成')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('显示名称'), { target: { value: 'Third IdP' } })
    fireEvent.change(screen.getByLabelText('Issuer 地址'), { target: { value: 'https://third.example.com' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'third' } })
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    await waitFor(() => expect(api.identitySourcesApi.saveDraft).toHaveBeenCalledTimes(1))
    const [source, body] = vi.mocked(api.identitySourcesApi.saveDraft).mock.calls[0]
    expect(source).toBe('new')
    expect(body).toMatchObject({ display_name: 'Third IdP' })
    expect(api.identityApi.saveDraft).not.toHaveBeenCalled()
  })

  it('identitySourcesApi 以查询参数 source 传递身份源', async () => {
    vi.restoreAllMocks()
    vi.spyOn(identityDepartmentMappingsApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    const put = vi.spyOn(api.apiClient, 'put').mockResolvedValue({ data: {} })
    const post = vi.spyOn(api.apiClient, 'post').mockResolvedValue({ data: {} })
    await api.identitySourcesApi.saveDraft('new', { display_name: 'x', issuer_url: 'https://x', client_id: 'x' })
    await api.identitySourcesApi.disable('jjd-a', true)
    expect(put).toHaveBeenCalledWith('/identity/sources/draft', expect.anything(), { params: { source: 'new' } })
    expect(post).toHaveBeenCalledWith('/identity/sources/disable', { confirm: true }, { params: { source: 'jjd-a' } })
  })
})
