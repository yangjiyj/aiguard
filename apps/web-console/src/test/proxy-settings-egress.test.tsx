import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Modal } from 'antd'
import ProxySettings from '../pages/ProxySettings'
import api, { caApi, proxyApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { chooseOption, last } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), warning: vi.fn(), error: vi.fn(), info: vi.fn() } }
})

const rows = [{ id: 'w1', tenant_id: 't', host_pattern: 'api.example.com', port: 443, audit_enabled: true, description: '模型接口', created_at: '' }]

function renderPage(role = 'platform_admin') {
  useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role, tenant_id: 'tenant-a' }, isAuthenticated: true })
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <ProxySettings />
    </QueryClientProvider>,
  )
}

describe('正向代理配置：白名单与出站限制', () => {
  afterEach(() => Modal.destroyAll())
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(caApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as never)
    vi.spyOn(api, 'get').mockResolvedValue({ data: { outbound_proxy_enabled: 'false' } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(proxyApi, 'getWhitelist').mockResolvedValue({ data: { data: rows, total: 1 } } as never)
    vi.spyOn(proxyApi, 'createWhitelist').mockResolvedValue({ data: rows[0] } as never)
    vi.spyOn(proxyApi, 'updateWhitelist').mockResolvedValue({ data: {} } as never)
    vi.spyOn(proxyApi, 'deleteWhitelist').mockResolvedValue({ data: {} } as never)
  })

  it('白名单可增删改', async () => {
    const user = userEvent.setup()
    renderPage()
    const section = await screen.findByRole('region', { name: '出站白名单' })
    expect(await within(section).findByText('api.example.com')).toBeInTheDocument()

    await user.click(within(section).getByRole('button', { name: /添加白名单/ }))
    const addDialog = last(await screen.findAllByText('添加白名单')).closest('.ant-modal') as HTMLElement
    await user.type(within(addDialog).getByLabelText('主机'), 'git.corp.example')
    await user.click(within(addDialog).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(proxyApi.createWhitelist).toHaveBeenCalledWith({ host_pattern: 'git.corp.example', port: 0, audit_enabled: true, description: '' }))

    await user.click(within(section).getByRole('button', { name: /编\s*辑/ }))
    const editDialog = (await screen.findByText('编辑白名单')).closest('.ant-modal') as HTMLElement
    await user.clear(within(editDialog).getByLabelText('说明'))
    await user.type(within(editDialog).getByLabelText('说明'), '改过')
    await user.click(within(editDialog).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(proxyApi.updateWhitelist).toHaveBeenCalledWith('w1', expect.objectContaining({ host_pattern: 'api.example.com', port: 443, description: '改过' })))

    await user.click(within(section).getByRole('button', { name: /删\s*除/ }))
    const pop = (await screen.findByText('删除 api.example.com？')).closest('.ant-popover') as HTMLElement
    await user.click(within(pop).getByRole('button', { name: /删\s*除/ }))
    await waitFor(() => expect(proxyApi.deleteWhitelist).toHaveBeenCalledWith('w1'))
  })

  it('打开允许内网要二次确认并写明后果，保存写入系统设置', async () => {
    const user = userEvent.setup()
    renderPage()
    const section = await screen.findByRole('region', { name: '出站限制' })
    const toggle = within(section).getByRole('switch', { name: '允许访问内网地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    expect(within(section).getByText('只跳过按名字的判断，内网地址仍需放行网段')).toBeInTheDocument()
    await user.click(toggle)
    expect(await screen.findByText('网关可被用来访问这些地址。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认打开' }))
    await waitFor(() => expect(toggle).toBeChecked())
    await chooseOption(within(section).getByRole('combobox', { name: '未登记目标' }), '放行并审计')
    // 改成放行要二次确认。
    const unlistedConfirm = last(await screen.findAllByText('网关可被用来访问未登记的地址。')).closest('.ant-modal') as HTMLElement
    await user.click(within(unlistedConfirm).getByRole('button', { name: '确认放行' }))
    await user.click(within(section).getByRole('button', { name: '保存出站限制' }))
    // 只提交改动过的键。
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', {
      forward_proxy_unlisted_action: 'allow_audit',
      forward_proxy_egress_allow_private: true,
    }))
  })

  it('来源是环境变量或默认值的显示值不回写', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: {
      forward_proxy_unlisted_action: 'allow_audit',
      proxy_whitelist_fail_mode: 'open',
      forward_proxy_egress_allow_loopback: 'false',
      forward_proxy_egress_allowed_cidrs: '[]',
      egress_setting_sources: { forward_proxy_unlisted_action: 'env', proxy_whitelist_fail_mode: 'env', forward_proxy_egress_allow_loopback: 'default', forward_proxy_egress_allowed_cidrs: 'default' },
    } } as never)
    const user = userEvent.setup()
    renderPage()
    const section = await screen.findByRole('region', { name: '出站限制' })
    const loopback = within(section).getByRole('switch', { name: '允许访问回环地址' })
    await waitFor(() => expect(loopback).toBeEnabled())
    expect(within(section).getByText('放行并审计')).toBeInTheDocument()
    await user.click(loopback)
    const confirmBox = last(await screen.findAllByText('网关可被用来访问这些地址。')).closest('.ant-modal') as HTMLElement
    await user.click(within(confirmBox).getByRole('button', { name: '确认打开' }))
    await waitFor(() => expect(loopback).toBeChecked())
    await user.click(within(section).getByRole('button', { name: '保存出站限制' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', { forward_proxy_egress_allow_loopback: true }))
  })

  it('库里的值无效、生效的是部署值时在该项下提示', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: {
      forward_proxy_unlisted_action: 'deny',
      forward_proxy_egress_allowed_cidrs: '[]',
      egress_setting_sources: { forward_proxy_unlisted_action: 'invalid', forward_proxy_egress_allowed_cidrs: 'default' },
    } } as never)
    renderPage()
    const section = await screen.findByRole('region', { name: '出站限制' })
    expect(await within(section).findByText('配置无效，已用部署值')).toBeInTheDocument()
    expect(within(section).getAllByText('配置无效，已用部署值')).toHaveLength(1)
  })

  it('白名单读取失败改成放行要二次确认，取消则不变', async () => {
    const user = userEvent.setup()
    renderPage()
    const section = await screen.findByRole('region', { name: '出站限制' })
    const failMode = within(section).getByRole('combobox', { name: '白名单读取失败' })
    await waitFor(() => expect(failMode).toBeEnabled())
    await chooseOption(failMode, '放行')
    const confirm = last(await screen.findAllByText('网关可被用来访问未登记的地址。')).closest('.ant-modal') as HTMLElement
    // 弹窗入场动画期间 pointer-events 为 none，直接派发点击。
    fireEvent.click(within(confirm).getByRole('button', { name: /取\s*消/ }))
    expect(within(section).getByRole('combobox', { name: '白名单读取失败' }).closest('.ant-select')).toHaveTextContent('拒绝')
    await user.click(within(section).getByRole('button', { name: '保存出站限制' }))
    expect(api.put).not.toHaveBeenCalled()
  })

  it('租户级安全员看到的出站限制只读', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'u2', username: 'so', role: 'security_officer', tenant_id: 'tenant-a' }, isAuthenticated: true })
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        <ProxySettings />
      </QueryClientProvider>,
    )
    const section = await screen.findByRole('region', { name: '出站限制' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(within(section).getByRole('button', { name: '保存出站限制' })).toBeDisabled()
  })

  it('取消确认后开关保持关闭', async () => {
    const user = userEvent.setup()
    renderPage()
    const section = await screen.findByRole('region', { name: '出站限制' })
    const toggle = within(section).getByRole('switch', { name: '允许访问云元数据地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    await user.click(toggle)
    const dialog = last(await screen.findAllByText('网关可被用来访问这些地址。')).closest('.ant-modal') as HTMLElement
    await user.click(within(dialog).getByRole('button', { name: /取\s*消/ }))
    expect(toggle).not.toBeChecked()
  })

  it('非系统管理员只读', async () => {
    renderPage('tenant_admin')
    const egress = await screen.findByRole('region', { name: '出站限制' })
    const whitelist = screen.getByRole('region', { name: '出站白名单' })
    await within(whitelist).findByText('api.example.com')
    expect(within(whitelist).getByRole('button', { name: /添加白名单/ })).toBeDisabled()
    expect(within(egress).getByRole('switch', { name: '允许访问回环地址' })).toBeDisabled()
    expect(within(egress).getByRole('button', { name: '保存出站限制' })).toBeDisabled()
  })
})
