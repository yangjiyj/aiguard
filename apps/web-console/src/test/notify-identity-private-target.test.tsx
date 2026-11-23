import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { Modal } from 'antd'
import NotifyChannels from '../pages/NotifyChannels'
import IdentitySources from '../pages/IdentitySources'
import api, { directoryApi, identityApi, notifyApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { last } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), warning: vi.fn(), error: vi.fn(), info: vi.fn() } }
})

function wrap(node: JSX.Element) {
  return render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        {node}
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

function setRole(role: string) {
  useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role, tenant_id: 'tenant-a' }, isAuthenticated: true })
}

const NOTIFY_RISK = '允许连内网地址（回环、链路本地、元数据地址仍拒绝）'
const SSO_RISK = '控制面可被用来访问这些地址。'

describe('通知渠道：允许内网地址', () => {
  afterEach(() => Modal.destroyAll())
  beforeEach(() => {
    vi.restoreAllMocks()
    setRole('platform_admin')
    vi.spyOn(notifyApi, 'list').mockResolvedValue({ data: { channels: [
      { id: 'nc_1', type: 'webhook', name: '内网告警', enabled: true, config_json: { url: 'http://10.1.2.3/hook', method: 'POST' } },
    ] } } as never)
    vi.spyOn(notifyApi, 'update').mockResolvedValue({ data: {} } as never)
  })

  it('编辑时打开允许内网地址要二次确认，保存写进 config_json', async () => {
    const user = userEvent.setup()
    wrap(<NotifyChannels />)
    await screen.findByText('内网告警')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const toggle = await screen.findByRole('switch', { name: '允许内网地址' })
    expect(toggle).not.toBeChecked()
    await user.click(toggle)
    const confirmBox = last(await screen.findAllByText(NOTIFY_RISK)).closest('.ant-modal') as HTMLElement
    await user.click(within(confirmBox).getByRole('button', { name: '确认打开' }))
    await waitFor(() => expect(toggle).toBeChecked())
    const dialog = (await screen.findByText('编辑通知渠道')).closest('.ant-modal') as HTMLElement
    await user.click(within(dialog).getByRole('button', { name: /确\s*认/ }))
    await waitFor(() => expect(notifyApi.update).toHaveBeenCalledWith('nc_1', {
      name: '内网告警',
      config_json: { url: 'http://10.1.2.3/hook', method: 'POST', allow_private_target: true },
      enabled: true,
    }))
  })

  it('取消确认则不打开', async () => {
    const user = userEvent.setup()
    wrap(<NotifyChannels />)
    await screen.findByText('内网告警')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const toggle = await screen.findByRole('switch', { name: '允许内网地址' })
    await user.click(toggle)
    const confirm = last(await screen.findAllByText(NOTIFY_RISK)).closest('.ant-modal') as HTMLElement
    await user.click(within(confirm).getByRole('button', { name: /取\s*消/ }))
    expect(toggle).not.toBeChecked()
  })

  it('租户级角色不能打开', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'u2', username: 'so', role: 'security_officer', tenant_id: 'tenant-a' }, isAuthenticated: true })
    const user = userEvent.setup()
    wrap(<NotifyChannels />)
    await screen.findByText('内网告警')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    expect(await screen.findByRole('switch', { name: '允许内网地址' })).toBeDisabled()
  })
})

describe('企业身份源：出站地址', () => {
  afterEach(() => Modal.destroyAll())
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(identityApi, 'getOverview').mockResolvedValue({ data: { login: { state: 'unconfigured' }, directory: { state: 'unconfigured' }, reconciliation_required: 0 } } as never)
    vi.spyOn(identityApi, 'getSources').mockResolvedValue({ data: [] } as never)
    vi.spyOn(directoryApi, 'getDraft').mockResolvedValue({ data: {} } as never)
    vi.spyOn(api, 'get').mockResolvedValue({ data: { ldap_allowed_targets: '["dc01.corp.example:636"]' } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
  })

  it('没有该键时按 2.9.21 视为允许内网（只有 true 才拦）', async () => {
    setRole('platform_admin')
    wrap(<IdentitySources />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    expect(toggle).toBeChecked()
  })

  it('拦内网时打开要二次确认，保存写入系统设置', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: { idp_block_private: 'true', ldap_allowed_targets: '["dc01.corp.example:636"]' } } as never)
    setRole('platform_admin')
    const user = userEvent.setup()
    wrap(<IdentitySources />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    expect(toggle).not.toBeChecked()
    expect(screen.getByText('dc01.corp.example:636')).toBeInTheDocument()
    await user.click(toggle)
    const confirmBox = last(await screen.findAllByText(SSO_RISK)).closest('.ant-modal') as HTMLElement
    await user.click(within(confirmBox).getByRole('button', { name: '确认打开' }))
    await waitFor(() => expect(toggle).toBeChecked())
    const cidrs = screen.getByRole('combobox', { name: 'SSO 放行网段' })
    fireEvent.change(cidrs, { target: { value: '10.20.0.0/16' } })
    fireEvent.keyDown(cidrs, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await user.click(screen.getByRole('button', { name: '保存出站地址' }))
    // 目录服务地址没改，不回写。
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/system/settings', {
      idp_block_private: false,
      idp_allowed_cidrs: '["10.20.0.0/16"]',
    }))
  })

  it('环境变量折算的显示值不回写', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: {
      idp_block_private: 'true',
      idp_allowed_cidrs: '["10.0.0.0/8"]',
      ldap_allowed_targets: '["dc.corp.test:636"]',
      egress_setting_sources: { idp_block_private: 'env', idp_allowed_cidrs: 'env', ldap_allowed_targets: 'env' },
    } } as never)
    setRole('platform_admin')
    const user = userEvent.setup()
    wrap(<IdentitySources />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    const targets = screen.getByRole('combobox', { name: '目录服务允许的地址' })
    fireEvent.change(targets, { target: { value: 'dc02.corp.test' } })
    fireEvent.keyDown(targets, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await user.click(screen.getByRole('button', { name: '保存出站地址' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/system/settings', { ldap_allowed_targets: '["dc.corp.test:636","dc02.corp.test"]' }))
  })

  it('库里的值无效、生效的是部署值时就地提示，其余来源不加说明', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: {
      idp_block_private: 'false',
      idp_allowed_cidrs: '[]',
      ldap_allowed_targets: '["dc.corp.test:636"]',
      egress_setting_sources: { idp_block_private: 'env', idp_allowed_cidrs: 'default', ldap_allowed_targets: 'invalid' },
    } } as never)
    setRole('platform_admin')
    wrap(<IdentitySources />)
    expect(await screen.findByText('配置无效，已用部署值')).toBeInTheDocument()
    expect(screen.getAllByText('配置无效，已用部署值')).toHaveLength(1)
  })

  it('目录服务地址格式不对时就地报错、不保存', async () => {
    setRole('platform_admin')
    const user = userEvent.setup()
    wrap(<IdentitySources />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    const targets = screen.getByRole('combobox', { name: '目录服务允许的地址' })
    fireEvent.change(targets, { target: { value: 'ldap://dc.corp.example:636' } })
    fireEvent.keyDown(targets, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await user.click(screen.getByRole('button', { name: '保存出站地址' }))
    expect(await screen.findByText('地址格式应为 主机名[:端口]：ldap://dc.corp.example:636')).toBeInTheDocument()
    expect(api.put).not.toHaveBeenCalled()
  })

  it('目录服务地址写成 主机名[:端口] 可以保存', async () => {
    setRole('platform_admin')
    const user = userEvent.setup()
    wrap(<IdentitySources />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    const targets = screen.getByRole('combobox', { name: '目录服务允许的地址' })
    fireEvent.change(targets, { target: { value: 'dc02.corp.example' } })
    fireEvent.keyDown(targets, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await user.click(screen.getByRole('button', { name: '保存出站地址' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/system/settings', expect.objectContaining({
      ldap_allowed_targets: '["dc01.corp.example:636","dc02.corp.example"]',
    })))
  })

  it('目录服务地址不接受 IP（IP 写在网段名单里），占位提示主机名写法', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: {} } as never)
    setRole('platform_admin')
    const user = userEvent.setup()
    wrap(<IdentitySources />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(toggle).toBeEnabled())
    expect(screen.getByText('ldap.corp.example:636')).toBeInTheDocument()
    const targets = screen.getByRole('combobox', { name: '目录服务允许的地址' })
    fireEvent.change(targets, { target: { value: '10.0.0.6:636' } })
    fireEvent.keyDown(targets, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await user.click(screen.getByRole('button', { name: '保存出站地址' }))
    expect(await screen.findByText('地址格式应为 主机名[:端口]：10.0.0.6:636')).toBeInTheDocument()
    expect(api.put).not.toHaveBeenCalled()
  })

  it('旧 admin 角色也只读（写系统设置只认平台管理员）', async () => {
    setRole('admin')
    wrap(<IdentitySources />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(toggle).toBeDisabled()
  })

  it('租户管理员只读', async () => {
    setRole('tenant_admin')
    wrap(<IdentitySources />)
    const toggle = await screen.findByRole('switch', { name: 'SSO 允许内网地址' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(toggle).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存出站地址' })).toBeDisabled()
  })
})
