import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { ConfigProvider } from 'antd'
import SkillSecurity from '../pages/SkillSecurity'
import api, { skillSecurityApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { chooseOption, PROTECTION_ITEMS } from './protectionTestUtils'

vi.mock('../hooks/useSecurityExecutionMode', () => ({ useSecurityExecutionMode: () => ({ mode: { effective_mode: 'protect' }, isError: false }) }))
vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

const blockedVersion = { id: 'v-block', asset_id: 'asset-1', declared_version: '2.0.0', bundle_hash: 'a'.repeat(64), tree_hash: 'b'.repeat(64), signature_status: 'unknown', risk_level: 'high', decision: 'block', scan_status: 'completed', admission_status: 'unverified', findings: [] }
const asset = { id: 'asset-1', canonical_name: 'pdf-review', display_name: 'PDF 审查', source_type: 'uploaded', admission_status: 'unverified' }

function renderPage(role: string, entry = '/security/skills') {
  useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role, tenant_id: 'tenant-a' }, isAuthenticated: true })
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        <ConfigProvider theme={{ token: { motion: false } }}><SkillSecurity /></ConfigProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('Skill 安全准入：防护项与强制批准', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api, 'get').mockImplementation(async (url: string) => {
      if (url === '/protection-settings') return { data: { items: PROTECTION_ITEMS } } as never
      return { data: { data: [] } } as never
    })
    vi.spyOn(api, 'put').mockResolvedValue({ data: { items: PROTECTION_ITEMS } } as never)
    vi.spyOn(skillSecurityApi, 'listAssets').mockResolvedValue({ data: { items: [asset], total: 1, limit: 20, offset: 0, summary: {}, inventory_scope: '', endpoint_inventory: false } } as never)
    vi.spyOn(skillSecurityApi, 'listVersions').mockResolvedValue({ data: { items: [blockedVersion], total: 1, endpoint_execution_observed: false } } as never)
    vi.spyOn(skillSecurityApi, 'setAdmission').mockResolvedValue({ data: {} } as never)
  })

  it('只显示 skill 组三项，改动作调用防护项接口', async () => {
    renderPage('security_officer')
    const table = await screen.findByRole('table', { name: 'Skill 调用防护' })
    expect(await within(table).findByText('Skill 身份异常')).toBeInTheDocument()
    expect(within(table).getByText('Skill 参数含危险命令')).toBeInTheDocument()
    expect(within(table).getByText('准入服务不可用')).toBeInTheDocument()
    expect(within(table).queryByText('SSH 私钥')).not.toBeInTheDocument()
    await chooseOption(within(table).getByRole('combobox', { name: 'Skill 参数含危险命令动作' }), '人工确认')
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/protection-settings', {
      items: { 'skill.dangerous_command': { action: 'confirm', params: {} } },
    }))
  })

  it('扫描判为阻断的版本可强制批准，原因必填并随请求提交', async () => {
    const user = userEvent.setup()
    renderPage('platform_admin')
    await user.click(await screen.findByRole('button', { name: '查看版本' }))
    const force = (await screen.findAllByRole('button', { name: /强制批准/ }))[0]
    expect(screen.queryByRole('button', { name: /^批准$/ })).not.toBeInTheDocument()
    await user.click(force)
    // 强制批准弹窗写明后果，标题就是“强制批准”。
    const dialog = (await screen.findByText('该版本扫描判为阻断，批准后可以被调用')).closest('.ant-modal') as HTMLElement
    expect(within(dialog).getByText('强制批准', { selector: '.ant-modal-title' })).toBeInTheDocument()
    const ok = within(dialog).getByRole('button', { name: '强制批准' })
    expect(ok).toBeDisabled()
    await user.type(within(dialog).getByLabelText('审核理由'), '已人工复核误报')
    await user.click(ok)
    await waitFor(() => expect(skillSecurityApi.setAdmission).toHaveBeenCalledWith('v-block', 'approved', expect.objectContaining({
      reason: '已人工复核误报',
      override_reason: '已人工复核误报',
    })))
  })

  it('扫描失败的版本可强制批准，弹窗写明扫描失败', async () => {
    const user = userEvent.setup()
    const failedVersion = { ...blockedVersion, id: 'v-failed', risk_level: 'critical', scan_status: 'failed', scan_error_code: 'archive_too_large', admission_status: 'quarantined' }
    vi.mocked(skillSecurityApi.listVersions).mockResolvedValue({ data: { items: [failedVersion], total: 1, endpoint_execution_observed: false } } as never)
    renderPage('platform_admin')
    await user.click(await screen.findByRole('button', { name: '查看版本' }))
    const force = (await screen.findAllByRole('button', { name: /强制批准/ }))[0]
    expect(force).toBeEnabled()
    await user.click(force)
    const dialog = (await screen.findByText('该版本扫描失败，批准后可以被调用')).closest('.ant-modal') as HTMLElement
    await user.type(within(dialog).getByLabelText('审核理由'), '包超出扫描上限，已逐个文件复核')
    await user.click(within(dialog).getByRole('button', { name: '强制批准' }))
    await waitFor(() => expect(skillSecurityApi.setAdmission).toHaveBeenCalledWith('v-failed', 'approved', expect.objectContaining({
      reason: '包超出扫描上限，已逐个文件复核',
      override_reason: '包超出扫描上限，已逐个文件复核',
      expected_status: 'quarantined',
    })))
  })

  it('扫描失败但签名无效的版本仍不能强制批准', async () => {
    const user = userEvent.setup()
    const invalidVersion = { ...blockedVersion, id: 'v-invalid', scan_status: 'failed', signature_status: 'invalid', admission_status: 'quarantined' }
    vi.mocked(skillSecurityApi.listVersions).mockResolvedValue({ data: { items: [invalidVersion], total: 1, endpoint_execution_observed: false } } as never)
    renderPage('platform_admin')
    await user.click(await screen.findByRole('button', { name: '查看版本' }))
    const force = (await screen.findAllByRole('button', { name: /强制批准/ }))[0]
    expect(force).toBeDisabled()
  })

  it('租户管理员看得到防护项但只读', async () => {
    renderPage('tenant_admin')
    const select = await screen.findByRole('combobox', { name: 'Skill 身份异常动作' })
    expect(select).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Skill 身份异常加例外' })).toBeDisabled()
  })

  it('?protection= 高亮对应行', async () => {
    renderPage('platform_admin', '/security/skills?protection=skill.admission_unavailable')
    const label = await screen.findByText('准入服务不可用')
    expect(label.closest('tr')).toHaveClass('is-focused')
  })
})
