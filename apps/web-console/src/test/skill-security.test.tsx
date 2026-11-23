import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { ConfigProvider } from 'antd'
import SkillSecurity from '../pages/SkillSecurity'
import { useAuthStore } from '../stores/auth'

const skillApi = vi.hoisted(() => ({ listAssets: vi.fn(), listVersions: vi.fn(), listInvocations: vi.fn(), scanArchive: vi.fn(), setAdmission: vi.fn() }))
// 2.9.22 起页面还会读防护项与例外（Skill 调用防护）；其余接口保持真实模块，只替换 Skill 接口与防护项读取。
vi.mock('../services/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../services/api')>()),
  skillSecurityApi: skillApi,
  protectionSettingsApi: { list: vi.fn().mockResolvedValue({ data: { items: [] } }), update: vi.fn() },
  agentGuardApi: { listExceptions: vi.fn().mockResolvedValue({ data: { data: [] } }), createException: vi.fn() },
}))
vi.mock('../hooks/useSecurityExecutionMode', () => ({ useSecurityExecutionMode: () => ({ mode: { effective_mode: 'record' }, isError: false }) }))
const version = () => ({ id: 'version-1', asset_id: 'asset-1', declared_version: '1.2.0', bundle_hash: 'a'.repeat(64), tree_hash: 'b'.repeat(64), signature_status: 'unknown', risk_level: 'medium', decision: 'confirm', scan_status: 'completed', admission_status: 'unverified', findings: Array.from({ length: 5 }, (_, index) => ({ type: 'network_egress', severity: index === 4 ? 'high' : 'medium', file: 'scripts/check.py', line: index + 1, evidence_preview: `evidence-${index + 1}`, content_hash: `hash-${index + 1}` })), manifest: { surface: 'uploaded_scan', files: [{ path: 'SKILL.md', sha256: 'c'.repeat(64) }] } })
const asset = () => ({ id: 'asset-1', canonical_name: 'pdf-review', display_name: 'PDF 审查', source_type: 'uploaded', publisher: '安全团队', admission_status: 'unverified' })
const summary = { uploaded_assets: 123, observed_assets: 35, pending_versions: 72, approved_versions: 18, quarantined_versions: 2, revoked_versions: 1, failed_scans: 9, invocations: 314 }
const renderPage = () => render(<MemoryRouter><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><ConfigProvider theme={{ token: { motion: false } }}><SkillSecurity /></ConfigProvider></QueryClientProvider></MemoryRouter>)
async function openVersions() { await userEvent.click(await screen.findByRole('button', { name: '查看版本' })); await screen.findByText('1.2.0') }

describe('Skill review workflow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({ token: 'fixture', user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' }, isAuthenticated: true })
    skillApi.listAssets.mockResolvedValue({ data: { items: [asset()], total: 123, limit: 20, offset: 0, summary, endpoint_inventory: false } })
    skillApi.listVersions.mockResolvedValue({ data: { items: [version()], total: 1, endpoint_execution_observed: false } })
    skillApi.listInvocations.mockResolvedValue({ data: { items: [{ id: 'inv-1', asset_id: 'asset-1', asset_version_id: 'version-1', canonical_name: 'pdf-review', declared_version: '1.2.0', request_id: 'request-safe', status: 'forwarded', raw_decision: 'confirm', effective_decision: 'audit', result_status: 'success', result_observed_at: '2026-10-04T00:00:00Z', attribution_mode: 'linked' }], total: 1, limit: 20, offset: 0, endpoint_execution_proof: false } })
    skillApi.setAdmission.mockResolvedValue({ data: { status: 'approved', version_id: 'version-1' } })
  })
  it('uses server totals and pages without claiming endpoint inventory or execution', async () => {
    renderPage()
    expect(await screen.findByText('上传资产：123')).toBeInTheDocument()
    expect(screen.getByText('待审核版本：72')).toBeInTheDocument()
    expect(screen.getByText('端侧执行：未知')).toBeInTheDocument()
    expect(screen.queryByText(/能力边界：/)).not.toBeInTheDocument()
    await userEvent.click(screen.getByTitle('2'))
    await waitFor(() => expect(skillApi.listAssets).toHaveBeenCalledWith(expect.objectContaining({ limit: 20, offset: 20 })))
  })
  it('shows all findings with file lines and expanded exact evidence', async () => {
    renderPage(); await openVersions()
    await userEvent.click(screen.getByRole('button', { name: '完整结果' }))
    expect(await screen.findByText('evidence-5')).toBeInTheDocument()
    expect(screen.getByText('scripts/check.py:5')).toBeInTheDocument()
    const row = screen.getByText('evidence-5').closest('tr')!
    expect(within(row).getByText('高危')).toBeInTheDocument()
    expect(within(row).queryByText('高')).not.toBeInTheDocument()
    expect(screen.getAllByText('外部网络地址')).toHaveLength(5)
    await userEvent.click(within(row).getByRole('button', { name: /Expand row|展开/ }))
    expect(await screen.findByText(/"content_hash": "hash-5"/)).toBeInTheDocument()
  })
  it('requires an explicit review reason and submits the exact status and bundle CAS', async () => {
    renderPage(); await openVersions()
    const approval = screen.getByRole('button', { name: /批\s*准/ })
    expect(approval).toBeEnabled()
    fireEvent.click(approval)
    const title = await screen.findByText('审核精确 Skill 版本')
    const dialog = title.closest('.ant-modal-content') as HTMLElement
    await waitFor(() => expect(dialog).toBeVisible())
    expect(within(dialog).getByRole('button', { name: '保存审核' })).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText('审核理由'), '已核对精确版本与包指纹')
    await userEvent.click(within(dialog).getByRole('button', { name: '保存审核' }))
    await waitFor(() => expect(skillApi.setAdmission).toHaveBeenCalledWith('version-1', 'approved', { reason: '已核对精确版本与包指纹', expected_status: 'unverified', expected_bundle_hash: 'a'.repeat(64) }))
  })
  it('shows persisted failed scans from HTTP 422 and allows only force approval', async () => {
    const failed = { ...version(), id: 'failed-version', scan_status: 'failed', scan_error_code: 'archive_symlink', admission_status: 'quarantined', decision: 'block' }
    skillApi.scanArchive.mockRejectedValue({ response: { status: 422, data: { version: failed, analysis_surface: 'uploaded_scan' } } })
    skillApi.listVersions.mockResolvedValue({ data: { items: [failed], total: 1 } })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: '提交扫描' }))
    await userEvent.type(screen.getByLabelText('Skill 标识'), 'pdf-review')
    await userEvent.type(screen.getByLabelText('声明版本'), '1.2.0')
    await userEvent.upload(screen.getByLabelText('Skill 压缩包'), new File(['PK fixture'], 'skill.zip', { type: 'application/zip' }))
    await userEvent.click(screen.getByRole('button', { name: '开始扫描' }))
    expect(await screen.findByText('扫描失败：archive_symlink')).toBeInTheDocument()
    // 2.9.22 复核：扫描失败的版本不能普通批准，只能强制批准（必填原因，见 skill-security-protection.test.tsx）。
    expect(screen.queryByRole('button', { name: /^批\s*准$/ })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /强制批准/ }).length).toBeGreaterThan(0)
    await waitFor(() => expect(screen.queryByRole('button', { name: '开始扫描' })).not.toBeInTheDocument())
    expect(skillApi.listAssets.mock.calls.length).toBeGreaterThan(1)
  })
  it('reopens review after a conflict without silently retrying the write', async () => {
    skillApi.setAdmission.mockRejectedValue({ response: { status: 409 } })
    renderPage(); await openVersions()
    await userEvent.click(screen.getByRole('button', { name: /批\s*准/ }))
    await userEvent.type(screen.getByLabelText('审核理由'), '人工审核依据')
    await userEvent.click(screen.getByRole('button', { name: '保存审核' }))
    expect(await screen.findByText('版本状态已变化，请重新审核')).toBeInTheDocument()
    expect(skillApi.setAdmission).toHaveBeenCalledTimes(1)
  })
  it('filters invocations by exact version and separates forwarding, result, and endpoint facts', async () => {
    renderPage(); await openVersions()
    await userEvent.click(screen.getByRole('button', { name: '调用关联' }))
    await waitFor(() => expect(skillApi.listInvocations).toHaveBeenCalledWith(expect.objectContaining({ asset_id: 'asset-1', version_id: 'version-1' })))
    expect(await screen.findByText('网关转发')).toBeInTheDocument()
    expect(screen.getByText('已收到 · success')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'request-safe' })).toHaveAttribute('href', '/audit/access-retention?view=requests&request_id=request-safe')
    expect(screen.queryByText('执行成功')).not.toBeInTheDocument()
  })
  // 2.9.22：扫描判为阻断（decision=block）不再禁止批准，改为“强制批准”并必填原因，见 skill-security-protection.test.tsx。
  it.each([{ source: 'observed', change: {} }, { source: 'uploaded', change: { declared_version: '' } }, { source: 'uploaded', change: { signature_status: 'invalid' } }])('refuses invalid approval condition %j', async ({ source, change }) => {
    skillApi.listAssets.mockResolvedValue({ data: { items: [{ ...asset(), source_type: source }], total: 1, summary } })
    skillApi.listVersions.mockResolvedValue({ data: { items: [{ ...version(), ...change }], total: 1 } })
    renderPage(); await userEvent.click(await screen.findByRole('button', { name: '查看版本' }))
    expect(await screen.findByRole('button', { name: /批\s*准/ })).toBeDisabled()
    expect(skillApi.setAdmission).not.toHaveBeenCalled()
  })
  it('does not claim a precise version match for an unresolved caller declaration', async () => {
    skillApi.listInvocations.mockResolvedValue({ data: { items: [{ id: 'declared-only', canonical_name: 'unknown-skill', status: 'proposed', attribution_mode: 'explicit' }], total: 1 } })
    renderPage()
    await userEvent.click(screen.getByRole('tab', { name: '调用关联' }))
    expect(await screen.findByText('调用方声明')).toBeInTheDocument()
    expect(screen.getByText('无精确版本')).toBeInTheDocument()
    expect(screen.queryByText('精确版本关联')).not.toBeInTheDocument()
    expect(screen.queryByText('声明匹配')).not.toBeInTheDocument()
  })
})
