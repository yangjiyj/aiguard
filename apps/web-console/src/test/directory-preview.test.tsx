import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import * as api from '../services/api'
import type { DirectorySourceSummary } from '../services/api'
import IdentityDirectorySource from '../pages/IdentityDirectorySource'
import DirectoryPreview from '../components/identity/DirectoryPreview'
import DirectorySyncHistory from '../components/identity/DirectorySyncHistory'

// 任务 9：目录同步 — 预览、激活、历史工作流（TDD）
// 覆盖规格 7 条断言：
// 1. 连接测试前禁止预览
// 2. 预览显示新增/更新/禁用/冲突/未分配数量
// 3. 冲突项可展开但敏感字段脱敏
// 4. 配置变更后旧预览作废
// 5. 激活需二次确认，确认文案包含影响数量
// 6. 同步历史可看到状态/耗时/操作者/失败摘要
// 7. API 错误不丢失草稿

const TESTED_DRAFT: DirectorySourceSummary = {
  id: 'd1', kind: 'ldap' as const, display_name: '总部目录',
  bind_password_set: true, ca_cert_set: false,
  stable_id_attribute: 'objectGUID', username_attribute: 'sAMAccountName',
  email_attribute: 'mail', name_attribute: 'displayName',
  status: 'tested', version: 3,
}

const PREVIEW = {
  preview_id: 'pv1', source_id: 'd1', status: 'succeeded',
  scanned: 100, created: 12, updated: 8, disabled: 4, conflict: 5, unassigned: 6,
  expires_at: '2099-01-01T00:00:00Z',
}

afterEach(() => {
  // antd Modal.confirm 是命令式 API，cleanup 不移除其 DOM，需手动清理避免跨用例污染
  cleanup()
  document.querySelectorAll('.ant-modal-root, .ant-message, .ant-notification').forEach((el) => el.remove())
})

function makeQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
}

function renderDirectory() {
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

function fillRequiredDirectoryDraftFields() {
  fireEvent.change(screen.getByLabelText('地址'), { target: { value: 'ldaps://dir.example.test:636' } })
  fireEvent.change(screen.getByLabelText('管理员账号'), { target: { value: 'cn=svc,dc=example,dc=test' } })
  fireEvent.change(screen.getByLabelText('用户/组范围'), { target: { value: 'ou=people,dc=example,dc=test' } })
  fireEvent.click(screen.getByText('高级设置'))
  fireEvent.change(screen.getByLabelText('Base DN'), { target: { value: 'dc=example,dc=test' } })
}

describe('DirectoryPreview 组件 — 预览数量展示', () => {
  it('显示新增、更新、禁用、冲突、未分配五类计数', () => {
    render(
      <MemoryRouter>
        <DirectoryPreview preview={PREVIEW} activating={false} onActivate={vi.fn()} onDismiss={vi.fn()} />
      </MemoryRouter>,
    )
    // 用 testid 容器避免与 Card 标题/明细的文本歧义
    const stat = screen.getByTestId('preview-stats')
    const txt = stat.textContent || ''
    expect(txt).toMatch(/新增/)
    expect(txt).toMatch(/更新/)
    expect(txt).toMatch(/禁用/)
    expect(txt).toMatch(/冲突/)
    expect(txt).toMatch(/未分配/)
    // 五个数字都在
    expect(txt).toContain('12')
    expect(txt).toContain('8')
    expect(txt).toContain('4')
    expect(txt).toContain('5')
    expect(txt).toContain('6')
  })

  it('冲突项可展开查看，但展开内容不展示 email/subject 原文（脱敏）', async () => {
    const { container } = render(
      <MemoryRouter>
        <DirectoryPreview preview={PREVIEW} activating={false} onActivate={vi.fn()} onDismiss={vi.fn()} />
      </MemoryRouter>,
    )
    // 点击「展开明细（脱敏）」链接
    const expand = await screen.findByRole('button', { name: /展开.*明细/i })
    fireEvent.click(expand)
    // 展开后出现脱敏提示行
    await waitFor(() => {
      const desensitizedHints = screen.getAllByText(/已脱敏|不展示.*邮箱|不展示.*原文/i)
      expect(desensitizedHints.length).toBeGreaterThan(0)
    })
    // DOM 中绝不出现原始 email 或 subject 明文
    expect(container.textContent).not.toContain('jane.doe@example.com')
    expect(container.textContent).not.toContain('cn=jane')
  })

  it('激活按钮弹出二次确认，确认文案包含影响数量（新增/更新/禁用/冲突）', async () => {
    const onActivate = vi.fn()
    render(
      <MemoryRouter>
        <DirectoryPreview preview={PREVIEW} activating={false} onActivate={onActivate} onDismiss={vi.fn()} />
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByTestId('directory-activate-btn'))
    // 二次确认 Modal 出现，文案包含各类影响数量
    await waitFor(() => {
      const body = document.body.textContent || ''
      expect(body).toMatch(/新增.*12/)
      expect(body).toMatch(/更新.*8/)
      expect(body).toMatch(/禁用.*4/)
      expect(body).toMatch(/冲突.*5/)
    })
  })
})

describe('DirectorySyncHistory 组件 — 历史展示', () => {
  it('展示状态、耗时、操作者、失败摘要', () => {
    const runs = [
      {
        id: 'run1', source_id: 'd1', source_version: 3, kind: 'full', status: 'succeeded',
        started_at: '2026-07-20T10:00:00Z', finished_at: '2026-07-20T10:02:30Z',
        scanned: 100, created: 12, updated: 8, restored: 0, disabled: 4, conflict: 5, skipped: 0,
        actor_user_id: 'u-admin',
      },
      {
        id: 'run2', source_id: 'd1', source_version: 2, kind: 'changed', status: 'failed',
        started_at: '2026-07-19T10:00:00Z', finished_at: '2026-07-19T10:00:45Z',
        scanned: 0, created: 0, updated: 0, restored: 0, disabled: 0, conflict: 0, skipped: 0,
        actor_user_id: 'u-admin', error_code: 'directory_list_failed',
      },
    ]
    render(
      <MemoryRouter>
        <DirectorySyncHistory runs={runs} loading={false} />
      </MemoryRouter>,
    )
    // 状态：成功 + 失败
    expect(screen.getByText('成功')).toBeInTheDocument()
    expect(screen.getByText('失败')).toBeInTheDocument()
    // 耗时列、操作者列存在（表头）
    expect(screen.getByText(/耗时/)).toBeInTheDocument()
    expect(screen.getByText(/操作者/)).toBeInTheDocument()
    // 失败摘要（error_code 中文映射，绝不展示原始 DB 错误）
    expect(screen.getByText(/目录读取失败/)).toBeInTheDocument()
  })

  it('失败摘要不泄露原始 DB 错误细节', () => {
    const runs = [{
      id: 'run3', source_id: 'd1', source_version: 3, kind: 'full', status: 'failed',
      started_at: '2026-07-20T10:00:00Z', finished_at: '2026-07-20T10:00:10Z',
      scanned: 0, created: 0, updated: 0, restored: 0, disabled: 0, conflict: 0, skipped: 0,
      actor_user_id: 'u-admin', error_code: 'directory_list_failed',
    }]
    const { container } = render(
      <MemoryRouter>
        <DirectorySyncHistory runs={runs} loading={false} />
      </MemoryRouter>,
    )
    expect(container.textContent).not.toContain('pq:')
    expect(container.textContent).not.toMatch(/connection refused/i)
    expect(container.textContent).not.toMatch(/SQLSTATE|syntax error/i)
  })
})

describe('IdentityDirectorySource — 完整三步工作流', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api.directoryApi, 'getDraft').mockResolvedValue({ data: { data: TESTED_DRAFT } } as any)
    vi.spyOn(api.directoryApi, 'previewDirectory').mockResolvedValue({ data: PREVIEW } as any)
    vi.spyOn(api.directoryApi, 'activatePreview').mockResolvedValue({
      data: { run_id: 'run-new', preview_id: 'pv1', scanned: 100, created: 12, updated: 8, disabled: 4, conflict: 5, unassigned: 6, restored: 0 },
    } as any)
    vi.spyOn(api.directoryApi, 'listSyncRuns').mockResolvedValue({ data: [] } as any)
    vi.spyOn(api.directoryApi, 'saveDraft').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.directoryApi, 'testConnection').mockResolvedValue({ data: { success: true } } as any)
  })

  it('连接测试前（status≠tested）禁止生成预览', async () => {
    vi.spyOn(api.directoryApi, 'getDraft').mockResolvedValue({
      data: { data: { ...TESTED_DRAFT, status: 'draft' } },
    } as any)
    renderDirectory()
    const previewBtn = await screen.findByRole('button', { name: /生成同步预览/ })
    await waitFor(() => expect(previewBtn).toBeDisabled())
  })

  it('配置变更（保存草稿）后，旧预览标记为已作废，激活入口消失', async () => {
    renderDirectory()
    await screen.findByDisplayValue('总部目录')
    // 先生成预览
    const previewBtn = await screen.findByRole('button', { name: /生成同步预览/ })
    await waitFor(() => expect(previewBtn).not.toBeDisabled())
    fireEvent.click(previewBtn)
    // 预览面板出现，激活按钮可见
    await waitFor(() => expect(screen.getByTestId('directory-activate-btn')).toBeInTheDocument())
    // 保存草稿（配置变更）后，旧预览应作废
    fillRequiredDirectoryDraftFields()
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    await waitFor(() => expect(api.directoryApi.saveDraft).toHaveBeenCalled())
    // 旧预览不再可激活：面板里的激活按钮消失，并出现「已作废」提示
    await waitFor(() => {
      expect(screen.queryByTestId('directory-activate-btn')).not.toBeInTheDocument()
    })
    // 「配置已变更，此预览已作废」是唯一的作废提示 Alert 标题
    expect(screen.getByText('配置已变更，此预览已作废')).toBeInTheDocument()
  })

  it('API 错误不丢失草稿（保存失败后表单内容仍在，且不泄露 DB 细节）', async () => {
    vi.spyOn(api.directoryApi, 'saveDraft').mockRejectedValue({
      response: { data: { error: { code: 'internal_error', message: '保存失败：pq: connection refused at pgx' } } },
    })
    renderDirectory()
    const nameInput = await screen.findByDisplayValue('总部目录')
    expect(nameInput).toBeInTheDocument()
    fillRequiredDirectoryDraftFields()
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    await waitFor(() => expect(api.directoryApi.saveDraft).toHaveBeenCalled())
    // 草稿内容仍在，未被清空
    expect(screen.getByDisplayValue('总部目录')).toBeInTheDocument()
    // 错误消息不泄露原始 DB 细节（前端对未知错误统一脱敏）
    expect(document.body.textContent).not.toMatch(/pq:|connection refused|pgx/i)
  })
})
