import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import api, { contentSecurityApi } from '../services/api'
import FilePolicySettings, { DEFAULT_FILE_POLICY, filePolicyDraft } from '../pages/security-policy/FilePolicySettings'
import { normalizeInboxItem } from '../utils/alertInboxDisplay'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

const wrapper = ({ children }: { children: ReactNode }) => (
  <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>{children}</QueryClientProvider>
)

describe('运行告警新增原因', () => {
  it.each([
    ['retention_unavailable', '日志留存不可用'],
    ['mcp_policy_unavailable', 'MCP 策略读取失败'],
  ])('%s 显示为 %s', (reason, label) => {
    const item = normalizeInboxItem({ id: 'r1', severity: 'warning', type: 'runtime_fault', title: '', body_json: { inspection_reason: reason }, read_at: null, created_at: '2026-11-17T00:00:00Z' })
    expect(item.detail).toBe(label)
  })
})

describe('文件策略默认名单与后端一致（全空）', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('后端字段缺失时三个名单都回落为空，不多出类型阻断', () => {
    expect(DEFAULT_FILE_POLICY.allowed_types).toEqual([])
    expect(DEFAULT_FILE_POLICY.review_types).toEqual([])
    expect(DEFAULT_FILE_POLICY.blocked_types).toEqual([])
    const draft = filePolicyDraft({})
    expect(draft.allowed_types).toEqual([])
    expect(draft.blocked_types).toEqual([])
  })

  it('后端返回空名单时原样保存', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ data: { file_content_dlp_enabled: false } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(contentSecurityApi, 'getFilePolicy').mockResolvedValue({ data: { allowed_types: [], review_types: [], blocked_types: [], max_file_mb: 20, max_attachments: 10, max_zip_ratio: 100 } } as never)
    vi.spyOn(contentSecurityApi, 'listExceptions').mockResolvedValue({ data: { items: [] } } as never)
    const update = vi.spyOn(contentSecurityApi, 'updateFilePolicy').mockResolvedValue({ data: {} } as never)
    render(<FilePolicySettings canManage />, { wrapper })
    await waitFor(() => expect(screen.getByLabelText('ZIP发送方式')).toBeEnabled())
    expect(screen.getByLabelText('ZIP发送方式')).toHaveValue('allowed')
    await userEvent.click(screen.getByRole('button', { name: '保存网页 AI 附件准入' }))
    await waitFor(() => expect(update).toHaveBeenCalledWith(expect.objectContaining({ allowed_types: [], review_types: [], blocked_types: [] })))
  })
})
