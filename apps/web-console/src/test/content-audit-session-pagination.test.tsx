import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ContentAudit from '../pages/ContentAudit'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'

describe('Content audit session pagination', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    useAuthStore.setState({
      token: 'admin-token',
      user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' },
      isAuthenticated: true,
    })
    vi.restoreAllMocks()
    vi.spyOn(api.contentAuditApi, 'getSessionEvents').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(api.contentAuditApi, 'listUsers').mockResolvedValue({
      data: { data: [], limit: 50, offset: 0, has_more: false, next_cursor: '' },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as any)
  })

  const renderPage = () => render(
    <MemoryRouter initialEntries={['/security/alerts?view=conversations']}>
      <QueryClientProvider client={queryClient}>
        <ContentAudit />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('loads the manager summary first and fetches raw pages only on demand', async () => {
    const user = userEvent.setup()
    const eventsSpy = vi.mocked(api.contentAuditApi.getSessionEvents)
    eventsSpy.mockResolvedValue({
      data: {
        data: [{
          id: 'event-page-two',
          request_id: 'request-page-two',
          severity: 'critical',
          rule_id: 'rule-page-two',
          rule_name: '分页证据',
          rule_type: 'ssrf_metadata_instruction',
          action_taken: 'alert',
          created_at: '2026-08-03T15:27:21Z',
          matched_summary: {
            findings: [{
              category: 'ssrf_metadata_instruction',
              rule_id: 'rule-page-two',
              rule_name: '分页证据',
              severity: 'critical',
              action: 'alert',
              matched_text_preview: '危险上下文',
            }],
          },
        }],
        total: 1,
        limit: 20,
        offset: 0,
        has_more: false,
      },
    } as any)
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: {
        data: [{
          session_id: 'session_large',
          user_id: 'user_1',
          start_time: '2026-08-03T15:26:49Z',
          end_time: '2026-08-03T15:28:50Z',
          message_count: 90,
          turn_count: 37,
          snapshot_count: 1,
          total_tokens: 3307,
          security_event_count: 1,
          actionable_alert_count: 1,
          matched_rule_count: 1,
          highest_severity: 'critical',
          risk_categories: ['ssrf_metadata_instruction'],
        }],
        total: 1,
      },
    } as any)

    const sessionSpy = vi.spyOn(api.contentAuditApi, 'getSession').mockImplementation(async (_sessionId: string, params?: any) => {
      if (params?.view === 'all') {
        const offset = Number(params.offset) || 0
        return {
          data: {
            data: [{
              id: `tool-${offset}`,
              role: 'tool',
              content: '工具运行大文本',
              tokens: 0,
              created_at: '2026-08-03T15:27:00Z',
            }],
            total: 21,
            limit: 20,
            offset,
            has_more: offset === 0,
          },
        } as any
      }
      const offset = Number(params?.offset) || 0
      const logs = offset === 0
        ? Array.from({ length: 20 }, (_, index) => ({
            id: 'manager-' + index,
            role: index % 2 === 0 ? 'user' : 'assistant',
            content: '摘要消息 ' + (index + 1),
            tokens: 1,
            created_at: '2026-08-03T15:26:' + String(index).padStart(2, '0') + 'Z',
          }))
        : [{
            id: 'manager-20',
            request_id: 'request-page-two',
            role: 'assistant',
            content: '第二页危险上下文',
            tokens: 1,
            created_at: '2026-08-03T15:27:20Z',
          }]
      return {
        data: {
          data: logs,
          total: 21,
          limit: 20,
          offset,
          has_more: offset === 0,
        },
      } as any
    })

    renderPage()
    await screen.findByText('session_large')
    await user.click(await screen.findByRole('button', { name: /查看/ }))
    expect(document.querySelector('.content-audit-drawer')).not.toBeNull()

    await waitFor(() => expect(sessionSpy).toHaveBeenCalledWith(
      'session_large',
      expect.objectContaining({ view: 'manager', limit: 20, offset: 0, from: expect.any(String), to: expect.any(String) }),
    ))
    expect(sessionSpy.mock.calls.every(([, params]) => params?.view === 'manager' || params?.view === 'all')).toBe(true)
    await waitFor(() => expect(eventsSpy).toHaveBeenCalledWith(
      'session_large',
      expect.objectContaining({ limit: 20, offset: 0, from: expect.any(String), to: expect.any(String) }),
    ))
    expect(screen.queryByText('工具运行大文本')).not.toBeInTheDocument()
    expect(screen.queryByText('第二页危险上下文')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '加载更多对话' })).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: /命中证据/ }))
    expect((await screen.findAllByText('第二页危险上下文')).length).toBeGreaterThan(0)
    expect(sessionSpy).toHaveBeenCalledWith(
      'session_large',
      expect.objectContaining({ view: 'manager', limit: 20, offset: 20 }),
    )

    await user.click(screen.getByText('全部原文'))
    await waitFor(() => expect(sessionSpy).toHaveBeenCalledWith(
      'session_large',
      expect.objectContaining({ view: 'all', limit: 20, offset: 0, from: expect.any(String), to: expect.any(String) }),
    ))
    expect(screen.getByRole('group', { name: '原文分页' })).toHaveClass('content-audit-detail-pagination')
    await user.click(await screen.findByRole('button', { name: '下一页原文' }))
    await waitFor(() => expect(sessionSpy).toHaveBeenCalledWith(
      'session_large',
      expect.objectContaining({ view: 'all', limit: 20, offset: 20, from: expect.any(String), to: expect.any(String) }),
    ))
  }, 30000)

  it('aborts an in-flight manager detail request when the drawer closes', async () => {
    const user = userEvent.setup()
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: {
        data: [{
          session_id: 'session_abort',
          start_time: '2026-09-08T00:00:00Z',
          actionable_alert_count: 1,
          matched_rule_count: 1,
        }],
        total: 1,
      },
    } as any)
    let requestSignal: AbortSignal | undefined
    vi.spyOn(api.contentAuditApi, 'getSession').mockImplementation(async (_sessionId, params) => {
      requestSignal = params?.signal
      return await new Promise((_resolve, reject) => {
        params?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
      })
    })

    renderPage()
    await screen.findByText('session_abort')
    await user.click(await screen.findByRole('button', { name: /查看/ }))
    await waitFor(() => expect(requestSignal).toBeInstanceOf(AbortSignal))
    await user.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(requestSignal?.aborted).toBe(true))
  })
})
