import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ws8AlertInboxApi } from '../services/api'

// 契约 A-E（折叠视图与管理员批量已读）：前端只负责按契约发请求，这里钉死 URL、方法与参数/请求体。
const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
  interceptors: {
    request: { use: vi.fn() },
    response: { use: vi.fn() },
  },
}))

vi.mock('axios', () => ({
  default: {
    create: vi.fn(() => mockApi),
  },
}))

describe('ws8AlertInboxApi 折叠与批量已读契约', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.get.mockResolvedValue({ data: {} })
    mockApi.post.mockResolvedValue({ data: {} })
  })

  it('A folded: GET /alerts/inbox/folded，筛选参数原样放进 params', async () => {
    const params = { unread: true, severity: 'warning', type: 'alert', from: '2026-09-03T16:00:00.000Z', to: '2026-10-13T16:00:00.000Z', limit: 20, offset: 40 }
    await ws8AlertInboxApi.folded(params)
    expect(mockApi.get).toHaveBeenCalledWith('/alerts/inbox/folded', { params })
  })

  it('B foldedItems: GET /alerts/inbox/folded/items，组原值全部带上', async () => {
    const params = {
      key: 'abc123', type: 'alert', severity: 'warning',
      day_start: '2026-10-09T16:00:00Z', day_end: '2026-10-10T16:00:00Z', unread: true, limit: 20, offset: 0,
    }
    await ws8AlertInboxApi.foldedItems(params)
    expect(mockApi.get).toHaveBeenCalledWith('/alerts/inbox/folded/items', { params })
  })

  it('C typeSummary: GET /alerts/inbox/type-summary，不带参数', async () => {
    await ws8AlertInboxApi.typeSummary()
    expect(mockApi.get).toHaveBeenCalledWith('/alerts/inbox/type-summary')
  })

  it('D bulkReadPreview: GET /alerts/inbox/bulk-read/preview（只读预览，不是 POST）', async () => {
    const params = { type: 'alert', from: '2026-09-03T16:00:00Z', to: '2026-10-13T16:00:00Z' }
    await ws8AlertInboxApi.bulkReadPreview(params)
    expect(mockApi.get).toHaveBeenCalledWith('/alerts/inbox/bulk-read/preview', { params })
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('E bulkRead: POST /alerts/inbox/bulk-read，请求体带 expected_count 与 confirm:true', async () => {
    const body = { type: 'alert', from: '2026-09-03T16:00:00Z', to: '2026-10-13T16:00:00Z', expected_count: 11944, confirm: true as const }
    await ws8AlertInboxApi.bulkRead(body)
    expect(mockApi.post).toHaveBeenCalledWith('/alerts/inbox/bulk-read', body)
  })
})
