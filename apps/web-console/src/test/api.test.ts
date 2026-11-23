import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import axios from 'axios'
import { proxyApi, caApi, agentStatsApi, usageApi, agentGuardApi } from '../services/api'

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

describe('directoryApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  // 激活是破坏性操作，后端要求显式确认。前端漏传 body 时后端
  // json.Decode 会读到 io.EOF，现场表现为「请求格式错误」400，
  // 排查方向被完全带偏。这条测试把 confirm:true 钉死。
  it('sends explicit confirmation when activating a directory preview', async () => {
    const { directoryApi } = await import('../services/api')
    vi.mocked(axios.create().post).mockResolvedValue({ data: { data: {} }, status: 200 })

    await directoryApi.activatePreview('dsp_abc')

    expect(axios.create().post).toHaveBeenCalledWith(
      '/directory/sources/previews/dsp_abc/activate',
      { confirm: true },
    )
  })
})

describe('accessRetentionApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('sends large task members in JSON bodies instead of the URL', async () => {
    const { accessRetentionApi } = await import('../services/api')
    const members = Array.from({ length: 1221 }, (_, index) => `req-${index}`)
    vi.mocked(axios.create().post).mockResolvedValue({ data: {}, status: 200 })

    await accessRetentionApi.getContent('req-1220', members)
    await accessRetentionApi.getTimeline('req-1220', members)

    expect(axios.create().post).toHaveBeenNthCalledWith(1, '/audit/access-retention/req-1220/content', { members })
    expect(axios.create().post).toHaveBeenNthCalledWith(2, '/audit/access-retention/req-1220/timeline', { members })
    expect(axios.create().get).not.toHaveBeenCalled()
  })

  it('keeps single-request detail reads as GET', async () => {
    const { accessRetentionApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValue({ data: {}, status: 200 })

    await accessRetentionApi.getContent('req-1')
    await accessRetentionApi.getTimeline('req-1')

    expect(axios.create().get).toHaveBeenNthCalledWith(1, '/audit/access-retention/req-1/content', { params: undefined })
    expect(axios.create().get).toHaveBeenNthCalledWith(2, '/audit/access-retention/req-1/timeline', { params: undefined })
  })
  it('reads retained artifacts as authorized blobs', async () => {
    const { accessRetentionApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValue({ data: new Blob(['image']), status: 200 })

    await accessRetentionApi.getArtifact('req-1', 'art-1', 'preview')

    expect(axios.create().get).toHaveBeenCalledWith('/audit/access-retention/req-1/artifacts/art-1/preview', { responseType: 'blob' })
  })

})

describe('proxyApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('getWhitelist', () => {
    it('calls correct endpoint', async () => {
      const mockAxios = vi.mocked(axios.create().get)
      mockAxios.mockResolvedValueOnce({
        data: { data: [], total: 0 },
        status: 200,
      })

      await proxyApi.getWhitelist()

      expect(mockAxios).toHaveBeenCalledWith('/proxy/whitelist')
    })

    it('returns whitelist data', async () => {
      const mockData = {
        data: [
          { id: 'pw_001', host_pattern: '*.openai.com', port: 443 },
        ],
        total: 1,
      }

      vi.mocked(axios.create().get).mockResolvedValueOnce({
        data: mockData,
        status: 200,
      })

      const result = await proxyApi.getWhitelist()

      expect(result.data).toEqual(mockData)
    })
  })

  describe('createWhitelist', () => {
    it('posts to correct endpoint with entry data', async () => {
      const entry = {
        host_pattern: '*.newapi.com',
        port: 443,
        audit_enabled: true,
      }

      vi.mocked(axios.create().post).mockResolvedValueOnce({
        data: { id: 'pw_new', ...entry },
        status: 201,
      })

      await proxyApi.createWhitelist(entry)

      expect(axios.create().post).toHaveBeenCalledWith('/proxy/whitelist', entry)
    })
  })

  describe('updateWhitelist', () => {
    it('puts to correct endpoint with id and entry', async () => {
      const id = 'pw_001'
      const entry = { host_pattern: '*.updated.com' }

      vi.mocked(axios.create().put).mockResolvedValueOnce({
        data: { id, ...entry },
        status: 200,
      })

      await proxyApi.updateWhitelist(id, entry)

      expect(axios.create().put).toHaveBeenCalledWith(`/proxy/whitelist/${id}`, entry)
    })
  })

  describe('deleteWhitelist', () => {
    it('deletes correct endpoint with id', async () => {
      const id = 'pw_001'

      vi.mocked(axios.create().delete).mockResolvedValueOnce({
        status: 204,
      })

      await proxyApi.deleteWhitelist(id)

      expect(axios.create().delete).toHaveBeenCalledWith(`/proxy/whitelist/${id}`)
    })
  })
})

describe('usageApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('uses backend date parameter names', async () => {
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: {}, status: 200 })

    await usageApi.summary({ start_date: '2026-05-01', end_date: '2026-05-25' })

    expect(axios.create().get).toHaveBeenCalledWith('/usage/summary', {
      params: { start_date: '2026-05-01', end_date: '2026-05-25' },
    })
  })

  it('calls cost governance endpoints', async () => {
    vi.mocked(axios.create().get).mockResolvedValue({ data: [], status: 200 })

    await usageApi.byModel()
    await usageApi.byUser()
    await usageApi.byKey()
    await usageApi.byProvider()
    await usageApi.recommendations()

    expect(axios.create().get).toHaveBeenCalledWith('/usage/by-model', { params: undefined })
    expect(axios.create().get).toHaveBeenCalledWith('/usage/by-user', { params: undefined })
    expect(axios.create().get).toHaveBeenCalledWith('/usage/by-key', { params: undefined })
    expect(axios.create().get).toHaveBeenCalledWith('/usage/by-provider', { params: undefined })
    expect(axios.create().get).toHaveBeenCalledWith('/usage/recommendations', { params: undefined })
  })
})


describe('agentGuardApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('calls policy governance endpoints', async () => {
    vi.mocked(axios.create().get).mockResolvedValue({ data: { data: [] }, status: 200 })
    vi.mocked(axios.create().put).mockResolvedValue({ data: { policy: {} }, status: 200 })
    vi.mocked(axios.create().post).mockResolvedValue({ data: {}, status: 200 })

    await agentGuardApi.listPolicies()
    await agentGuardApi.upsertPolicy({ name: '默认策略', scope_type: 'tenant', mode: 'audit', default_action: 'audit', fail_policy: 'fail_closed' })
    await agentGuardApi.upsertPolicy({ id: 'agp_1', name: '更新策略', scope_type: 'tenant', mode: 'strict', default_action: 'block', fail_policy: 'fail_closed' })
    await agentGuardApi.listVersions('agp_1')
    await agentGuardApi.rollbackPolicy('agp_1', 'agpv_1')
    await agentGuardApi.listExceptions()
    await agentGuardApi.createException({ scope_type: 'project', decision: 'audit', reason: '已审批', expires_at: '2026-06-10T00:00:00Z' })
    await agentGuardApi.listConfirmations('pending')
    await agentGuardApi.resolveConfirmation('agc_1', { status: 'approved', note: '批准' })

    expect(axios.create().get).toHaveBeenCalledWith('/agentguard/policies')
    expect(axios.create().post).toHaveBeenCalledWith('/agentguard/policies', expect.objectContaining({ mode: 'audit' }))
    expect(axios.create().put).toHaveBeenCalledWith('/agentguard/policies/agp_1', expect.not.objectContaining({ id: expect.anything() }))
    expect(axios.create().get).toHaveBeenCalledWith('/agentguard/policies/agp_1/versions')
    expect(axios.create().post).toHaveBeenCalledWith('/agentguard/policies/agp_1/rollback', { version_id: 'agpv_1' })
    expect(axios.create().get).toHaveBeenCalledWith('/agentguard/exceptions')
    expect(axios.create().post).toHaveBeenCalledWith('/agentguard/exceptions', expect.objectContaining({ reason: '已审批' }))
    expect(axios.create().get).toHaveBeenCalledWith('/agentguard/confirmations', { params: { status: 'pending', source: 'agentguard' } })
    expect(axios.create().post).toHaveBeenCalledWith('/agentguard/confirmations/agc_1/resolve', { status: 'approved', note: '批准' })
  })
})


describe('caApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('generate', () => {
    it('posts to correct endpoint with validity_days param', async () => {
      vi.mocked(axios.create().post).mockResolvedValueOnce({
        data: { id: 'ca_new', status: 'active' },
        status: 201,
      })

      await caApi.generate(365)

      expect(axios.create().post).toHaveBeenCalledWith('/ca/generate', null, {
        params: { validity_days: 365 },
      })
    })

    it('uses the default ten-year validity when no param is provided', async () => {
      vi.mocked(axios.create().post).mockResolvedValueOnce({
        data: { id: 'ca_new' },
        status: 201,
      })

      await caApi.generate()

      expect(axios.create().post).toHaveBeenCalledWith('/ca/generate', null, {
        params: { validity_days: 3650 },
      })
    })
  })

  describe('list', () => {
    it('gets correct endpoint', async () => {
      vi.mocked(axios.create().get).mockResolvedValueOnce({
        data: { data: [], total: 0 },
        status: 200,
      })

      await caApi.list()

      expect(axios.create().get).toHaveBeenCalledWith('/ca/list')
    })
  })

  describe('download', () => {
    it('gets correct endpoint with blob response type', async () => {
      vi.mocked(axios.create().get).mockResolvedValueOnce({
        data: new Blob(['test cert']),
        status: 200,
      })

      await caApi.download()

      expect(axios.create().get).toHaveBeenCalledWith('/ca/download', {
        responseType: 'blob',
      })
    })
  })
})

describe('agentStatsApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('getStats', () => {
    it('gets correct endpoint', async () => {
      vi.mocked(axios.create().get).mockResolvedValueOnce({
        data: [],
        status: 200,
      })

      await agentStatsApi.getStats()

      expect(axios.create().get).toHaveBeenCalledWith('/stats/agents')
    })
  })

  describe('getDistribution', () => {
    it('gets correct endpoint', async () => {
      vi.mocked(axios.create().get).mockResolvedValueOnce({
        data: [],
        status: 200,
      })

      await agentStatsApi.getDistribution()

      expect(axios.create().get).toHaveBeenCalledWith('/stats/agents/distribution')
    })
  })

  describe('getUserDetail', () => {
    it('gets correct endpoint with user_id', async () => {
      const userId = 'user_001'

      vi.mocked(axios.create().get).mockResolvedValueOnce({
        data: [],
        status: 200,
      })

      await agentStatsApi.getUserDetail(userId)

      expect(axios.create().get).toHaveBeenCalledWith(`/audit/agents/user/${userId}`)
    })
  })

  describe('listSessions', () => {
    it('gets correct endpoint with params', async () => {
      vi.mocked(axios.create().get).mockResolvedValueOnce({
        data: [],
        status: 200,
      })

      await agentStatsApi.listSessions('claude-code', 'user_001', 10, 0)

      expect(axios.create().get).toHaveBeenCalledWith('/audit/agents/sessions', {
        params: {
          agent_type: 'claude-code',
          user_id: 'user_001',
          limit: 10,
          offset: 0,
        },
      })
    })
  })
})

// ---- T43: 新增 7 组 API client 测试 ----

describe('orgApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('listTeams calls GET /teams', async () => {
    const { orgApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: { data: [] }, status: 200 })
    await orgApi.listTeams()
    expect(axios.create().get).toHaveBeenCalledWith('/teams')
  })

  it('addMember calls POST /teams/:id/members with payload', async () => {
    const { orgApi } = await import('../services/api')
    vi.mocked(axios.create().post).mockResolvedValueOnce({ data: {}, status: 201 })
    await orgApi.addMember('team_01', { user_id: 'u1', role: 'member' })
    expect(axios.create().post).toHaveBeenCalledWith('/teams/team_01/members', { user_id: 'u1', role: 'member' })
  })

  it('removeMember calls DELETE /teams/:id/members/:userId', async () => {
    const { orgApi } = await import('../services/api')
    vi.mocked(axios.create().delete).mockResolvedValueOnce({ status: 204 })
    await orgApi.removeMember('team_01', 'u1')
    expect(axios.create().delete).toHaveBeenCalledWith('/teams/team_01/members/u1')
  })
})

describe('budgetApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('snapshot calls GET /budgets/snapshot with params', async () => {
    const { budgetApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: {}, status: 200 })
    await budgetApi.snapshot({ scope_type: 'project', scope_id: 'p1' })
    expect(axios.create().get).toHaveBeenCalledWith('/budgets/snapshot', { params: { scope_type: 'project', scope_id: 'p1' } })
  })

  it('pauseKey calls POST /budgets/keys/:prefix/pause', async () => {
    const { budgetApi } = await import('../services/api')
    vi.mocked(axios.create().post).mockResolvedValueOnce({ data: {}, status: 200 })
    await budgetApi.pauseKey('sk-abc', 'over budget')
    expect(axios.create().post).toHaveBeenCalledWith('/budgets/keys/sk-abc/pause', { reason: 'over budget' })
  })
})

describe('alertApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('inbox calls GET /alerts/inbox with unread param', async () => {
    const { alertApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: { data: [] }, status: 200 })
    await alertApi.inbox(true)
    expect(axios.create().get).toHaveBeenCalledWith('/alerts/inbox', { params: { unread: true } })
  })

  it('markRead calls POST /alerts/:id/read', async () => {
    const { alertApi } = await import('../services/api')
    vi.mocked(axios.create().post).mockResolvedValueOnce({ data: {}, status: 200 })
    await alertApi.markRead('alert_01')
    expect(axios.create().post).toHaveBeenCalledWith('/alerts/alert_01/read')
  })
})

describe('fxApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('current calls GET /fx/current', async () => {
    const { fxApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: { rate: 7.2 }, status: 200 })
    await fxApi.current()
    expect(axios.create().get).toHaveBeenCalledWith('/fx/current')
  })

  it('set calls PUT /fx with rate + effective_at', async () => {
    const { fxApi } = await import('../services/api')
    vi.mocked(axios.create().put).mockResolvedValueOnce({ data: {}, status: 200 })
    await fxApi.set({ rate: 7.25, effective_at: '2026-06-01' })
    expect(axios.create().put).toHaveBeenCalledWith('/fx', { rate: 7.25, effective_at: '2026-06-01' })
  })
})

// ---- P23: 4 组新 API client 测试 ----

describe('auditChainApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('verify calls POST /audit-chain/verify with params', async () => {
    const { auditChainApi } = await import('../services/api')
    vi.mocked(axios.create().post).mockResolvedValueOnce({ data: { ok: true }, status: 200 })
    await auditChainApi.verify({ from_seq: 1, to_seq: 100 })
    expect(axios.create().post).toHaveBeenCalledWith('/audit-chain/verify', null, {
      params: { from_seq: 1, to_seq: 100 },
    })
  })

  it('stats calls GET /audit-chain/stats', async () => {
    const { auditChainApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: { length: 50 }, status: 200 })
    await auditChainApi.stats()
    expect(axios.create().get).toHaveBeenCalledWith('/audit-chain/stats')
  })

  it('exportUrl returns correct download URL', async () => {
    const { auditChainApi } = await import('../services/api')
    const url = auditChainApi.exportUrl(1, 100)
    expect(url).toBe('/admin/v1/audit-chain/export?from=1&to=100&format=zip')
  })
})

describe('savingsConfigApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('get calls GET /savings/config', async () => {
    const { savingsConfigApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: { self_research_saving_monthly: 1000 }, status: 200 })
    await savingsConfigApi.get()
    expect(axios.create().get).toHaveBeenCalledWith('/savings/config')
  })

  it('set calls PUT /savings/config with payload', async () => {
    const { savingsConfigApi } = await import('../services/api')
    vi.mocked(axios.create().put).mockResolvedValueOnce({ data: {}, status: 200 })
    await savingsConfigApi.set({ self_research_saving_monthly: 5000, labor_hourly_rate: 150 })
    expect(axios.create().put).toHaveBeenCalledWith('/savings/config', {
      self_research_saving_monthly: 5000,
      labor_hourly_rate: 150,
    })
  })
})

describe('anomalyApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('list calls GET /anomalies with params', async () => {
    const { anomalyApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: { data: [] }, status: 200 })
    await anomalyApi.list({ range: '7d', dimension: 'absolute_spike' })
    expect(axios.create().get).toHaveBeenCalledWith('/anomalies', {
      params: { range: '7d', dimension: 'absolute_spike' },
    })
  })

  it('ack calls POST /anomalies/:id/ack', async () => {
    const { anomalyApi } = await import('../services/api')
    vi.mocked(axios.create().post).mockResolvedValueOnce({ data: {}, status: 200 })
    await anomalyApi.ack('anomaly_01')
    expect(axios.create().post).toHaveBeenCalledWith('/anomalies/anomaly_01/ack')
  })
})

describe('forecastApi', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('create calls POST /forecast/jobs with payload', async () => {
    const { forecastApi } = await import('../services/api')
    vi.mocked(axios.create().post).mockResolvedValueOnce({ data: { id: 'job_01' }, status: 201 })
    await forecastApi.create({ range_days: 30, quota_params: { monthly_budget_limit: 10000 } })
    expect(axios.create().post).toHaveBeenCalledWith('/forecast/jobs', {
      range_days: 30,
      quota_params: { monthly_budget_limit: 10000 },
    })
  })

  it('list calls GET /forecast/jobs', async () => {
    const { forecastApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: { data: [] }, status: 200 })
    await forecastApi.list()
    expect(axios.create().get).toHaveBeenCalledWith('/forecast/jobs')
  })

  it('get calls GET /forecast/jobs/:id', async () => {
    const { forecastApi } = await import('../services/api')
    vi.mocked(axios.create().get).mockResolvedValueOnce({ data: { id: 'job_01', status: 'done' }, status: 200 })
    await forecastApi.get('job_01')
    expect(axios.create().get).toHaveBeenCalledWith('/forecast/jobs/job_01')
  })
})
