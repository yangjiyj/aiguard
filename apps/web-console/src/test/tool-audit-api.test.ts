import { describe, expect, it, vi } from 'vitest'
import { apiClient, toolAuditApi } from '../services/api'

describe('toolAuditApi', () => {
  it('sends linked decision and server filters as HTTP query parameters', async () => {
    const signal = new AbortController().signal
    const get = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: {} } as any)

    await toolAuditApi.listHighRisk({
      raw_decision: 'confirm',
      effective_decision: 'audit',
      server: 'filesystem',
      limit: 20,
      offset: 40,
      signal,
    })

    expect(get).toHaveBeenCalledWith('/audit/tools/high-risk', {
      params: {
        raw_decision: 'confirm',
        effective_decision: 'audit',
        server: 'filesystem',
        limit: 20,
        offset: 40,
      },
      signal,
    })
    get.mockRestore()
  })
})
