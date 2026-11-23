import { describe, expect, it } from 'vitest'
import {
  agentGuardResolutionErrorMessage,
  agentGuardResolutionSuccessMessage,
} from '../pages/agentguard/confirmationMessages'

describe('W5 AgentGuard confirmation messages', () => {
  it('distinguishes a first approval under dual approval', () => {
    const done = agentGuardResolutionSuccessMessage(200)
    const half = agentGuardResolutionSuccessMessage(202)
    expect(half).not.toBe(done)
    expect(agentGuardResolutionSuccessMessage(undefined)).toBe(done)
  })

  it('maps approver errors from the control plane and falls back otherwise', () => {
    const err = (code: string) => ({ response: { status: 403, data: { error: { code } } } })
    const fallback = 'fallback-text'
    const self = agentGuardResolutionErrorMessage(err('confirmation_self_approval_forbidden'), fallback)
    const second = agentGuardResolutionErrorMessage(err('confirmation_second_approver_required'), fallback)
    expect(self).not.toBe(fallback)
    expect(second).not.toBe(fallback)
    expect(self).not.toBe(second)
    expect(agentGuardResolutionErrorMessage(err('internal_error'), fallback)).toBe(fallback)
    expect(agentGuardResolutionErrorMessage(new Error('boom'), fallback)).toBe(fallback)
  })
})
