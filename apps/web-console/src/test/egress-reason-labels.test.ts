import { describe, expect, it } from 'vitest'
import { GATEWAY_REASON_LABELS } from '../utils/gatewayReasonLabels'

describe('出站拦截与 git 口令的原因中文名', () => {
  it.each([
    'forward_proxy_internal_egress_denied',
    'forward_proxy_internal_egress_allowed',
    'reverse_proxy_internal_egress_denied',
    'mcp_upstream_internal_egress_denied',
    'mcp_upstream_egress_denied',
    'platform_egress_denied',
    'blocked_git_credential_dump',
  ])('%s 有中文名', (code) => {
    expect(GATEWAY_REASON_LABELS[code]).toMatch(/[一-龥]/)
  })
})
