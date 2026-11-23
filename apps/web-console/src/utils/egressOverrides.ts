import type { EgressOverrides } from '../services/api'

// 对象级出站放行写回时补齐布尔值；只有 MCP 服务带证书与重定向三项。
export function normalizeEgressOverrides(value: EgressOverrides | undefined, includeMcp = false): EgressOverrides {
  const out: EgressOverrides = {
    allow_loopback: Boolean(value?.allow_loopback),
    allow_link_local: Boolean(value?.allow_link_local),
    allow_metadata: Boolean(value?.allow_metadata),
    allow_internal_hostnames: Boolean(value?.allow_internal_hostnames),
  }
  if (includeMcp) {
    out.allow_same_host_redirect = Boolean(value?.allow_same_host_redirect)
    out.insecure_skip_verify = Boolean(value?.insecure_skip_verify)
    out.trusted_ca_pem = String(value?.trusted_ca_pem ?? '').trim()
  }
  return out
}
