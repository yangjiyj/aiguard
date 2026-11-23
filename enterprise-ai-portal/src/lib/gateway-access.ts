export type GatewayEndpoint = { name: string; url: string; source?: 'current' | 'default' | 'custom' }
export type GatewayAccessSettings = { gateway_public_base_url?: unknown; gateway_public_endpoints?: unknown; gateway_public_url_mode?: unknown }

const hasControlCharacters = (value: string) => Array.from(value).some(char => { const code = char.charCodeAt(0); return code < 32 || (code >= 127 && code <= 159) })

export function normalizeGatewayBase(value: unknown): string {
  if (typeof value !== 'string') return ''
  const raw = value.trim()
  if (!raw || raw.length > 2048 || /[\\?#]/.test(raw) || hasControlCharacters(raw)) return ''
  try {
    const path = raw.replace(/^https?:\/\/[^/]+/i, '').split('/')
    if (path.some(p => ['.', '..'].includes(decodeURIComponent(p)) || hasControlCharacters(decodeURIComponent(p))) || /%(?:2f|5c|25)/i.test(raw)) return ''
    const url = new URL(raw)
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash || ['0.0.0.0', '[::]'].includes(url.hostname) || url.port === '0') return ''
    const parts = url.pathname.split('/').filter(Boolean)
    while (parts[parts.length - 1]?.toLowerCase() === 'v1') parts.pop()
    parts.push('v1')
    url.pathname = '/' + parts.join('/')
    return url.toString().replace(/\/$/, '')
  } catch { return '' }
}

export function parseGatewayEndpoints(value: unknown): GatewayEndpoint[] {
  try {
    const entries: unknown = typeof value === 'string' ? JSON.parse(value) : value
    if (!Array.isArray(entries)) return []
    const result: GatewayEndpoint[] = []
    for (const entry of entries.slice(0, 20)) {
      if (!entry || typeof entry.name !== 'string' || !entry.name.trim() || entry.name.length > 80) continue
      const url = normalizeGatewayBase(entry.url)
      if (url && !result.some(e => e.url === url)) result.push({ name: entry.name.trim(), url, source: 'custom' })
    }
    return result
  } catch { return [] }
}

export function gatewayAccessOptions(settings: GatewayAccessSettings = {}, currentOrigin = ''): GatewayEndpoint[] {
  const configured = normalizeGatewayBase(settings.gateway_public_base_url)
  const endpoints = [...(configured ? [{ name: '默认地址', url: configured, source: 'default' as const }] : []), ...parseGatewayEndpoints(settings.gateway_public_endpoints)]
  let current = normalizeGatewayBase(currentOrigin)
  const followsHost = settings.gateway_public_url_mode === 'current_host' && Boolean(configured)
  if (current && followsHost) {
    // The console's TLS scheme and port do not describe the model listener.
    const api = new URL(configured)
    api.hostname = new URL(current).hostname
    current = normalizeGatewayBase(api.toString())
  }
  const match = !followsHost && current && endpoints.find(e => new URL(e.url).origin === new URL(current).origin)
  const result: GatewayEndpoint[] = current ? [{ name: followsHost ? '当前调用地址' : '当前访问入口', url: match ? match.url : current, source: 'current' }] : []
  for (const entry of endpoints) if (!result.some(e => e.url === entry.url)) result.push(entry)
  return result
}

export function chooseGatewayEndpoint(options: GatewayEndpoint[], settings: GatewayAccessSettings = {}, preferred = ''): string {
  if (options.some(e => e.url === preferred)) return preferred
  const configured = normalizeGatewayBase(settings.gateway_public_base_url)
  if (settings.gateway_public_url_mode === 'configured' && options.some(e => e.url === configured)) return configured
  return options[0]?.url || ''
}

export function inspectGatewayResponse(status: number, body: unknown): { ok: boolean; message: string } {
  const value = body as { error?: { code?: string; type?: string }; data?: unknown[]; object?: string } | null
  if (status === 401 && value?.error?.code === 'unauthorized') return { ok: true, message: '当前浏览器已连接到网关模型接口；调用时请使用网关 API Key。其他客户端还需信任 HTTPS 证书。' }
  if (status === 200 && Array.isArray(value?.data)) return { ok: true, message: '当前浏览器可以访问模型接口。其他客户端仍需检查网络和证书信任。' }
  if (value?.error?.type === 'new_api_error') return { ok: false, message: '入口连接到了上游或代理接口，请管理员检查 /v1 的转发目标。' }
  return { ok: false, message: `该地址未返回预期的网关模型接口（HTTP ${status}），请检查转发路径。` }
}
