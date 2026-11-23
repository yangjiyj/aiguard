import { normalizeGatewayBase } from './gatewayAccess'

// 网关默认的明文 HTTP 端口：8080 是模型 API，8082 是正向代理，3000 是控制台的明文入口。
// 这些端口前面没有 TLS，客户端写成 https:// 只会得到 “wrong version number” 之类用户看不懂的错误。
export const PLAINTEXT_GATEWAY_PORTS = [8080, 8082, 3000] as const

export type ClientBaseUrls = { openai: string; anthropic: string }

/**
 * 由「对外调用地址」推出两类协议各自正确的客户端 Base URL：
 * - OpenAI 协议（Codex、Cherry Studio 等）的 base_url 要带一层 /v1；
 * - Anthropic 协议（Claude Code 等）的客户端会自己拼 /v1/messages，所以不能带 /v1。
 * 配置里重复的 /v1 会先合并成一层。地址为空或不合法时返回空串，不猜测端口。
 */
export function clientBaseUrls(configured: unknown): ClientBaseUrls {
  const openai = normalizeGatewayBase(configured)
  if (!openai) return { openai: '', anthropic: '' }
  return { openai, anthropic: openai.replace(/\/v1$/, '') }
}

/** 原始输入的路径末尾是否重复写了 /v1（大小写不敏感，只看末尾连续的 v1 段）。 */
function hasDuplicateV1Suffix(url: URL): boolean {
  const segments = url.pathname.split('/').filter(Boolean)
  return segments.length >= 2 && segments[segments.length - 1].toLowerCase() === 'v1' && segments[segments.length - 2].toLowerCase() === 'v1'
}

/**
 * 检查管理员填写的原始地址里的两类常见错误，返回给用户看的中文提示（没有问题时为空数组）：
 * 1. https:// 配到了网关的明文 HTTP 端口；
 * 2. 路径里重复写了 /v1。
 * 非字符串或无法解析的输入不报错，直接视为没有可提示的内容。
 */
export function gatewayAddressRisks(raw: unknown): string[] {
  if (typeof raw !== 'string' || !raw.trim()) return []
  let url: URL
  try { url = new URL(raw.trim()) } catch { return [] }
  const risks: string[] = []
  const port = Number(url.port)
  if (url.protocol === 'https:' && (PLAINTEXT_GATEWAY_PORTS as readonly number[]).includes(port)) {
    risks.push(`当前地址使用 https，但端口 ${port} 通常是网关的明文 HTTP 端口，客户端会报 TLS 握手错误。请改成 http://，或确认该端口前面已配置 TLS 后再使用。`)
  }
  if (hasDuplicateV1Suffix(url)) {
    risks.push('地址里重复写了 /v1，客户端会请求 /v1/v1/...，网关会返回 404 并提示多了一层 /v1。请只保留一层 /v1（Anthropic 协议客户端则不带 /v1）。')
  }
  return risks
}
