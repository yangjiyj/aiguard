import type { AlertOccurrence } from '../services/alertOccurrences'
import { upstreamPrincipalLabel } from './risk'
import { formatAgentType } from './agents'

// Account attribution is a display label, not the case grouping key or proof
// that a credential owner personally operated every request.
export const alertAccountName = (item: AlertOccurrence) => item.actor_name?.trim() || item.key_owner_name?.trim() || ''
export const alertIdentityLabel = (item: AlertOccurrence) => alertAccountName(item) || item.source_ip?.trim() || '账户与来源 IP 未记录'
export const alertIdentityBasis = (item: AlertOccurrence) => item.actor_name?.trim()
  ? item.identity_reliability === 'authenticated' ? '已认证账户' : '请求记录账户'
  : item.key_owner_name?.trim() ? '凭据绑定账户' : item.source_ip?.trim() ? '来源 IP' : '账户与来源 IP 未记录'
export const alertCredentialLabel = (item: AlertOccurrence) => item.credential_name?.trim() || item.credential_id?.trim() || upstreamPrincipalLabel(item.principal_key) || '未记录'
const transports: Record<string, string> = {
  forward: '正向代理', outbound: '正向代理', reverse: '反向代理', backward: '反向代理', inbound: '反向代理',
  chat_completion: 'API 接入', responses: 'API 接入', completion: 'API 接入', embeddings: 'API 接入', api: 'API 接入',
}
// These are recorded web-product IDs from the adapter catalog; API products
// (for example deepseek_api) remain distinct. Never classify from target host.
const webProducts = new Set(['chatgpt', 'claude', 'gemini', 'deepseek_chat', 'qwen_chat', 'doubao', 'yuanbao', 'kimi', 'grok', 'copilot', 'poe', 'chatglm', 'wenxin_yiyan'])
const usages: Record<string, string> = { llm: '大模型访问', normal_public: '普通公网访问', unknown_ai_candidate: '待识别 AI 访问', web: '网页 AI', web_ai: '网页 AI', ai_web: '网页 AI', ai_ide: 'AI 编程工具', api: 'API 调用', ai_api: 'API 调用' }
export const alertConnectionLabel = (item: AlertOccurrence) => {
  let transport = transports[item.access_direction]
  const keyBound = item.identity_source === 'api_key' || Boolean(item.credential_id || item.credential_name)
  if ((!transport || transport === 'API 接入') && keyBound) transport = 'API Key 接入'
  const usage = item.access_type === 'llm' && webProducts.has(item.client_product || '') ? '网页 AI' : usages[item.access_type || '']
  return [transport, usage].filter(Boolean).join(' · ') || '接入方式未记录'
}
const products: Record<string, string> = { codebuddy: '腾讯 CodeBuddy', cursor: 'Cursor', cursor_agent: 'Cursor', chatgpt: 'ChatGPT', claude: 'Claude', doubao: '豆包', deepseek: 'DeepSeek', deepseek_chat: 'DeepSeek Chat', deepseek_api: 'DeepSeek API', gemini: 'Gemini', qwen_chat: '通义千问', yuanbao: '腾讯元宝', kimi: 'Kimi', grok: 'Grok', copilot: 'Microsoft Copilot' }
export const alertClientLabel = (item: AlertOccurrence) => {
  const product = item.client_product?.trim()
  return product ? products[product] || product : item.agent_type ? formatAgentType(item.agent_type) : '未记录'
}
export const alertIdentityDetails = (item: AlertOccurrence) => [
  { label: '用户账户', children: alertAccountName(item) || '未关联账户，按来源 IP 展示' },
  { label: '来源 IP', children: item.source_ip || '未记录' },
  { label: '接入方式', children: alertConnectionLabel(item) },
  { label: '客户端 / 应用', children: alertClientLabel(item) },
  { label: '接入凭据', children: alertCredentialLabel(item) },
]

// 来源一句话：把"谁、用什么、从哪来、到哪去"合成一句人话，而不是给一排"未记录"。
// 只陈述已记录的事实；缺的项单独列出并给出下一步，绝不编造或用"未记录"充数。
export type AlertOrigin = { sentence: string; missing: string[] }
const directionLabel: Record<string, string> = { forward: '正向代理', outbound: '正向代理', reverse: '反向代理', backward: '反向代理', inbound: '反向代理' }
export const alertOriginSummary = (item: AlertOccurrence): AlertOrigin => {
  const account = alertAccountName(item)
  const ip = item.source_ip?.trim()
  const client = item.client_product?.trim() ? alertClientLabel(item) : item.agent_type ? formatAgentType(item.agent_type) : ''
  const direction = directionLabel[item.access_direction] || ''
  const host = item.target_host?.trim() && !item.target_host.startsWith('model_') ? item.target_host.trim() : ''
  const credential = item.credential_name?.trim()
  const who = account || (client && ip ? `${client}（${ip}）` : client || ip || '')
  const parts = [
    who ? `来自 ${who}` : '',
    account && client ? `使用 ${client}` : '',
    direction ? `经${direction}` : '',
    host ? `访问 ${host}` : '',
    credential ? `凭据「${credential}」` : '',
  ].filter(Boolean)
  const missing: string[] = []
  if (!ip) missing.push('来源 IP 未被记录')
  if (!account && !credential) missing.push('没有关联到具体账户或接入凭据，请用请求编号到「请求留存」核对')
  if (!client) missing.push('客户端类型未识别')
  return { sentence: parts.length ? parts.join('，') : '', missing }
}
