export type AgentDetectionInfo = {
  label: string
  color: string
  coverage: string
}

export type AgentDefinition = {
  type: string
  label: string
  vendor: string
  color: string
}

import generatedAgentDefinitions from '../generated/agent-definitions.json'

export const AGENT_DEFINITIONS: AgentDefinition[] = generatedAgentDefinitions

export const AGENT_LABELS = Object.fromEntries(AGENT_DEFINITIONS.map((agent) => [agent.type, agent.label])) as Record<string, string>
export const AGENT_COLORS = Object.fromEntries(AGENT_DEFINITIONS.map((agent) => [agent.type, agent.color])) as Record<string, string>
export const KNOWN_AGENT_TYPES = new Set(AGENT_DEFINITIONS.map((agent) => agent.type))

export const formatAgentType = (value?: string) => AGENT_LABELS[value || ''] || value || '未知智能体'
export const getAgentColor = (value?: string) => AGENT_COLORS[value || ''] || 'var(--chart-1)'
export const isKnownAgentType = (value?: string) => Boolean(value && KNOWN_AGENT_TYPES.has(value))

export const getAgentDetection = (agentType?: string): AgentDetectionInfo => {
  if (agentType === 'agent-tool-call') {
    return {
      label: '工具调用迹象推断',
      color: 'orange',
      coverage: '仅确认经过网关的模型请求存在工具调用记录，不代表已采集脚本内部行为。',
    }
  }
  if (isKnownAgentType(agentType)) {
    return {
      label: '客户端标识/特征识别',
      color: 'green',
      coverage: '覆盖模型请求、内容审计、Token 用量和网关可见的工具调用摘要。',
    }
  }
  return {
    label: '自报名称 · 客户端待确认',
    color: 'blue',
    coverage: '此名称尚未映射到已知客户端。查看原始识别依据后，可由管理员确认或登记接入。',
  }
}

export const agentSourceLabel = (source: string) => ({
 explicit_header: '自报请求头', client_header: '客户端请求头', user_agent: 'User-Agent 特征',
 user_agent_runtime: '运行环境特征', content: '协议/内容特征',
 product_identity: '客户端产品标识', message_protocol: '消息协议特征', manual_confirmation: '人工确认', registered_identity: '接入登记', unrecorded: '未留存识别依据',
}[source] || source || '未留存识别依据')
