import type { ControlBoundaryPath, ControlBoundaryReport } from '../../services/agentEndpoint.types'

export const CONTROL_BOUNDARY_SCHEMA = 'jjdguard-control-boundary/v1'
export const notReportedText = '未上报 · 失效行为未知'
export const notReportedDetail = '该端点的 hookd 未在心跳中上报控制边界（版本早于该能力，或尚未完成首次心跳）。在上报前，无法判断宿主在 hookd 不可用或判定超时时是放行还是阻断。'

export const behaviorLabels: Record<string, { text: string; color: string }> = {
  fail_open: { text: '失效放行', color: 'orange' },
  fail_closed: { text: '失效阻断', color: 'green' },
  no_pre_tool_gate: { text: '无前置拦截', color: 'default' },
}
export const triggerLabels: Record<string, string> = {
  hookd_unavailable_launch_failure_or_host_timeout: 'hookd 不可用、启动失败或宿主超时',
  hookd_unavailable_timeout_or_invalid_output: 'hookd 不可用、超时或输出无效',
  hookd_input_parse_error_non_strict: 'hookd 输入解析失败（非严格）',
  hookd_input_parse_error_strict: 'hookd 输入解析失败（严格）',
  hookd_state_revoked_config_or_identity_unavailable: '端点已吊销，或配置、身份不可用',
  server_decide_unavailable_or_timeout: '服务端判定不可用或超时',
  trusted_authorization_unavailable_or_timeout: '可信授权不可用或超时',
  before_handshake_failure_or_timeout: '模式握手失败或超时',
  after_handshake_failure_strict: '握手后调用失败（严格）',
  after_handshake_failure_non_strict: '握手后调用失败（非严格）',
  after_tool_call_legacy_path: '旧版 after_tool_call 路径',
  t15_approval_required_action: '需审批动作（宿主无法等待）',
  any_tool_call: '任意工具调用',
}
export const uncontrolledLabels: Record<string, string> = {
  plugin_removed_or_disabled: '插件被移除或禁用',
  hosts_without_installed_hook: '未安装钩子的宿主',
  other_plugins_and_custom_tools: '其他插件与自定义工具',
  shell_child_processes: 'Shell 子进程',
  direct_mcp_clients: '直连 MCP 客户端',
  direct_network_clients: '直连网络客户端',
}
export const decideFailModeLabels: Record<string, string> = {
  open: '放行',
  closed_for_block_mode: '阻断模式下阻断，其余放行',
}

export const yesNo = (value: unknown) => (value === true ? '是' : value === false ? '否' : '未知')

/** Returns the report only when it is an object carrying the v1 schema. */
export function readControlBoundary(value: unknown): ControlBoundaryReport | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const report = value as ControlBoundaryReport
  return report.schema === CONTROL_BOUNDARY_SCHEMA ? report : null
}

export interface ControlBoundaryRow extends ControlBoundaryPath { key: string; host: string; pre_tool_gate: boolean }

export function controlBoundaryRows(report: ControlBoundaryReport): ControlBoundaryRow[] {
  const hosts = report.hosts && typeof report.hosts === 'object' ? report.hosts : {}
  return Object.keys(hosts).sort().flatMap(host => {
    const entry = hosts[host]
    const paths = Array.isArray(entry?.paths) ? entry.paths : []
    return paths.map((path, index) => ({ ...path, key: `${host}:${index}`, host, pre_tool_gate: entry?.pre_tool_gate === true }))
  })
}
