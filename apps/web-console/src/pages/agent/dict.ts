import { severityOptions } from '../../utils/risk'

export type Option = { value: string; label: string }
export const products: Option[] = [
  ['claude-code','Claude Code'],['openclaw','OpenClaw'],['opencode','OpenCode'],['hermes','Hermes'],['codex','Codex'],['cursor','Cursor'],['vscode','VS Code'],['python-sdk','Python 开发包'],['dify','Dify'],['other','其他产品'],
].map(([value, label]) => ({ value, label }))
export const modes: Option[] = [{value:'monitor',label:'监控'}, {value:'would_block',label:'收敛'}, {value:'block',label:'阻断'}]
export const captureLevels: Option[] = [{value:'metadata',label:'元数据'}, {value:'summary',label:'摘要'}, {value:'full',label:'完整内容'}]
export const endpointStatuses: Option[] = [{value:'active',label:'在线'}, {value:'stale',label:'陈旧'}, {value:'offline',label:'离线'}, {value:'revoked',label:'已吊销'}]
export const sessionStatuses: Option[] = [{value:'active',label:'进行中'}, {value:'ended',label:'已结束'}]
export const eventTypes: Option[] = [
  ['session.start','会话开始'],['session.end','会话结束'],['turn.start','轮次开始'],['turn.end','轮次结束'],
  ['tool.pre','工具调用前'],['tool.post','工具调用后'],['tool.failure','工具调用失败'],['tool.denied','工具调用被拒绝'],['permission.request','权限请求'],
  ['subagent.start','子智能体启动'],['subagent.stop','子智能体停止'],['config.change','配置变更'],['instructions.loaded','指令文件加载'],
  ['context.compact','上下文压缩'],['asset.snapshot','资产快照'],['adapter.health','适配器健康'],
].map(([value, label]) => ({value,label}))
export const toolTypes: Option[] = [
  ['system','系统命令'],['file','文件操作'],['network','网络请求'],['database','数据库操作'],['mcp','MCP 调用'],
  ['skill','技能调用'],['agent','智能体调用'],['browser','浏览器操作'],['other','其他工具'],
].map(([value,label]) => ({value,label}))
export const decisions: Option[] = [{value:'allow',label:'放行'}, {value:'audit',label:'审计'}, {value:'confirm',label:'人工确认'}, {value:'block',label:'阻断'}]
export const risks: Option[] = severityOptions(['low', 'medium', 'high', 'critical'])
export const startSources: Option[] = [{value:'startup',label:'启动'}, {value:'resume',label:'恢复'}, {value:'clear',label:'清空重启'}, {value:'compact',label:'压缩恢复'}, {value:'fork',label:'分叉'}]
export const endReasons: Option[] = [{value:'user',label:'用户结束'}, {value:'exit',label:'正常退出'}, {value:'error',label:'异常结束'}, {value:'timeout',label:'超时'}, {value:'unknown',label:'原因未记录'}]
export const stopReasons: Option[] = [{value:'end_turn',label:'轮次完成'}, {value:'tool_use',label:'工具调用'}, {value:'max_tokens',label:'达到生成上限'}, {value:'stop_sequence',label:'停止序列'}, {value:'error',label:'异常停止'}]
export const deniedBy: Option[] = [{value:'user',label:'用户拒绝'}, {value:'hook',label:'端侧阻断'}, {value:'policy',label:'策略阻断'}, {value:'unknown',label:'来源未知'}]
export const assetTypes: Option[] = [
  ['model','模型'],['mcp_server','MCP 服务'],['mcp_tool','MCP 工具'],['skill','技能'],['plugin','插件'],['instruction_file','指令文件'],['hook','钩子'],['config','配置'],
].map(([value,label]) => ({value,label}))
export const sources: Option[] = [{value:'endpoint',label:'端侧 Hook'}, {value:'gateway',label:'网关'}, {value:'both',label:'双视角'}, {value:'hook',label:'端侧 Hook'}]
export const modeColors: Record<string, string> = {monitor:'blue',would_block:'gold',block:'red'}
export const riskColors: Record<string,string> = {low:'green',medium:'orange',high:'red',critical:'magenta'}
export const decisionColors: Record<string,string> = {allow:'green',audit:'blue',confirm:'orange',block:'red'}
export function label(options: Option[], value?: string | null): string {
  if (!value) return '未记录'
  return options.find(item => item.value === value)?.label ?? '未识别'
}
export function time(value?: string | null): string { return value ? new Date(value).toLocaleString('zh-CN', {hour12:false}) : '未记录' }
export function endpointState(status: string, heartbeat: string | null): string {
  if (status === 'revoked') return 'revoked'
  if (status !== 'active' || !heartbeat) return 'offline'
  const age = Date.now() - Date.parse(heartbeat)
  if (age > 15 * 60_000) return 'stale'
  return 'active'
}
export const canReadAgent = (role?: string) => ['platform_admin','tenant_owner','tenant_admin','admin','auditor'].includes(role ?? '')
export const canWriteAgent = (role?: string) => ['platform_admin','tenant_owner','tenant_admin','admin'].includes(role ?? '')
