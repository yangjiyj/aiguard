import { fireEvent, screen } from '@testing-library/react'
import type { ProtectionSettingItem } from '../services/api'

export function last<T>(items: T[]): T {
  return items[items.length - 1]
}

// antd Select：展开下拉后点选项文字。
export async function chooseOption(combobox: HTMLElement, label: string) {
  fireEvent.mouseDown(combobox)
  const options = await screen.findAllByText(label, { selector: '.ant-select-item-option-content' })
  fireEvent.click(options[options.length - 1])
}

const RACB: ProtectionSettingItem['actions'] = ['record', 'alert_allow', 'confirm', 'block']

export function protectionItem(key: string, group: string, label: string, overrides: Partial<ProtectionSettingItem> = {}): ProtectionSettingItem {
  return {
    key,
    group,
    label,
    actions: RACB,
    default_action: 'alert_allow',
    action: 'alert_allow',
    configured: false,
    params: {},
    param_specs: [],
    updated_by: '',
    updated_at: null,
    ...overrides,
  }
}

export const PROTECTION_ITEMS: ProtectionSettingItem[] = [
  protectionItem('agent.cloud_metadata', 'agent_target', '云元数据地址'),
  protectionItem('agent.ssh_private_key', 'agent_target', 'SSH 私钥'),
  protectionItem('agent.high_risk_without_rule', 'agent_fallback', '未配置规则的高风险调用'),
  protectionItem('agent.tool_failure_loop', 'agent_fallback', '工具连续失败', {
    param_specs: [
      { key: 'window_seconds', label: '窗口（秒）', kind: 'int', default: 600, min: 10, max: 86400 },
      { key: 'threshold', label: '次数', kind: 'int', default: 5, min: 2, max: 1000 },
    ],
  }),
  protectionItem('agent.identity_rejected', 'agent_fallback', '调用身份异常', {
    param_specs: [{ key: 'trusted_agent_types', label: '可信客户端', kind: 'string_list', default: [] }],
  }),
  protectionItem('endpoint.local_rule', 'endpoint', '端侧本地规则'),
  protectionItem('skill.identity_invalid', 'skill', 'Skill 身份异常'),
  protectionItem('skill.dangerous_command', 'skill', 'Skill 参数含危险命令'),
  protectionItem('skill.admission_unavailable', 'skill', '准入服务不可用'),
  protectionItem('mcp.admission', 'mcp', '未准入的 MCP 服务'),
  protectionItem('mcp.scan_timeout', 'mcp', '扫描超时', {
    param_specs: [{ key: 'timeout_seconds', label: '超时（秒）', kind: 'int', default: 5, min: 1, max: 60 }],
  }),
]
