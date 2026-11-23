import { describe, expect, it } from 'vitest'
import { getStatusSourceLabel } from '../utils/statusSource'

// 智能体风险总览“配置意图”的来源与控制面 executionmode 判定一一对应。
describe('配置意图来源标签', () => {
  it('每种执行模式来源都有中文标签', () => {
    expect(getStatusSourceLabel('system_settings.security_execution_mode')).toBe('控制台设置')
    expect(getStatusSourceLabel('deployment')).toBe('部署变量')
    expect(getStatusSourceLabel('system_settings.security_audit_only')).toBe('系统安全设置')
    expect(getStatusSourceLabel('safe_default')).toBe('默认值')
    expect(getStatusSourceLabel('settings_unavailable')).toBe('读取失败')
    expect(getStatusSourceLabel('runtime_status_unavailable')).toBe('执行热路径状态未上报')
    expect(getStatusSourceLabel('something_else')).toBe('状态来源未识别')
  })
})
