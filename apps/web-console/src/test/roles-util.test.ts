import { describe, expect, it } from 'vitest'
import {
  PLATFORM_ROLE_OPTIONS,
  DEFAULT_PLATFORM_ROLE,
  platformRoleMeta,
  platformRoleLabel,
  normalizeSystemRole,
  systemRoleLabel,
} from '../utils/roles'

describe('平台角色（users.role）权威取值', () => {
  it('创建/编辑下拉只提供权威 8 值，普通用户仅 Chat 为默认', () => {
    expect(PLATFORM_ROLE_OPTIONS.map(o => o.value)).toEqual([
      'platform_admin',
      'security_officer',
      'auditor',
      'tenant_admin',
      'dept_manager',
      'developer',
      'viewer',
      'chat_user',
    ])
    expect(DEFAULT_PLATFORM_ROLE).toBe('chat_user')
    expect(platformRoleLabel('chat_user')).toBe('普通用户（仅 Chat）')
    // 旧的非法取值不得出现在下拉里
    const values = PLATFORM_ROLE_OPTIONS.map(o => o.value)
    expect(values).not.toContain('admin')
    expect(values).not.toContain('operator')
    // label 全中文
    for (const o of PLATFORM_ROLE_OPTIONS) {
      expect(o.label).toMatch(/[一-龥]/)
    }
  })

  it('权威角色渲染中文 label', () => {
    expect(platformRoleLabel('platform_admin')).toBe('平台管理员')
    expect(platformRoleLabel('tenant_admin')).toBe('租户管理员')
    expect(platformRoleLabel('dept_manager')).toBe('部门主管（只读）')
    expect(platformRoleLabel('developer')).toBe('开发者')
    expect(platformRoleLabel('viewer')).toBe('只读')
    expect(platformRoleLabel('security_officer')).toBe('安全保密管理员')
    expect(platformRoleLabel('auditor')).toBe('审计员')
  })

  it('历史遗留取值也回显中文（不露原始英文）', () => {
    expect(platformRoleLabel('operator')).toContain('历史')
    expect(platformRoleLabel('admin')).toContain('历史')
    expect(platformRoleLabel('auditor')).not.toContain('历史')
    // 任何取值都不返回原始英文枚举
    expect(platformRoleLabel('operator')).not.toBe('operator')
  })

  it('完全未知的取值回退为中文占位，绝不露英文', () => {
    expect(platformRoleLabel('whatever_x')).toBe('未知角色')
    expect(platformRoleLabel(undefined)).toBe('未设置')
    expect(platformRoleMeta('platform_admin').color).toBeTruthy()
  })
})

describe('system_roles（scoped RBAC 角色）归一', () => {
  it('兼容 Go 结构体大写键，优先用 description 作为中文 label', () => {
    const r = normalizeSystemRole({ Code: 'auditor', Name: 'auditor', Description: '审计员（只读+导出）' })
    expect(r.code).toBe('auditor')
    expect(r.label).toBe('审计员（只读+导出）')
  })

  it('兼容 snake_case 键', () => {
    const r = normalizeSystemRole({ code: 'team_owner', name: 'team_owner', description: '' })
    expect(r.code).toBe('team_owner')
    // description 为空时回退到内置中文名，而不是英文 code
    expect(r.label).toBe('部门管理员')
  })

  it('systemRoleLabel 优先用动态映射，其次内置中文，最后才是 code', () => {
    expect(systemRoleLabel('auditor', { auditor: '审计专员' })).toBe('审计专员')
    expect(systemRoleLabel('project_viewer')).toBe('应用观察者')
    expect(systemRoleLabel(undefined)).toBe('-')
  })
})
