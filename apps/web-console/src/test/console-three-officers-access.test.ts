import { describe, expect, it } from 'vitest'
import { isConsoleRole } from '../utils/consoleAccess'
import { canAccessPath, canSeeMenuItem, roleHome, PAGE_ACCESS } from '../utils/access'

// SoD 项：三员（系统管理员、安全保密管理员、审计员）都是控制台角色。后端登录放开之后，前端的控制台角色闸门
// 也必须认三员，否则登录成功会被前端立刻判成「需要管理员身份」。放开的只是「能进来」；进来后每个人看到的菜单与能打开的
// 页面仍完全由 PAGE_ACCESS 按角色裁剪，两个官员不能因此看到对方的页面。

describe('控制台角色闸门（三员分立）', () => {
  it('三员与租户管理员都是控制台角色', () => {
    for (const role of ['platform_admin', 'admin', 'security_officer', 'auditor', 'tenant_admin', 'tenant_owner']) {
      expect(isConsoleRole(role), role).toBe(true)
    }
  })

  it('员工与业务角色仍不是控制台角色', () => {
    for (const role of ['chat_user', 'developer', 'viewer', 'dept_manager', 'operator', 'platform_connector', '', undefined]) {
      expect(isConsoleRole(role as string | undefined), String(role)).toBe(false)
    }
  })

  it('前后端对「谁能登录控制台」使用同一份角色清单', () => {
    // 后端 roles.CanLoginConsole：platform_admin、security_officer、auditor、tenant_admin、admin、tenant_owner
    const backend = ['platform_admin', 'security_officer', 'auditor', 'tenant_admin', 'admin', 'tenant_owner'].sort()
    const frontend = ['platform_admin', 'security_officer', 'auditor', 'tenant_admin', 'admin', 'tenant_owner', 'chat_user', 'developer', 'viewer', 'dept_manager', 'operator']
      .filter((r) => isConsoleRole(r)).sort()
    expect(frontend).toEqual(backend)
  })
})

describe('三员登录后的菜单与路由裁剪', () => {
  const officerOnly = {
    security_officer: ['/mcp-gateway/policies', '/mcp-gateway/servers', '/mcp-gateway/approvals', '/security/policies', '/security/tool-config', '/security/agents', '/security/corpus-scan'],
    auditor: ['/system/audit-operations', '/audit/login-history'],
  }

  it('安全员能进 MCP 策略/服务/审批与安全策略页', () => {
    for (const path of officerOnly.security_officer) expect(canAccessPath('security_officer', path), path).toBe(true)
  })

  it('安全员不能进用户、系统设置、审计操作、登录历史、密钥', () => {
    for (const path of ['/users', '/system/settings', '/system/audit-operations', '/audit/login-history', '/keys', '/system/license']) {
      expect(canAccessPath('security_officer', path), path).toBe(false)
      expect(canSeeMenuItem('security_officer', path), path).toBe(false)
    }
  })

  it('审计员能读审计与 MCP 调用审计，但进不了任何策略页或 MCP 管理页', () => {
    for (const path of ['/system/audit-operations', '/audit/login-history', '/mcp-gateway/audit']) expect(canAccessPath('auditor', path), path).toBe(true)
    for (const path of ['/mcp-gateway/policies', '/mcp-gateway/servers', '/mcp-gateway/approvals', '/security/policies', '/security/tool-config', '/security/agents', '/security/corpus-scan', '/users', '/system/settings', '/keys']) {
      expect(canAccessPath('auditor', path), path).toBe(false)
      expect(canSeeMenuItem('auditor', path), path).toBe(false)
    }
  })

  it('两个官员都进不了业务与计费页', () => {
    for (const role of ['security_officer', 'auditor']) {
      for (const path of ['/dashboard', '/usage', '/cost/records']) expect(canAccessPath(role, path), `${role} ${path}`).toBe(false)
    }
  })

  it('每位官员的落地页对自己是可访问的（不会登录后陷入重定向循环）', () => {
    for (const role of ['security_officer', 'auditor']) {
      expect(canAccessPath(role, roleHome(role)), `${role} -> ${roleHome(role)}`).toBe(true)
    }
  })

  it('PAGE_ACCESS 里没有任何页面把「chat_user」之类的非控制台角色放行', () => {
    for (const [path, roles] of Object.entries(PAGE_ACCESS)) {
      for (const r of roles) if (['chat_user', 'operator', 'platform_connector'].includes(r)) throw new Error(`${path} 放行了 ${r}`)
    }
  })
})
