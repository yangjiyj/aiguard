import { describe, expect, it } from 'vitest'
import { PAGE_ACCESS, canAccessPath, canSeeMenuItem, roleHome } from '../utils/access'

// W4 three-officer separation of duties: presentation-layer access table.
const AUDIT_PAGES = ['/system/audit-operations', '/audit/login-history']
const EVIDENCE_PAGES = ['/audit/access-retention', '/compliance/overview']
const SYSTEM_PAGES = ['/users', '/keys', '/system/settings', '/system/license', '/providers', '/models']

describe('W4 access table', () => {
  it.each(['platform_admin', 'admin'])('%s can read audit and evidence pages under the 2026-10-01 SoD contract', (role) => {
    for (const p of [...AUDIT_PAGES, ...EVIDENCE_PAGES]) {
      expect(canAccessPath(role, p)).toBe(true)
      expect(canSeeMenuItem(role, p)).toBe(true)
    }
    for (const p of SYSTEM_PAGES) expect(canAccessPath(role, p)).toBe(true)
  })

  it('auditor reads the four audit pages and nothing in business config (4.2)', () => {
    for (const p of [...AUDIT_PAGES, ...EVIDENCE_PAGES]) expect(canAccessPath('auditor', p)).toBe(true)
    for (const p of [...SYSTEM_PAGES, '/model-routing', '/cost/quota-policies', '/security/policies', '/dashboard', '/usage']) {
      expect(canAccessPath('auditor', p)).toBe(false)
    }
  })

  it('security officer manages policies and alerts but not users, system config or audit logs (4.1)', () => {
    for (const p of ['/security/policies', '/security/tool-config', '/security/alerts', '/mcp-gateway/policies']) {
      expect(canAccessPath('security_officer', p)).toBe(true)
      expect(canSeeMenuItem('security_officer', p)).toBe(true)
    }
    // 2.9.22 起安全员要在 Skill 页改 Skill 调用防护（后端 Skill 接口对安全员开放）。
    expect(canAccessPath('security_officer', '/security/skills')).toBe(true)
    expect(canSeeMenuItem('security_officer', '/security/skills')).toBe(true)
    expect(canAccessPath('security_officer', '/security/corpus-scan')).toBe(true)
    expect(canSeeMenuItem('security_officer', '/security/corpus-scan')).toBe(true)
    for (const p of EVIDENCE_PAGES) expect(canAccessPath('security_officer', p)).toBe(true)
    for (const p of [...SYSTEM_PAGES, ...AUDIT_PAGES, '/dashboard']) expect(canAccessPath('security_officer', p)).toBe(false)
  })

  it('every officer home page is reachable by that officer (no redirect loop)', () => {
    for (const role of ['platform_admin', 'admin', 'security_officer', 'auditor', 'tenant_owner', 'tenant_admin', 'dept_manager', 'developer', 'viewer', 'operator', 'unknown_role', '']) {
      expect(canAccessPath(role, roleHome(role))).toBe(true)
    }
  })

  it('menu visibility never exceeds route access', () => {
    for (const role of ['platform_admin', 'security_officer', 'auditor', 'tenant_owner', 'dept_manager', 'developer']) {
      for (const p of Object.keys(PAGE_ACCESS)) {
        if (canSeeMenuItem(role, p)) expect(canAccessPath(role, p)).toBe(true)
      }
    }
  })
})

describe('model operations tenant permissions', () => {
  it.each(['platform_admin', 'admin', 'tenant_owner', 'tenant_admin'])('%s can open its authorized model administration views', (role) => {
    for (const path of ['/providers', '/models', '/model-operations']) {
      expect(canAccessPath(role, path)).toBe(true)
      expect(canSeeMenuItem(role, path)).toBe(true)
    }
  })
  it.each(['auditor', 'security_officer', 'developer', 'viewer', 'dept_manager', 'unknown_role'])('%s cannot enter model administration through route or menu', (role) => {
    for (const path of ['/providers', '/models', '/model-operations']) {
      expect(canAccessPath(role, path)).toBe(false)
      expect(canSeeMenuItem(role, path)).toBe(false)
    }
  })
})

describe('chat_user is a Chat-only role', () => {
 it('hides and denies all console pages including unlisted paths', () => {
  for (const path of [...Object.keys(PAGE_ACCESS), '/dashboard', '/usage', '/cost/records', '/unknown-console-page']) {
   expect(canAccessPath('chat_user', path)).toBe(false)
   expect(canSeeMenuItem('chat_user', path)).toBe(false)
  }
  expect(roleHome('chat_user')).toBe('/chat')
  expect(canAccessPath('chat_user', '/chat')).toBe(true)
 })
})

// P1 资源与计费重组：新页面的可见角色与旧页面完全一致。
describe('billing restructure keeps the legacy role contract', () => {
  const ROLES = ['platform_admin', 'admin', 'security_officer', 'auditor', 'tenant_owner', 'tenant_admin',
    'dept_manager', 'team_owner', 'team_member', 'project_owner', 'project_developer', 'project_viewer',
    'developer', 'viewer', 'operator', 'chat_user', 'unknown_role', '']
  it.each(ROLES)('%s sees pricing/statements exactly when it could see the billing center', (role) => {
    for (const path of ['/cost/pricing', '/cost/statements']) {
      expect(canAccessPath(role, path)).toBe(canAccessPath(role, '/cost/customer-billing'))
      expect(canSeeMenuItem(role, path)).toBe(canSeeMenuItem(role, '/cost/customer-billing'))
    }
  })
  it.each(ROLES)('%s sees budgets exactly when it could see quota policies', (role) => {
    expect(canAccessPath(role, '/cost/budgets')).toBe(canAccessPath(role, '/cost/quota-policies'))
    expect(canSeeMenuItem(role, '/cost/budgets')).toBe(canSeeMenuItem(role, '/cost/quota-policies'))
  })
  it('only system administrators reach pricing and statements', () => {
    for (const role of ['tenant_owner', 'tenant_admin', 'dept_manager', 'auditor', 'security_officer', 'developer']) {
      expect(canAccessPath(role, '/cost/statements')).toBe(false)
      expect(canAccessPath(role, '/cost/pricing')).toBe(false)
    }
    expect(canAccessPath('platform_admin', '/cost/statements')).toBe(true)
  })
})
