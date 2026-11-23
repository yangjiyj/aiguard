import { CONSOLE_LOGIN_COPY as copy } from '../utils/consoleAccess'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Outlet } from 'react-router-dom'
import App from '../App'

const { authState } = vi.hoisted(() => ({ authState: { role: 'tenant_owner' } }))
vi.mock('../stores/auth', () => ({ useAuthStore: () => ({ isAuthenticated: true, user: { role: authState.role, password_change_required: false } }) }))
vi.mock('../components/Layout', () => ({ default: () => <Outlet /> }))
vi.mock('../pages/ModelRouting', () => ({ default: () => <div>模型路由受保护页面</div> }))

vi.mock('../pages/OperationAudit', () => ({ default: () => <div>operation-audit-page</div> }))
vi.mock('../pages/Dashboard', () => ({ default: () => <div>态势总览受保护页面</div> }))

describe('App model routing RBAC', () => {
  beforeEach(() => { window.history.replaceState({}, '', '/model-routing') })

  it.each(['tenant_owner', 'platform_admin', 'admin'])('%s can enter model routing', (role) => {
    authState.role = role
    render(<App />)
    expect(screen.getByText('模型路由受保护页面')).toBeInTheDocument()
  })

  it('auditor is sent to operation audit instead of business config (W4 4.2)', () => {
    authState.role = 'auditor'
    render(<App />)
    expect(screen.queryByText('模型路由受保护页面')).not.toBeInTheDocument()
    // 审计员是控制台角色：不会被整体挡下，而是重定向到自己的落地页（操作审计）。
    expect(screen.queryByText(copy.deniedHeading)).not.toBeInTheDocument()
    expect(window.location.pathname).toBe('/system/audit-operations')
  })

  it('ordinary developer is redirected away from model routing', () => {
    authState.role = 'developer'
    render(<App />)
    expect(screen.queryByText('模型路由受保护页面')).not.toBeInTheDocument()
    expect(screen.getByText(copy.deniedHeading)).toBeInTheDocument()
  })

	it('legacy routing-decisions path redirects to model routing', () => {
		authState.role = 'tenant_owner'
		window.history.replaceState({}, '', '/routing-decisions')
		render(<App />)
		expect(screen.getByText('模型路由受保护页面')).toBeInTheDocument()
	})
  it('blocks project_owner before model configuration mounts', () => {
    authState.role = 'project_owner'
    render(<App />)
    expect(screen.getByText(copy.deniedHeading)).toBeInTheDocument()
  })

})
