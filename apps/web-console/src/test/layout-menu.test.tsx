import layoutSource from '../components/Layout.tsx?raw'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor, within, act, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import Layout from '../components/Layout'
import { productCopy } from '../product/profiles'
import { billingAdminApi, licenseApi, productApi } from '../services/api'
import { useThemeStore } from '../stores/theme'
import { canSeeMenuItem } from '../utils/access'

type NodeRequire = {
  (name: string): unknown
  resolve(name: string): string
}
const productionNavLabel = (path: string) => {
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = layoutSource.match(new RegExp('key: "' + escaped + '"[^\\n]+label: "([^"]+)"'))
  if (!match) throw new Error('Production navigation label not found: ' + path)
  return match[1]
}

const { createRequire } = await import('node:module' as string) as {
  createRequire(filename: string): NodeRequire
}
const requireFromAntd = createRequire(createRequire(import.meta.url).resolve('antd'))
const { _el: resizeListeners, _rs: notifyResize } = requireFromAntd('rc-resize-observer/lib/utils/observerUtil') as typeof import('rc-resize-observer/lib/utils/observerUtil')
const { animationEndName, transitionEndName } = requireFromAntd('rc-motion/lib/util/motion') as { animationEndName: string; transitionEndName: string }

const { mockAuth } = vi.hoisted(() => ({ mockAuth: { user: { role: 'platform_admin' } as any, logout: vi.fn() } }))
vi.mock('../stores/auth', () => ({ useAuthStore: () => ({ user: mockAuth.user, logout: mockAuth.logout }) }))
vi.mock('../stores/alertInbox', () => ({ useAlertInboxStore: () => ({ refresh: () => {} }) }))
vi.mock('../stores/orgLabels', () => ({ useOrgLabels: { getState: () => ({ fetch: () => {} }) } }))

const G = {
  "overview": "\u6982\u89c8",
  "users": "\u7528\u6237\u4e0e\u5e94\u7528",
  "access": "AI \u63a5\u5165",
  "policy": "\u9632\u62a4\u7b56\u7565",
  "risk": "\u98ce\u9669\u5904\u7406",
  "logs": "\u5ba1\u8ba1\u4e2d\u5fc3",
  "resource": "\u8d44\u6e90\u4e0e\u8ba1\u8d39",
  "system": "\u7cfb\u7edf\u7ba1\u7406"
}

const L = {
  "/agent/sessions": "智能体会话",
  "/dashboard": "\u6001\u52bf\u603b\u89c8",
  "/cost/alerts": "\u6d88\u606f\u4e2d\u5fc3",
  "/compliance/overview": "\u5408\u89c4\u603b\u89c8",
  "/apps": "\u5e94\u7528\u7ba1\u7406",
  "/keys": "\u5bc6\u94a5\u7ba1\u7406",
  "/providers": "\u6a21\u578b\u4e0a\u6e38",
  "/models": "\u6a21\u578b\u7ba1\u7406",
  "/model-operations": "模型运营",
  "/model-routing": "\u6a21\u578b\u8def\u7531",
  "/mcp-gateway/servers": "MCP \u670d\u52a1\u7ba1\u7406",
  "/connect/channels": "\u63a5\u5165\u901a\u9053",
  "/connect/network": "\u7f51\u7edc\u4e0e\u8bc1\u4e66",
  "/security/policies": "\u7b56\u7565\u4e2d\u5fc3",
  "/security/tool-config": "\u5de5\u5177\u7981\u7528",
  "/security/agents": "\u667a\u80fd\u4f53\u884c\u4e3a\u7ba1\u63a7",
  "/security/skills": "Skill \u5b89\u5168\u51c6\u5165",
  "/security/corpus-scan": "训练语料扫描",
  "/mcp-gateway/policies": "MCP \u8c03\u7528\u7b56\u7565",
  "/security/agentguard": "\u667a\u80fd\u4f53\u5b89\u5168",
  "/security/agent-operation-protection/advanced": "Agent \u64cd\u4f5c\u9632\u62a4",
  "/security/alerts": "\u5b89\u5168\u544a\u8b66",
  "/security/agents/advanced": "\u5de5\u5177\u786e\u8ba4\u4e0e\u4f8b\u5916",
  "/mcp-gateway/approvals": "MCP \u5ba1\u6279\u4e0e\u4f8b\u5916",
  "/security/blocks": "\u963b\u65ad\u8bb0\u5f55",
  "/cost/records": "\u8c03\u7528\u660e\u7ec6",
  "/security/agent-tools": "\u5de5\u5177\u8c03\u7528\u660e\u7ec6",
  "/mcp-gateway/audit": "MCP \u8c03\u7528\u5ba1\u8ba1",
  "/system/audit-operations": "\u64cd\u4f5c\u5ba1\u8ba1",
  "/system/service-health": "\u670d\u52a1\u5065\u5eb7",
  "/audit/access-retention": "\u5185\u5bb9\u7559\u8bc1",
  "/audit/login-history": "\u767b\u5f55\u5386\u53f2",
  "/usage": "费用总览",
  "/cost/budgets": productionNavLabel("/cost/budgets"),
  "/cost/pricing": "价格与成本",
  "/cost/statements": productionNavLabel("/cost/statements"),
  "/system/settings": "\u7cfb\u7edf\u8bbe\u7f6e",
  "/system/retention-storage": "\u5185\u5bb9\u7559\u5b58\u5b58\u50a8",
  "/system/license": "\u8bb8\u53ef\u8bc1\u7ba1\u7406",
  "/system/notify-channels": "\u901a\u77e5\u6e20\u9053",
  "/organizations": "\u7ec4\u7ec7\u7ba1\u7406",
  "/users": "\u7528\u6237\u7ba1\u7406",
  "/identity-sources": "\u4f01\u4e1a\u8eab\u4efd\u6e90"
}

const UI = {
  "brand": "AI\u7b97\u529b\u5b89\u5168\u7f51\u5173",
  "expand": "\u5c55\u5f00\u83dc\u5355",
  "collapse": "\u6536\u8d77\u83dc\u5355",
  "open": "\u6253\u5f00\u4e3b\u5bfc\u822a",
  "advanced": "\u9ad8\u7ea7\u89c4\u5219",
  "secondary": "\u4e8c\u7ea7\u5bfc\u822a",
  "dark": "\u6df1\u8272",
  "light": "\u660e\u4eae",
  "system": "\u7cfb\u7edf",
  "main": "\u4e3b\u5bfc\u822a"
}

const ROLE_LABELS = {
  "admin": "\u7ba1\u7406\u5458\uff08\u5386\u53f2\uff09",
  "platform_admin": "\u7cfb\u7edf\u7ba1\u7406\u5458",
  "security_officer": "\u5b89\u5168\u4fdd\u5bc6\u7ba1\u7406\u5458"
}

function CurrentRoute() {
  const location = useLocation()
  return <div data-testid="current-path">{location.pathname}</div>
}

function ConsoleRouter({ path = '/dashboard' }: { path?: string }) {
  return (
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route path="*" element={<CurrentRoute />} />
        </Route>
      </Routes>
    </MemoryRouter>
  )
}

const renderLayout = (path = '/dashboard') => render(<ConsoleRouter path={path} />)
const primary = () => within(document.getElementById('app-primary-navigation')!)
const secondary = () => within(screen.getByRole('navigation', { name: UI.secondary }))
const group = (label: string) => primary().getByRole('menuitem', { name: label })
const finishPopupMotion = async (item: HTMLElement) => {
  const popup = item.closest<HTMLElement>('.ant-menu-submenu-popup')!
  await waitFor(() => expect(popup.className).toMatch(/ant-slide-up-(?:appear|enter)-active/))
  fireEvent(popup, new Event(animationEndName, { bubbles: true }))
  fireEvent(popup, new Event(transitionEndName, { bubbles: true }))
  await waitFor(() => expect(item).toBeVisible())
}
const measureLayout = async () => {
  await act(async () => {
    notifyResize(Array.from(resizeListeners.keys(), (target) => ({ target }) as ResizeObserverEntry))
  })
  await waitFor(() => {
    for (const item of secondary().getAllByRole('menuitem')) expect(item).toHaveAttribute('data-menu-id')
  })
}
const open = async (label: string) => {
  await userEvent.setup().click(group(label))
  await measureLayout()
}
const hasPage = (path: keyof typeof L) => expect(secondary().getByRole('menuitem', { name: L[path] })).toBeVisible()
const noPage = (path: keyof typeof L) => expect(secondary().queryByRole('menuitem', { name: L[path] })).not.toBeInTheDocument()

const EXPECTED = {
  overview: ['/dashboard', '/cost/alerts', '/compliance/overview'],
  users: ['/users', '/organizations', '/identity-sources', '/apps', '/keys'],
  access: ['/providers', '/models', '/model-operations', '/model-routing', '/mcp-gateway/servers', '/connect/channels', '/connect/network'],
  policy: ['/security/policies', '/security/tool-config', '/security/agents', '/security/skills', '/security/corpus-scan', '/mcp-gateway/policies'],
  risk: ['/security/alerts', '/security/agents/advanced', '/mcp-gateway/approvals', '/security/blocks'],
logs: ['/cost/records', '/security/agent-tools', '/mcp-gateway/audit', '/agent/sessions', '/system/audit-operations', '/audit/access-retention', '/audit/login-history'],
  resource: ['/usage', '/cost/budgets', '/cost/pricing', '/cost/statements'],
  system: ['/system/settings', '/system/retention-storage', '/system/license', '/system/notify-channels', '/system/service-health'],
} as const

const ALL_LEAVES = [
  ...Object.entries(EXPECTED).flatMap(([key, paths]) => paths.map((path) => ({ key: key as keyof typeof G, path, advanced: false }))),
]

describe('Layout navigation - eight task groups and W4 separation of duties', () => {
  it('renders the fixed gateway identity within the task layout', () => {
    const { container } = renderLayout()
    expect(container.querySelector('.app-brand-copy strong')).toHaveTextContent(productCopy.gateway.title)
    expect(container.querySelector('.app-brand-copy small')).toHaveTextContent(productCopy.gateway.subtitle)
  })

  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
      for (let element: HTMLElement | null = this.parentElement; element; element = element.parentElement) {
        if (element.hidden || element.style.display === 'none') return new DOMRect()
      }
      if (this.hidden || this.style.display === 'none') return new DOMRect()
      return new DOMRect(0, 0, this.matches('[role="menu"]') ? 1200 : 120, 44)
    })
    for (const property of ['clientWidth', 'offsetWidth'] as const) {
      vi.spyOn(HTMLElement.prototype, property, 'get').mockImplementation(function (this: HTMLElement) {
        return this.getBoundingClientRect().width
      })
    }
    for (const property of ['clientHeight', 'offsetHeight'] as const) {
      vi.spyOn(HTMLElement.prototype, property, 'get').mockImplementation(function (this: HTMLElement) {
        return this.getBoundingClientRect().height
      })
    }
    mockAuth.user = { id: 'test-admin', tenant_id: 'tenant-a', role: 'platform_admin' }
    useThemeStore.setState({ mode: 'dark', isDark: true })
    vi.spyOn(billingAdminApi, 'runtime').mockResolvedValue({ data: { data: { mode: 'metering' } } } as any)
    vi.spyOn(productApi, 'get').mockResolvedValue({ data: { product_profile: 'gateway', product_name: 'JJDGuard' } } as any)
    vi.spyOn(licenseApi, 'status').mockResolvedValue({ data: { valid: false, features: [] } } as any)
  })

  afterEach(() => vi.restoreAllMocks())

  it('uses a 216px flat sidebar in task order, with leaf pages only in the secondary menu', () => {
    const { container } = renderLayout()
    const side = container.querySelector('.app-sidebar') as HTMLElement
    expect(side.style.width).toBe('216px')
    expect(primary().getAllByRole('menuitem').map((item) => item.textContent)).toEqual(Object.values(G))
    for (const label of Object.values(G)) expect(group(label)).toHaveAccessibleName(label)
    expect(side.querySelector('.ant-menu-submenu')).toBeNull()
    expect(primary().queryByRole('menuitem', { name: L['/dashboard'] })).not.toBeInTheDocument()
    hasPage('/dashboard')
  })

  it.each(Object.keys(EXPECTED) as (keyof typeof EXPECTED)[])('%s keeps every permitted original leaf', async (key) => {
    renderLayout()
    await open(G[key])
    for (const path of EXPECTED[key]) {
      if (canSeeMenuItem('platform_admin', path)) {
        if (path === '/cost/pricing' || path === '/cost/statements') expect(await secondary().findByRole('menuitem', { name: L[path] })).toBeVisible()
        else hasPage(path)
      } else noPage(path)
    }
  })

  it('keyboard activation reaches the first group leaf and its secondary leaf', async () => {
    renderLayout()
    const access = group(G.users)
    act(() => access.focus())
    fireEvent.keyDown(access, { key: 'Enter', code: 'Enter', keyCode: 13, which: 13 })
    expect(screen.getByTestId('current-path')).toHaveTextContent('/users')
    await measureLayout()
    const keys = secondary().getByRole('menuitem', { name: L['/keys'] })
    act(() => keys.focus())
    fireEvent.keyDown(keys, { key: 'Enter', code: 'Enter', keyCode: 13, which: 13 })
    expect(screen.getByTestId('current-path')).toHaveTextContent('/keys')
    await open(G.access)
    expect(screen.getByTestId('current-path')).toHaveTextContent('/providers')
  })

  it.each([
    ['platform_admin', ['/users', '/organizations', '/identity-sources', '/apps', '/keys']],
    ['admin', ['/users', '/organizations', '/identity-sources', '/apps', '/keys']],
    ['tenant_owner', ['/organizations', '/identity-sources', '/apps']],
    ['tenant_admin', ['/organizations', '/identity-sources', '/apps']],
    ['dept_manager', ['/organizations']],
  ] as const)('%s sees only its exact user and application leaves', async (role, paths) => {
    mockAuth.user.role = role
    const { container } = renderLayout()
    await open(G.users)
    expect(screen.getByTestId('current-path')).toHaveTextContent(paths[0])
    expect(container.querySelector('.app-header-title')).toHaveTextContent(G.users)
    expect(secondary().getAllByRole('menuitem').map(item => item.textContent)).toEqual(paths.map(path => L[path]))
    expect(primary().queryByRole('menuitem', { name: G.system }) === null).toBe(!['platform_admin', 'admin'].includes(role))
  })

  it('offers one agent governance entry without duplicated advanced menu pages', async () => {
    renderLayout()
    await open(G.policy)
    expect(secondary().queryByRole('menuitem', { name: UI.advanced })).not.toBeInTheDocument()
    expect(secondary().getAllByRole('menuitem', { name: L['/security/agents'] })).toHaveLength(1)
    noPage('/security/agentguard')
    noPage('/security/agent-operation-protection/advanced')
  })
  it('shows tool disable navigation under its preserved policy route', async () => {
    renderLayout()
    await open(G.policy)
    hasPage('/security/tool-config')
    expect(secondary().queryByRole('menuitem', { name: '工具调用策略' })).not.toBeInTheDocument()
    await userEvent.click(secondary().getByRole('menuitem', { name: '工具禁用' }))
    expect(screen.getByTestId('current-path')).toHaveTextContent('/security/tool-config')
  })

  it.each(ALL_LEAVES)('selects and reaches $path without changing its original route', async ({ key, path, advanced }) => {
    mockAuth.user.role = canSeeMenuItem('platform_admin', path) ? 'platform_admin' : 'auditor'
    renderLayout(path)
    await waitFor(() => expect(group(G[key])).toHaveClass('ant-menu-item-selected'))
    if (advanced) {
      expect(secondary().getByRole('menuitem', { name: UI.advanced }).closest('.ant-menu-submenu')).toHaveClass('ant-menu-submenu-selected')
      await open(G[key])
      await userEvent.setup().click(secondary().getByRole('menuitem', { name: UI.advanced }))
      const leaf = await screen.findByRole('menuitem', { name: L[path] })
      await finishPopupMotion(leaf)
      await userEvent.setup().click(leaf)
    } else {
      expect(await secondary().findByRole('menuitem', { name: L[path] })).toHaveClass('ant-menu-item-selected')
      await open(G[key])
      await userEvent.setup().click(secondary().getByRole('menuitem', { name: L[path] }))
    }
    expect(screen.getByTestId('current-path')).toHaveTextContent(path)
  })

  it.each(['off', 'unavailable'])('billing %s hides only the runtime-gated pricing and statements pages', async (mode) => {
    if (mode === 'unavailable') vi.mocked(billingAdminApi.runtime).mockRejectedValue(new Error('unavailable'))
    else vi.mocked(billingAdminApi.runtime).mockResolvedValue({ data: { data: { mode } } } as any)
    renderLayout('/usage')
    await waitFor(() => expect(billingAdminApi.runtime).toHaveBeenCalled())
    noPage('/cost/pricing')
    noPage('/cost/statements')
    hasPage('/cost/budgets')
    hasPage('/usage')
  })

  it.each([
    { id: 'other-admin' }, { tenant_id: 'tenant-b' }, { role: 'admin' },
  ])('a delayed response cannot reopen billing after principal change %j', async (change) => {
    let completeOld: (value: any) => void = () => {}
    vi.mocked(billingAdminApi.runtime).mockImplementationOnce(() => new Promise((resolve) => { completeOld = resolve }))
    const view = renderLayout('/usage')
    noPage('/cost/statements')
    mockAuth.user = { ...mockAuth.user, ...change }
    vi.mocked(billingAdminApi.runtime).mockResolvedValue({ data: { data: { mode: 'off' } } } as any)
    view.rerender(<ConsoleRouter path="/usage" />)
    await waitFor(() => expect(billingAdminApi.runtime).toHaveBeenCalledTimes(2))
    noPage('/cost/statements')
    await act(async () => completeOld({ data: { data: { mode: 'metering' } } }))
    noPage('/cost/statements')
  })

  it('billing prepaid is visible, but principal changes cannot reuse previous capability', async () => {
    vi.mocked(billingAdminApi.runtime).mockResolvedValueOnce({ data: { data: { mode: 'prepaid' } } } as any)
    const view = renderLayout('/usage')
    expect(await secondary().findByRole('menuitem', { name: L['/cost/statements'] })).toBeVisible()
    expect(secondary().getByRole('menuitem', { name: L['/cost/pricing'] })).toBeVisible()
    let complete: (value: any) => void = () => {}
    vi.mocked(billingAdminApi.runtime).mockImplementationOnce(() => new Promise((resolve) => { complete = resolve }))
    mockAuth.user = { id: 'other-admin', tenant_id: 'tenant-b', role: 'platform_admin' }
    view.rerender(<ConsoleRouter path="/usage" />)
    noPage('/cost/statements')
    await act(async () => complete({ data: { data: { mode: 'off' } } }))
    noPage('/cost/statements')
  })

  it('legacy admin retains a readable, non-actionable historical role label', async () => {
    mockAuth.user.role = 'admin'
    renderLayout()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Admin' }))
    const info = await screen.findByRole('menuitem', { name: `Admin ${ROLE_LABELS.admin}` })
    expect(info).toHaveAttribute('aria-disabled', 'true')
    expect(info).not.toHaveAttribute('tabindex')
    expect(info).toHaveAccessibleName(`Admin ${ROLE_LABELS.admin}`)
    expect(within(info).getByText(ROLE_LABELS.admin)).toBeInTheDocument()
    fireEvent.click(info)
    fireEvent.keyDown(info, { key: 'Enter', code: 'Enter', keyCode: 13, which: 13 })
    expect(screen.getByTestId('current-path')).toHaveTextContent('/dashboard')
    expect(mockAuth.logout).not.toHaveBeenCalled()
    expect(screen.queryByText(ROLE_LABELS.platform_admin)).not.toBeInTheDocument()
  })

  it('auditor has evidence and risk records but no business, policy or platform configuration', async () => {
    mockAuth.user.role = 'auditor'
    renderLayout('/system/audit-operations')
    expect(primary().getAllByRole('menuitem').map((item) => item.textContent)).toEqual([G.overview, G.risk, G.logs])
    for (const path of ['/system/audit-operations', '/audit/access-retention', '/audit/login-history'] as const) hasPage(path)
    noPage('/cost/records')
    await open(G.overview)
    hasPage('/compliance/overview')
    noPage('/dashboard')
    await open(G.risk)
    hasPage('/security/alerts')
    noPage('/security/agents/advanced')
    noPage('/mcp-gateway/approvals')
    expect(billingAdminApi.runtime).not.toHaveBeenCalled()
  })

  it('security officer keeps policy and MCP access, not identity or operation audit', async () => {
    mockAuth.user.role = 'security_officer'
    renderLayout('/security/alerts')
    expect(primary().getAllByRole('menuitem').map((item) => item.textContent)).toEqual([G.overview, G.access, G.policy, G.risk, G.logs])
    await open(G.access)
    hasPage('/mcp-gateway/servers')
    noPage('/apps')
    noPage('/keys')
    await open(G.policy)
    hasPage('/security/policies')
    hasPage('/mcp-gateway/policies')
    await open(G.logs)
    noPage('/system/audit-operations')
    noPage('/audit/login-history')
    noPage('/cost/records')
    await open(G.overview)
    hasPage('/compliance/overview')
    noPage('/dashboard')
  })

  it('平台级安全员在菜单里看到系统设置和网络与证书', async () => {
    mockAuth.user = { id: 'so', tenant_id: 'tenant_default', role: 'security_officer' }
    renderLayout('/security/alerts')
    await open(G.access)
    hasPage('/connect/network')
    await open(G.system)
    hasPage('/system/settings')
    noPage('/system/license')
  })

  it('tenant owner remains tenant scoped after regrouping', async () => {
    mockAuth.user.role = 'tenant_owner'
    renderLayout()
    await open(G.access)
    noPage('/apps')
    hasPage('/model-routing')
    hasPage('/models')
    hasPage('/providers')
    hasPage('/model-operations')
    noPage('/keys')
    noPage('/mcp-gateway/servers')
    await open(G.users)
    hasPage('/organizations')
    hasPage('/identity-sources')
    hasPage('/apps')
    noPage('/users')
    noPage('/keys')
    noPage('/system/settings')
    expect(primary().queryByRole('menuitem', { name: G.system })).not.toBeInTheDocument()
    await open(G.resource)
    hasPage('/cost/budgets')
    noPage('/cost/statements')
    await open(G.policy)
    hasPage('/security/agents')
    noPage('/security/policies')
    await open(G.risk)
    hasPage('/security/alerts')
    noPage('/mcp-gateway/approvals')
    expect(billingAdminApi.runtime).not.toHaveBeenCalled()
  })

  it('department manager has read-only risk and usage, not quota editing', async () => {
    mockAuth.user.role = 'dept_manager'
    renderLayout('/cost/records')
    expect(primary().queryByRole('menuitem', { name: G.overview })).not.toBeInTheDocument()
    expect(primary().queryByRole('menuitem', { name: G.policy })).not.toBeInTheDocument()
    hasPage('/cost/records')
    await open(G.resource)
    hasPage('/usage')
    noPage('/cost/budgets')
    await open(G.risk)
    hasPage('/security/alerts')
    noPage('/security/agents/advanced')
  })

  it('developer has only overview, own call records and usage', () => {
    mockAuth.user.role = 'developer'
    renderLayout()
    expect(primary().getAllByRole('menuitem').map((item) => item.textContent)).toEqual([G.overview, G.logs, G.resource])
    noPage('/cost/alerts')
  })

  it('collapse and mobile drawer keep their accessible controls and reachable task groups', async () => {
    const { container } = renderLayout()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: UI.collapse }))
    expect(container.querySelector('.app-sidebar')).toHaveClass('ant-layout-sider-collapsed')
    expect(screen.getByRole('button', { name: UI.expand })).toHaveAttribute('aria-expanded', 'false')
    await user.click(screen.getByRole('button', { name: UI.open }))
    const mobile = within(await screen.findByRole('dialog'))
    await user.click(mobile.getByRole('menuitem', { name: G.risk }))
    expect(screen.getByTestId('current-path')).toHaveTextContent('/security/alerts')
    expect(screen.getByRole('button', { name: UI.open })).toHaveAttribute('aria-expanded', 'false')
  })

  it.each([true, false])('system theme resolves isDark=%s for sidebar and both menus', (isDark) => {
    vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: isDark, addEventListener: vi.fn(), removeEventListener: vi.fn() } as unknown as MediaQueryList)
    useThemeStore.getState().setMode('system')
    const { container } = renderLayout()
    expect(container.querySelector('.app-sidebar')).toHaveClass(`ant-layout-sider-${isDark ? 'dark' : 'light'}`)
    expect(primary().getByRole('menu')).toHaveClass(`ant-menu-${isDark ? 'dark' : 'light'}`)
    expect(secondary().getByRole('menu')).toHaveClass(`ant-menu-${isDark ? 'dark' : 'light'}`)
  })

  it.each([
    'platform_admin', 'admin', 'security_officer', 'auditor', 'tenant_owner', 'tenant_admin',
    'dept_manager', 'team_owner', 'team_member', 'project_owner', 'project_developer',
    'project_viewer', 'developer', 'viewer', 'operator', 'unknown_role', '',
  ])('%s keeps the complete 41-leaf menu within its authorized RBAC contract', async (role) => {
    mockAuth.user.role = role
    renderLayout()
    expect(ALL_LEAVES).toHaveLength(41)
    expect(new Set(ALL_LEAVES.map(({ path }) => path)).size).toBe(41)
    const allowed = ALL_LEAVES.filter(({ path }) => canSeeMenuItem(role, path))
    const allowedGroups = Object.keys(G).filter((key) => allowed.some((item) => item.key === key)) as (keyof typeof G)[]
    expect(primary().getAllByRole('menuitem').map((item) => item.textContent)).toEqual(allowedGroups.map((key) => G[key]))
    const observedPaths: string[] = []
    for (const key of allowedGroups) {
      await open(G[key])
      for (const path of EXPECTED[key]) {
        if (canSeeMenuItem(role, path)) {
          expect(await secondary().findByRole('menuitem', { name: L[path] })).toBeVisible()
          observedPaths.push(path)
        } else noPage(path)
      }
      if (key === 'policy') {
        const advancedAllowed = ALL_LEAVES.filter((item) => item.advanced && canSeeMenuItem(role, item.path))
        if (advancedAllowed.length) {
          await userEvent.setup().click(secondary().getByRole('menuitem', { name: UI.advanced }))
          await finishPopupMotion(await screen.findByRole('menuitem', { name: L[advancedAllowed[0].path] }))
          for (const item of ALL_LEAVES.filter((leaf) => leaf.advanced)) {
            if (canSeeMenuItem(role, item.path)) {
              expect(await screen.findByRole('menuitem', { name: L[item.path] })).toBeVisible()
              observedPaths.push(item.path)
            } else expect(screen.queryByRole('menuitem', { name: L[item.path] })).not.toBeInTheDocument()
          }
        } else expect(secondary().queryByRole('menuitem', { name: UI.advanced })).not.toBeInTheDocument()
      }
    }
    expect(observedPaths.sort()).toEqual(allowed.map(({ path }) => path).sort())
    expect(observedPaths).toHaveLength(allowed.length)
  })

  it.each([
    ['/security', '/security/policies', 'policy'],
    ['/security/semantic', '/security/policies', 'policy'],
    ['/security/events', '/security/alerts', 'risk'],
    ['/security/tools', '/security/alerts', 'risk'],
    ['/security/detections', '/security/alerts', 'risk'],
    ['/security/content', '/security/alerts', 'risk'],
    ['/security/data', '/security/alerts', 'risk'],
    ['/security/content-data', '/security/alerts', 'risk'],
    ['/security/instruction-alerts', '/security/alerts', 'risk'],
    ['/audit/content', '/security/alerts', 'risk'],
    ['/audit/tools', '/security/alerts', 'risk'],
    ['/audit/agents', '/security/alerts', 'risk'],
    ['/connect/forward-access', '/audit/access-retention', 'logs'],
    ['/routing-policies', '/model-routing', 'access'],
    ['/sso-config', '/identity-sources', 'users'],
    ['/directory-sync', '/identity-sources', 'users'],
    ['/cost/quota-policies', '/cost/budgets', 'resource'],
    ['/identity-sources/login', '/identity-sources', 'users'],
    ['/identity-sources/directory', '/identity-sources', 'users'],
  ] as const)('legacy URL $0 still selects its canonical navigation leaf $1', (path, canonical, key) => {
    mockAuth.user.role = canSeeMenuItem('platform_admin', canonical) ? 'platform_admin' : 'auditor'
    const { container } = renderLayout(path)
    expect(group(G[key])).toHaveClass('ant-menu-item-selected')
    expect(secondary().getByRole('menuitem', { name: L[canonical] })).toHaveClass('ant-menu-item-selected')
    expect(container.querySelector('.app-header-title')).toHaveTextContent(G[key])
  })

  it('legacy billing center URL selects 账单与对账 once billing is enabled', async () => {
    const { container } = renderLayout('/cost/customer-billing')
    expect(await secondary().findByRole('menuitem', { name: L['/cost/statements'] })).toHaveClass('ant-menu-item-selected')
    expect(group(G.resource)).toHaveClass('ant-menu-item-selected')
    expect(container.querySelector('.app-header-title')).toHaveTextContent(G.resource)
  })

  it('resource group shows exactly the four reorganized billing pages in order', async () => {
    renderLayout('/usage')
    await secondary().findByRole('menuitem', { name: L['/cost/statements'] })
    const names = secondary().getAllByRole('menuitem').map((item) => item.textContent)
    expect(names).toEqual(['费用总览', L['/cost/budgets'], '价格与成本', L['/cost/statements']])
  })
})
