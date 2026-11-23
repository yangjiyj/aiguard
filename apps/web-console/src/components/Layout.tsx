import DiagnosisBot from "./diagnosis/DiagnosisBot"
import { Outlet, useLocation, useNavigate } from "react-router-dom"
import { Layout as AntLayout, Avatar, Drawer, Dropdown, Tooltip, Menu, Segmented } from "antd"
import {
  DashboardOutlined,
  TeamOutlined,
  ProjectOutlined,
  ApiOutlined,
  KeyOutlined,
  BarChartOutlined,
  AuditOutlined,
  UserOutlined,
  LockOutlined,
  LogoutOutlined,
  SettingOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  DesktopOutlined,
  SunOutlined,
  MoonOutlined,
  DeploymentUnitOutlined,
  GlobalOutlined,
  FileSearchOutlined,
  ApartmentOutlined,
  FundOutlined,
  DollarOutlined,
  AlertOutlined,
  SafetyOutlined,
  BellOutlined,
  ControlOutlined,
} from "@ant-design/icons"
import { useState, useEffect, useMemo, type ReactNode } from "react"
import { useAuthStore } from "../stores/auth"
import { useAlertInboxStore } from "../stores/alertInbox"
import { useOrgLabels } from "../stores/orgLabels"
import { useThemeStore, type ThemeMode } from "../stores/theme"
import type { MenuProps } from "antd"
import { auditChainApi, billingAdminApi, licenseApi, type AuditChainIntegrity } from "../services/api"
import { canSeeMenuItem, isSystemAdminRole, roleHome } from "../utils/access"
import { AuditHmacDefaultKeyBanner } from "./AuditIntegrityStatus"
import { canReadAgent } from "../pages/agent/dict"
import { productCopy, useProductIdentity } from "../product/profiles"

const { Sider, Header, Content } = AntLayout

type NavigationItem = {
  key: string
  label: string
  icon: ReactNode
  children?: NavigationItem[]
  disabled?: boolean
}

type NavigationGroup = NavigationItem & { children: NavigationItem[] }

const UI_LABELS = {
  "brand": "AI安全网关",
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

const navigationGroups: NavigationGroup[] = [
  {
    key: "group-overview",
    icon: <DashboardOutlined aria-hidden="true" />,
    label: "\u6982\u89c8",
    children: [
      { key: "/dashboard", icon: <DashboardOutlined aria-hidden="true" />, label: "\u6001\u52bf\u603b\u89c8" },
      { key: "/cost/alerts", icon: <BellOutlined aria-hidden="true" />, label: "\u6d88\u606f\u4e2d\u5fc3" },
      { key: "/compliance/overview", icon: <SafetyCertificateOutlined aria-hidden="true" />, label: "\u5408\u89c4\u603b\u89c8" },
    ],
  },
  {
    key: "group-users",
    icon: <TeamOutlined aria-hidden="true" />,
    label: "\u7528\u6237\u4e0e\u5e94\u7528",
    children: [
      { key: "/users", icon: <TeamOutlined aria-hidden="true" />, label: "\u7528\u6237\u7ba1\u7406" },
      { key: "/organizations", icon: <ApartmentOutlined aria-hidden="true" />, label: "\u7ec4\u7ec7\u7ba1\u7406" },
      { key: "/identity-sources", icon: <SafetyOutlined aria-hidden="true" />, label: "\u4f01\u4e1a\u8eab\u4efd\u6e90" },
      { key: "/apps", icon: <ProjectOutlined aria-hidden="true" />, label: "\u5e94\u7528\u7ba1\u7406" },
      { key: "/keys", icon: <KeyOutlined aria-hidden="true" />, label: "\u5bc6\u94a5\u7ba1\u7406" },
    ],
  },
  {
    key: "group-access",
    icon: <ApiOutlined aria-hidden="true" />,
    label: "AI \u63a5\u5165",
    children: [
      { key: "/providers", icon: <ApiOutlined aria-hidden="true" />, label: "\u6a21\u578b\u4e0a\u6e38" },
      { key: "/models", icon: <DeploymentUnitOutlined aria-hidden="true" />, label: "\u6a21\u578b\u7ba1\u7406" },
      { key: "/model-operations", icon: <BarChartOutlined aria-hidden="true" />, label: "模型运营" },
      { key: "/model-routing", icon: <SafetyOutlined aria-hidden="true" />, label: "\u6a21\u578b\u8def\u7531" },
      { key: "/mcp-gateway/servers", icon: <DeploymentUnitOutlined aria-hidden="true" />, label: "MCP \u670d\u52a1\u7ba1\u7406" },
      { key: "/connect/channels", icon: <GlobalOutlined aria-hidden="true" />, label: "\u63a5\u5165\u901a\u9053" },
      { key: "/connect/network", icon: <ApiOutlined aria-hidden="true" />, label: "\u7f51\u7edc\u4e0e\u8bc1\u4e66" },
    ],
  },
  {
    key: "group-policy",
    icon: <SafetyCertificateOutlined aria-hidden="true" />,
    label: "\u9632\u62a4\u7b56\u7565",
    children: [
      { key: "/security/policies", icon: <SafetyOutlined aria-hidden="true" />, label: "\u7b56\u7565\u4e2d\u5fc3" },
      { key: "/security/tool-config", icon: <ControlOutlined aria-hidden="true" />, label: "\u5de5\u5177\u7981\u7528" },
      { key: "/security/agents", icon: <SafetyOutlined aria-hidden="true" />, label: "\u667a\u80fd\u4f53\u884c\u4e3a\u7ba1\u63a7" },
      { key: "/security/skills", icon: <SafetyCertificateOutlined aria-hidden="true" />, label: "Skill \u5b89\u5168\u51c6\u5165" },
      { key: "/security/corpus-scan", icon: <FileSearchOutlined aria-hidden="true" />, label: "训练语料扫描" },
      { key: "/mcp-gateway/policies", icon: <SafetyOutlined aria-hidden="true" />, label: "MCP \u8c03\u7528\u7b56\u7565" },
    ],
  },
  {
    key: "group-risk",
    icon: <AlertOutlined aria-hidden="true" />,
    label: "\u98ce\u9669\u5904\u7406",
    children: [
      { key: "/security/alerts", icon: <AlertOutlined aria-hidden="true" />, label: "\u5b89\u5168\u544a\u8b66" },
      { key: "/security/agents/advanced", icon: <AuditOutlined aria-hidden="true" />, label: "\u5de5\u5177\u786e\u8ba4\u4e0e\u4f8b\u5916" },
      { key: "/mcp-gateway/approvals", icon: <AuditOutlined aria-hidden="true" />, label: "MCP \u5ba1\u6279\u4e0e\u4f8b\u5916" },
      { key: "/security/blocks", icon: <StopOutlined aria-hidden="true" />, label: "\u963b\u65ad\u8bb0\u5f55" },
    ],
  },
  {
    key: "group-logs",
    icon: <FileSearchOutlined aria-hidden="true" />,
    label: "\u5ba1\u8ba1\u4e2d\u5fc3",
    children: [
      { key: "/cost/records", icon: <BarChartOutlined aria-hidden="true" />, label: "\u8c03\u7528\u660e\u7ec6" },
      { key: "/security/agent-tools", icon: <FileSearchOutlined aria-hidden="true" />, label: "\u5de5\u5177\u8c03\u7528\u660e\u7ec6" },
      { key: "/mcp-gateway/audit", icon: <FileSearchOutlined aria-hidden="true" />, label: "MCP \u8c03\u7528\u5ba1\u8ba1" },
      { key: "/agent/sessions", icon: <BarChartOutlined aria-hidden="true" />, label: "智能体会话" },
      { key: "/system/audit-operations", icon: <FileSearchOutlined aria-hidden="true" />, label: "\u64cd\u4f5c\u5ba1\u8ba1" },
      { key: "/audit/access-retention", icon: <GlobalOutlined aria-hidden="true" />, label: "\u5185\u5bb9\u7559\u8bc1" },
      { key: "/audit/login-history", icon: <UserOutlined aria-hidden="true" />, label: "\u767b\u5f55\u5386\u53f2" },
    ],
  },
  {
    key: "group-resource",
    icon: <FundOutlined aria-hidden="true" />,
    label: "\u8d44\u6e90\u4e0e\u8ba1\u8d39",
    children: [
      { key: "/usage", icon: <FundOutlined aria-hidden="true" />, label: "费用总览" },
      { key: "/cost/budgets", icon: <ControlOutlined aria-hidden="true" />, label: "钱包" },
      { key: "/cost/pricing", icon: <DollarOutlined aria-hidden="true" />, label: "价格与成本" },
      { key: "/cost/statements", icon: <FileSearchOutlined aria-hidden="true" />, label: "账单" },
    ],
  },
  {
    key: "group-system",
    icon: <SettingOutlined aria-hidden="true" />,
    label: "\u7cfb\u7edf\u7ba1\u7406",
    children: [
      { key: "/system/settings", icon: <SettingOutlined aria-hidden="true" />, label: "\u7cfb\u7edf\u8bbe\u7f6e" },
      { key: "/system/retention-storage", icon: <SettingOutlined aria-hidden="true" />, label: "\u5185\u5bb9\u7559\u5b58\u5b58\u50a8" },
      { key: "/system/license", icon: <SafetyCertificateOutlined aria-hidden="true" />, label: "\u8bb8\u53ef\u8bc1\u7ba1\u7406" },
      { key: "/system/notify-channels", icon: <BellOutlined aria-hidden="true" />, label: "\u901a\u77e5\u6e20\u9053" },
      { key: "/system/service-health", icon: <FileSearchOutlined aria-hidden="true" />, label: "\u670d\u52a1\u5065\u5eb7" },
    ],
  },
]


const SELECTED_KEY_ALIASES: Record<string, string> = {
  "/security": "/security/policies",
  "/security/semantic": "/security/policies",
  "/security/events": "/security/alerts",
  "/security/tools": "/security/alerts",
  "/security/detections": "/security/alerts",
  "/security/content": "/security/alerts",
  "/security/data": "/security/alerts",
  "/security/content-data": "/security/alerts",
  "/security/instruction-alerts": "/security/alerts",
  "/audit/content": "/security/alerts",
  "/audit/tools": "/security/alerts",
  "/audit/agents": "/security/alerts",
  "/connect/forward-access": "/audit/access-retention",
  "/cost/customer-billing": "/cost/statements",
  "/cost/quota-policies": "/cost/budgets",
  "/routing-policies": "/model-routing",
  "/sso-config": "/identity-sources",
  "/directory-sync": "/identity-sources",
  "/identity-sources/login": "/identity-sources",
  "/identity-sources/directory": "/identity-sources",
}

const themeOptions = [
  { label: <Tooltip title={UI_LABELS.dark}><span aria-label={UI_LABELS.dark}><MoonOutlined aria-hidden="true" /></span></Tooltip>, value: "dark" },
  { label: <Tooltip title={UI_LABELS.system}><span aria-label={UI_LABELS.system}><DesktopOutlined aria-hidden="true" /></span></Tooltip>, value: "system" },
  { label: <Tooltip title={UI_LABELS.light}><span aria-label={UI_LABELS.light}><SunOutlined aria-hidden="true" /></span></Tooltip>, value: "light" },
]

function getLeaves(items: NavigationItem[]): NavigationItem[] {
  return items.flatMap((item) => item.children ? getLeaves(item.children) : [item])
}

const BILLING_RUNTIME_GATED = new Set(["/cost/pricing", "/cost/statements"])

function filterNavigation(role: string | undefined, tenantId: string | undefined, billingVisible: boolean, agentLicensed: boolean): NavigationGroup[] {
  const filterItems = (items: NavigationItem[]): NavigationItem[] => items.flatMap<NavigationItem>((item) => {
    if (item.children) {
      const children = filterItems(item.children)
      return children.length ? [{ ...item, children }] : []
    }
    // 价格与成本、账单沿用原“计费中心”的运行态门控：计费关闭或模式未知时不显示。
    if (BILLING_RUNTIME_GATED.has(item.key) && !billingVisible) return []
    if (item.key === "/agent/sessions" && !canReadAgent(role)) return []
    return canSeeMenuItem(role, item.key, tenantId) ? [{ ...item, disabled: item.key === "/agent/sessions" && !agentLicensed }] : []
  })
  return navigationGroups.flatMap((group) => {
    const children = filterItems(group.children)
    return children.length ? [{ ...group, children }] : []
  })
}

function Layout() {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, logout } = useAuthStore()
  const { mode, isDark, setMode } = useThemeStore()
  const product = useProductIdentity()
  const copy = productCopy[product.profile]
  const [billingCapability, setBillingCapability] = useState<{ principal: string; enabled: boolean } | null>(null)
  const [agentLicense, setAgentLicense] = useState<{ principal: string; enabled: boolean } | null>(null)
  const principal = `${user?.id ?? ''}:${user?.tenant_id ?? ''}:${user?.role ?? ''}`
  useEffect(() => {
    let cancelled = false
    setBillingCapability(null)
    if (!isSystemAdminRole(user?.role)) return
    const refreshBilling = () => billingAdminApi.runtime().then((response) => {
      const billingMode = response.data?.data?.mode
      if (!cancelled) setBillingCapability({ principal, enabled: billingMode === 'metering' || billingMode === 'prepaid' })
    }).catch(() => { if (!cancelled) setBillingCapability(null) })
    void refreshBilling()
    const timer = setInterval(() => { void refreshBilling() }, 60000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [principal, user?.role])
  useEffect(() => {
    if (product.profile !== 'agent-platform') return
    let active = true
    setAgentLicense(null)
    licenseApi.status().then(({ data }) => {
      if (active) setAgentLicense({ principal, enabled: data.valid && Boolean(data.features?.includes('agent_security')) })
    }).catch(() => { if (active) setAgentLicense({ principal, enabled: false }) })
    return () => { active = false }
  }, [principal, product.profile])
  // 审计签名密钥告警条只给能处置的系统管理员和审计员看。
  const [auditIntegrity, setAuditIntegrity] = useState<AuditChainIntegrity | undefined>(undefined)
  useEffect(() => {
    let active = true
    setAuditIntegrity(undefined)
    if (!isSystemAdminRole(user?.role) && user?.role !== "auditor") return
    auditChainApi.integrity?.().then(({ data }) => { if (active) setAuditIntegrity(data) }).catch(() => undefined)
    return () => { active = false }
  }, [principal, user?.role])
  const [collapsed, setCollapsed] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const { refresh } = useAlertInboxStore()

  useEffect(() => {
    refresh()
    const timer = setInterval(() => refresh(), 30000)
    return () => clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    useOrgLabels.getState().fetch()
  }, [])

  const selectedKey = location.pathname.startsWith("/agent/sessions/") ? "/agent/sessions" : SELECTED_KEY_ALIASES[location.pathname] || location.pathname
  const visibleGroups = useMemo(() => {
    const billingVisible = billingCapability?.principal === principal && billingCapability.enabled
    const agentLicensed = product.profile !== "agent-platform" || (agentLicense?.principal === principal && agentLicense.enabled)
    return filterNavigation(user?.role, user?.tenant_id, !!billingVisible, !!agentLicensed)
  }, [user?.role, user?.tenant_id, principal, billingCapability, agentLicense, product.profile])
  const activeGroup = visibleGroups.find((group) => getLeaves(group.children).some((item) => item.key === selectedKey))
    || visibleGroups.find((group) => getLeaves(group.children).some((item) => item.key === roleHome(user?.role || "")))
    || visibleGroups[0]
  const primaryItems = visibleGroups.map(({ key, label, icon }) => ({ key, label, icon }))
  const theme = isDark ? "dark" : "light"

  const ROLE_LABELS: Record<string, string> = {
    chat_user: "普通用户（仅 Chat）",
    platform_admin: "系统管理员",
    admin: "管理员（历史）",
    security_officer: "安全保密管理员",
    tenant_owner: "单位管理员",
    dept_manager: "部门主管（只读）",
    team_owner: "部门主管",
    auditor: "审计员",
    operator: "操作员",
    developer: "开发者",
    project_owner: "应用负责人",
    project_developer: "应用开发",
    project_viewer: "应用观察员",
    viewer: "只读用户",
  }
  const roleLabel = ROLE_LABELS[user?.role || ""] || user?.role || "用户"

  const handleGroupClick: MenuProps["onClick"] = ({ key }) => {
    const group = visibleGroups.find((item) => item.key === key)
    const target = group && getLeaves(group.children)[0]
    if (target) navigate(target.key)
    setMobileMenuOpen(false)
  }

  const handleMenuClick: MenuProps["onClick"] = ({ key }) => {
    if (activeGroup && getLeaves(activeGroup.children).some((item) => item.key === key)) {
      navigate(key)
      setMobileMenuOpen(false)
    }
  }

  const userMenuItems: MenuProps["items"] = [
    {
      key: "info",
      disabled: true,
      label: (
        <div style={{ padding: "4px 0" }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>{user?.username || "Admin"}</div>
          <div style={{ fontSize: 12, color: "var(--text-tertiary)" }}>{roleLabel}</div>
        </div>
      ),
    },
    { type: "divider" },
    {
      key: "change-password",
      icon: <LockOutlined aria-hidden="true" />,
      label: "修改密码",
      onClick: () => navigate("/change-password"),
    },
    {
      key: "logout",
      icon: <LogoutOutlined aria-hidden="true" />,
      label: "退出登录",
      onClick: logout,
    },
  ]

  return (
    <AntLayout className="app-shell">
      <Sider
        className="app-sidebar"
        width={216}
        collapsedWidth={64}
        collapsed={collapsed}
        onCollapse={setCollapsed}
        theme={theme}
      >
        <button
          type="button"
          className={`app-brand${collapsed ? " app-brand--collapsed" : ""}`}
          aria-label={UI_LABELS.brand}
          onClick={() => navigate(roleHome(user?.role || ""))}
        >
          <span className="app-brand-mark"><SafetyCertificateOutlined aria-hidden="true" /></span>
          {!collapsed && (
            <span className="app-brand-copy">
              <strong>{product.profile === 'agent-platform' ? product.name : copy.title}</strong>
              <small>{copy.subtitle}</small>
            </span>
          )}
        </button>
        <nav id="app-primary-navigation" aria-label={UI_LABELS.main}>
          <Menu
            className="app-primary-menu"
            mode="inline"
            theme={theme}
            selectedKeys={activeGroup ? [activeGroup.key] : []}
            items={primaryItems}
            onClick={handleGroupClick}
          />
        </nav>
      </Sider>

      <Drawer
        className="app-mobile-drawer"
        title={(
          <div className="app-mobile-brand">
            <span className="app-brand-mark"><SafetyCertificateOutlined aria-hidden="true" /></span>
            <span>{product.profile === 'agent-platform' ? product.name : copy.title}</span>
          </div>
        )}
        placement="left"
        width={288}
        open={mobileMenuOpen}
        onClose={() => setMobileMenuOpen(false)}
        styles={{ body: { padding: 12 } }}
      >
        <nav id="app-mobile-navigation" aria-label={UI_LABELS.main}>
          <Menu
            className="app-primary-menu"
            mode="inline"
            theme={theme}
            selectedKeys={activeGroup ? [activeGroup.key] : []}
            items={primaryItems}
            onClick={handleGroupClick}
          />
        </nav>
      </Drawer>

      <AntLayout className="app-main-layout" style={{ marginLeft: collapsed ? 64 : 216 }}>
        <Header className="app-header">
          <div className="app-header-start">
            <Tooltip title={collapsed ? UI_LABELS.expand : UI_LABELS.collapse}>
              <button
                type="button"
                className="app-menu-trigger app-menu-trigger--desktop"
                aria-label={collapsed ? UI_LABELS.expand : UI_LABELS.collapse}
                aria-expanded={!collapsed}
                aria-controls="app-primary-navigation"
                onClick={() => setCollapsed(!collapsed)}
              >
                {collapsed ? <MenuUnfoldOutlined aria-hidden="true" /> : <MenuFoldOutlined aria-hidden="true" />}
              </button>
            </Tooltip>
            <button
              type="button"
              className="app-menu-trigger app-menu-trigger--mobile"
              aria-label={UI_LABELS.open}
              aria-expanded={mobileMenuOpen}
              aria-controls="app-mobile-navigation"
              onClick={() => setMobileMenuOpen(true)}
            >
              <MenuUnfoldOutlined aria-hidden="true" />
            </button>
            <span className="app-header-title">{activeGroup?.label}</span>
          </div>

          <div className="app-header-tools">
            {user?.role !== "chat_user" && <DiagnosisBot />}
            <Segmented
              size="small"
              options={themeOptions}
              value={mode}
              onChange={(val) => setMode(val as ThemeMode)}
            />
            <Dropdown menu={{ items: userMenuItems }} placement="bottomRight" trigger={["click"]}>
              <button type="button" className="app-user-trigger" aria-label={user?.username || "Admin"}>
                <Avatar size={30} icon={<UserOutlined aria-hidden="true" />} />
                <span>{user?.username || "Admin"}</span>
              </button>
            </Dropdown>
          </div>
        </Header>

        <nav className="app-secondary-navigation" aria-label={UI_LABELS.secondary}>
          <Menu
            className="app-secondary-menu"
            mode="horizontal"
            theme={theme}
            selectedKeys={[selectedKey]}
            items={activeGroup?.children || []}
            onClick={handleMenuClick}
            triggerSubMenuAction="click"
          />
        </nav>
        <Content className="app-content">
          <AuditHmacDefaultKeyBanner integrity={auditIntegrity} />
          <Outlet />
        </Content>
      </AntLayout>
    </AntLayout>
  )
}

export default Layout
