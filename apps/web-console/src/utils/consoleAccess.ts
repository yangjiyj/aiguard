// 能登录管理控制台的角色，必须与后端 roles.CanLoginConsole 保持一致：三员分立的三员（系统管理员、安全保密管理员、
// 审计员）加上租户管理员及其历史别名。员工与业务角色（chat_user、developer、viewer、dept_manager 等）走 Chat 入口。
// 这里只回答「能不能进来」；进来后看到哪些菜单、打开哪些页面由 utils/access.ts 的 PAGE_ACCESS 按角色裁剪，
// 后端每个接口仍由 permission 中间件与 SoD 守卫把关。
const CONSOLE_ROLES = new Set(['platform_admin', 'security_officer', 'auditor', 'tenant_admin', 'admin', 'tenant_owner'])

export const isConsoleRole = (role?: string) => !!role && CONSOLE_ROLES.has(role)

export const CONSOLE_LOGIN_COPY = {
  adminHeading: '管理员登录',
  employeeHint: '此入口仅供管理员使用，请在 Chat 登录页登录员工账号。',
  deniedHeading: '需要管理员身份',
  returnToConsole: '返回管理员登录',
  openChat: '前往 Chat 登录',
} as const
