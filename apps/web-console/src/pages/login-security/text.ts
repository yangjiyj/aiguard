// W3 控制台登录安全：前端文案集中在此，测试直接引用这些常量，避免在断言里重复手打中文。
export const LOGIN_TEXT = {
  genericFailure: '登录失败，请检查用户名、密码和验证码',
  totpFailure: '登录失败，请检查用户名、密码、验证码和双因素验证码',
  invalidCaptcha: '验证码错误或已过期，请重新输入',
  ipNotAllowed: '当前网络地址不允许管理员账号登录，请联系平台管理员',
  totpRequired: '该账号已启用双因素认证，请输入验证器中的 6 位验证码',
  totpLabel: '双因素验证码',
  totpPlaceholder: '6 位验证码',
  totpRule: '请输入 6 位数字验证码',
  passwordExpired: '密码已超过有效期，请修改密码后继续使用',
  ssoButton: '使用企业统一身份登录',
  locked: (minutes: number) => `登录失败次数过多，账号已锁定，请 ${minutes} 分钟后再试`,
}

export const TOTP_ENROLL_TEXT = {
  title: '绑定双因素认证',
  intro: '平台要求管理员账号启用双因素认证。请在验证器应用中添加以下密钥，然后输入当前验证码完成绑定。',
  secretLabel: '密钥',
  uriLabel: '验证器链接',
  confirm: '完成绑定',
  success: '双因素认证已启用',
  invalidCode: '验证码不正确，请重新输入',
  loadFailed: '无法生成密钥，请重新登录后再试',
}

export const PASSWORD_TEXT = {
  title: '修改密码',
  subtitle: '请设置符合密码策略的新密码',
  hint: '默认策略：至少 12 位，包含大写字母、小写字母、数字、符号中的至少 3 类，不得包含用户名，不得与最近 5 次密码相同。',
  tooShort: (n: number) => `新密码至少 ${n} 位`,
  tooFewClasses: (n: number) => `新密码需包含大写字母、小写字母、数字、符号中的至少 ${n} 类`,
  containsUsername: '新密码不得包含用户名',
  reused: (n: number) => `新密码不得与最近 ${n} 次使用过的密码相同`,
  wrongCurrent: '当前密码不正确',
}

export const PORTAL_BASELINE_TEXT = {
  notMet: '门户登录安全基线未达标',
  detail: '门户身份引擎的登录安全配置低于基线。升级不会自动修改，请由运维人员在服务器上检查冲突后执行一键收紧：',
}

export const LOGIN_SECURITY_SETTINGS_TEXT = {
  title: '控制台登录安全',
  lockoutThreshold: '连续失败锁定次数',
  lockoutMinutes: '锁定时长（分钟）',
  passwordMinLength: '密码最小长度',
  passwordMinClasses: '密码最少字符类别',
  passwordHistoryCount: '不得重复的历史密码次数',
  passwordMaxAgeDays: '密码有效期（天，0 为不限）',
  sessionIdleMinutes: '空闲超时（分钟）',
  sessionAbsoluteHours: '会话最长时长（小时）',
  sessionMaxConcurrent: '单账号并发会话上限（0 为不限）',
  adminTotpRequired: '管理员强制双因素认证',
  adminIpAllowlist: '管理员登录地址白名单（CIDR 或 IP，逗号分隔，留空不限）',
  save: '保存',
  saved: '登录安全设置已保存',
  excludesCurrentIp: '白名单必须包含你当前的网络地址，否则保存后将无法登录',
  invalid: '设置值不合法，请检查后重试',
}
