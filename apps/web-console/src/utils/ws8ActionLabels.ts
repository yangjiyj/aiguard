import { securityModeLabel } from '../services/securityExecutionMode'

// W8 8.8：记录模式（security_audit_only）下命中规则的落库值统一显示为「<观察留痕模式名>放行」。
// 2026-09-29 核实：记录模式期间只落 security_audit_only / audit / tool_audit_only，不产生阻断类值；
// 阻断类值只可能在防护模式下写入，如实显示为已拦截。模式名取自 securityModeLabel，不另起说法。
export const RECORD_MODE_PASS_LABEL = `${securityModeLabel('record')}放行`
