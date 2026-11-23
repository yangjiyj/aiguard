// 从 axios 错误里解析后端返回的可读原因。
// 后端统一错误体为 { "error": { "code": "...", "message": "中文原因" } }，
// 部分老接口用顶层 { "message": "..." }。解析不到时返回 undefined，交由调用方给默认文案，
// 例如：message.error(extractApiError(e) || '创建失败')。
// 后端只给英文原因的错误码，在这里转成中文；不在表里且原因不含中文的，返回 undefined 让调用方给中文默认文案，
// 客户可见界面不直出英文原因、HTTP 状态码或技术 id。
const ERROR_CODE_MESSAGES: Record<string, string> = {
  password_managed_externally: '该用户密码由企业身份源管理，请前往对应身份源修改',
  // 计费
  invalid_billing_request: '计费参数不正确，请检查后重试',
  billing_currency_mixed: '所选范围包含多种币种，金额无法合计，请只选择一种币种',
  billing_idempotency_conflict: '该计费操作与已有记录冲突，请刷新后重试',
  billing_quote_missing: '该请求缺少价格快照，无法补结算',
  cache_true_up_not_applicable: '该记录不是待补缓存结算的记录',
  customer_group_not_found: '客户组不存在或未启用',
  tariff_not_draft: '只有草稿状态的时段方案可以删除',
  tariff_not_found: '时段方案不存在或已被删除',
  invalid_allowance: '额度金额、币种、时区或员工选择不正确',
  invalid_currency: '币种只能是人民币或美元',
  allowance_currency_mismatch: '钱包与模型价格币种不一致；系统不做汇率换算。本月已发放赠金时币种和时区不可更改，请由管理员在「切换系统币种」中统一处理',
  price_currency_mismatch: '该模型价格币种与系统币种不一致，请管理员重新设置价格',
  cost_currency_mismatch: '采购成本币种必须与系统计价币种一致，系统不做汇率换算',
  count_changed: '预览之后数据已变化，请重新预览后再确认切换',
  currency_switch_in_flight: '仍有在途预占，请等待请求结算后再切换系统币种',
  currency_switch_conflict: '同一用户存在无法安全合并的钱包，请先处理冲突用户的余额后再切换',
  currency_switch_unpriced_confirm_required: '切换后有模型将变为未定价，请在预览中勾选确认后重试',
  currency_switch_busy: '计费表正忙，请在停流量窗口重试',
  invalid_dimension_filter: '筛选条件过多，请减少后重试',
  invalid_time_range: '时间范围不正确，最长可查询 366 天',
  invalid_time: '时间格式不正确',
  invalid_upstream_rate: '采购成本或渠道、模型选择不正确',
  price_currency_unsupported: '价格币种必须与计费币种一致，暂不支持多币种计费',
  redemption_unavailable: '兑换码无效、已使用或已过期',
  rpm_limit_exceeded: '每分钟请求数已达上限，请稍后再试',
  concurrency_limit_exceeded: '并发请求数已达上限，请稍后再试',
  usage_limit_exceeded: '已达到每日或每月用量上限',
  insufficient_balance: '余额不足，请充值后再试',
  price_effective_at_in_past: '生效时间不能早于当前时间，价格只能从现在或将来生效',
  price_zero_confirmation_required: '这次提交会把非零价格改成 0（免费），请在确认框中明确勾选确认后再提交',
  model_price_missing: '该模型还没有配置价格，请先在“价格与成本”中配置',
}

const hasChinese = (value: unknown): value is string => typeof value === 'string' && /[\u4e00-\u9fff]/.test(value)

export function extractApiError(e: any): string | undefined {
  const data = e?.response?.data
  const code = data?.error?.code
  if (typeof code === 'string' && ERROR_CODE_MESSAGES[code]) return ERROR_CODE_MESSAGES[code]
  const reason = data?.error?.message || data?.message
  return hasChinese(reason) ? reason : undefined
}
