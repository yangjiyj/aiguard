// 界面里金额单位的文字：USD 显示「美元」，其余（含未知）沿用「元」。
// 只换文字，不做汇率换算；符号请用 stores/currency 的 symbol。
export const currencyUnitLabel = (currency?: string | null): string =>
  String(currency ?? '').trim().toUpperCase() === 'USD' ? '美元' : '元'

// 表单标签后缀，例如「月费用预算（美元）」。
export const currencyUnitSuffix = (currency?: string | null): string => `（${currencyUnitLabel(currency)}）`
