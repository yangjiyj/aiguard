export const toolPricingOptions = [
  { value: 'web_search', label: '联网搜索（OpenAI / Anthropic）' },
  { value: 'web_search_preview', label: '联网搜索预览（OpenAI）' },
  { value: 'file_search', label: '文件检索（OpenAI）' },
  { value: 'image_generation', label: '图像生成工具（OpenAI）' },
  { value: 'google_search', label: 'Google 搜索（Gemini，按查询）' },
  { value: 'google_search_grounded_prompt', label: 'Google 搜索（Gemini，按搜索增强请求）' },
  { value: 'web_fetch', label: '网页抓取（Anthropic）' },
]

export const TOOL_PRICING_HELP = '按上游实际执行的工具用量计费，仅声明工具不收费。选择工具可查看具体计量单位和有来源的参考费率；缺少执行数据时不收工具附加费。'

export const toolPricingUnit = (name: string) => name === 'google_search' ? '千次查询' : name === 'google_search_grounded_prompt' ? '千个搜索增强请求' : name === 'image_generation' ? '千次执行' : '千次调用'

export function toolPricingLabel(name: string) {
  return toolPricingOptions.find((option) => option.value === name)?.label ?? `自定义工具：${name}`
}

export function toolPricingOptionsWithExisting(names: string[] = []) {
  const known = new Set(toolPricingOptions.map((option) => option.value))
  return [...toolPricingOptions, ...[...new Set(names)].filter((name) => name && name !== '__custom__' && !known.has(name)).map((value) => ({ value, label: toolPricingLabel(value) }))]
}
