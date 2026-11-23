import type { RawEvidenceMeta } from '../services/rawEvidence'

// 后端返回的具体失败原因（如无权限、已过保留期、审计写入失败）；取不到时用默认文字。
export const errorMessage = (e: unknown, fallback: string) =>
  (e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || fallback

// 命中所在的那条消息的原文留证；找不到同序号的、且全请求只有一条时用那一条。
export const pickEvidence = (items: RawEvidenceMeta[], messageIndex: number | null) =>
  items.find((item) => item.message_index === messageIndex) || (items.length === 1 ? items[0] : undefined)

// 原文留证的方向按“请求带上来的”还是“模型这次生成的”区分，与阶段一致：
// 请求里的所有消息（含历史里的助手消息）都是 input，只有模型本次响应是 output。
// 所以阶段明确时只看阶段；阶段缺失（旧事件）时才按来源推断。
const OUTPUT_ONLY_SOURCES = ['model_output', 'final_output', 'verified_final_output', 'assistant_output']

export const rawEvidenceDirection = (stage?: string | null, contentSource?: string | null): 'input' | 'output' => {
  if (stage === 'output') return 'output'
  if (stage === 'input' || stage === 'tool') return 'input'
  return OUTPUT_ONLY_SOURCES.includes(String(contentSource ?? '')) ? 'output' : 'input'
}
