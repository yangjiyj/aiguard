// 留证详情的客户投影会丢弃 system/工具段；原文只保留在内部审计链。
// A 路 content_logs 回退文本已带【system】/【tool】角色前缀段（access_retention_content.go
// 的合成规则）；纯平铺文本按"首个 user 锚点"启发式折叠头部（参考 ContentAudit.tsx
// isHiddenByDefault / AGENT_META_USER_PATTERNS 先例）。
const ROLE_PREFIX_RE = /^【(system|tool|developer|系统|工具|其它)】/i

// 代理运行时头部特征（与 ContentAudit 先例同源；命中即视为非员工发送的机器噪音段）
const AGENT_META_HEAD_PATTERNS = [
  /^You are Claude Code/i,
  /^You are an? (expert |interactive )?(AI|CLI|coding|programming)/i,
  /^<system-reminder>/i,
  /^Your name is GitHub Copilot/i,
  /^The user stepped away and is coming back/i,
]

const AGENT_RUNTIME_SECTION_PATTERNS = [
  /^<environment_context(?:\s|>)/i,
  /^<skills_instructions(?:\s|>)/i,
  /^<available_skills(?:\s|>)/i,
  /^<(?:tool_call|tool_result|tool_use|function_call|system-reminder|task_management)(?:\s|>)/i,
  /^internal recap:/i,
  /^You are Codex\b/i,
  /^Analyze this rollout\b/i,
  /^rollout_context:/i,
  /^rendered conversation\s*\(/i,
  /^#{1,2}\s*Skills\b/i,
  /^(?:current_turn|shell_command)\b/i,
]

export type CollapsedRetentionText = { head: string; body: string; collapsedCount: number }

export const collapseSystemSections = (text?: string): CollapsedRetentionText => {
  const raw = String(text || '')
  if (!raw.trim()) return { head: '', body: raw, collapsedCount: 0 }
  const paragraphs = raw.split(/\n\n+/)
  // 折叠"所有"系统/工具段（不只开头）——后端把真实对话放最前、系统提示词+工具噪音放后
  // （编码 agent 的系统提示词常超 64KB，放末尾会被留证截断切掉真实对话），故噪音段可能在正文之后，
  // 需整体折叠而非仅折开头。非系统段（真实对话）作正文展示。
  const bodyParas: string[] = []
  let collapsedCount = 0
  for (const p of paragraphs) {
    const t = p.trim()
    const systemish = ROLE_PREFIX_RE.test(t) ||
      AGENT_META_HEAD_PATTERNS.some((re) => re.test(t)) ||
      AGENT_RUNTIME_SECTION_PATTERNS.some((re) => re.test(t))
    if (systemish) collapsedCount += 1
    else bodyParas.push(p)
  }
  if (collapsedCount === 0) return { head: '', body: raw, collapsedCount: 0 }
  return {
    head: '',
    body: bodyParas.join('\n\n'),
    collapsedCount,
  }
}
