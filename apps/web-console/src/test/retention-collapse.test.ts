import { describe, it, expect } from 'vitest'
import { collapseSystemSections } from '../utils/retentionCollapse'

describe('留证详情客户可见文本边界', () => {
  it('丢弃【system】/【tool】前缀段，只保留 user 正文', () => {
    const text = '【system】You are Claude Code, an agent.\n\n【tool】tool result blob\n\n帮我修一下这个空指针\n\n附上堆栈'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(2)
    expect(got.head).toBe('')
    expect(got.body).toContain('帮我修一下这个空指针')
    expect(got.body).not.toContain('【system】')
  })
  it('平铺文本按首个 user 锚点折叠代理头部', () => {
    const text = 'You are Claude Code, Anthropic\'s official CLI for Claude.\n\n<system-reminder>skills list</system-reminder>\n\n查询昨天的报错日志'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(2)
    expect(got.body).toBe('查询昨天的报错日志')
  })
  it('无 system 特征时不折叠', () => {
    const text = '帮我写个正则\n\n匹配手机号'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(0)
    expect(got.body).toBe(text)
  })
  it('全部是 system 时不保留原文（避免伪装成真实问答）', () => {
    const text = '【system】a\n\n【system】b'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(2)
    expect(got.body).toBe('')
  })
  it('丢弃正文之后的系统段（对话在前、噪音在后）', () => {
    const text = '哦\n\n【工具】[tool_def:present_files] Present files to the user\n\n【系统】You are the agent'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(2)
    expect(got.body).toBe('哦')
    expect(got.head).toBe('')
  })
  it('折叠 Codex Responses 的 instructions 噪音，保留真实用户输入', () => {
    const text = '检查告警留存\n\n【系统】{"model":"gpt-5.5","instructions":"You are Codex. # Personality ..."}'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(1)
    expect(got.body).toBe('检查告警留存')
    expect(got.head).toBe('')
  })
  it('全部是系统段时不保留全文供展开', () => {
    const text = '【系统】You are Codex. current_turn uses shell_command.\n\n【工具】tool runtime details'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(2)
    expect(got.head).toBe('')
    expect(got.body).toBe('')
  })
  it('丢弃环境、Skills 和内部 recap，而不把它们留在可展开状态', () => {
    const text = '检查告警\n\n<environment_context>workspace=/srv/customer</environment_context>\n\n<skills_instructions>internal skills</skills_instructions>\n\ninternal recap: shell_command completed'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(3)
    expect(got.head).toBe('')
    expect(got.body).toBe('检查告警')
  })
  it('丢弃 Codex rollout 后台记忆整理载荷', () => {
    const text = 'Analyze this rollout and produce JSON with `raw_memory`, `rollout_summary`, and `rollout_slug`.\n\nrollout_context:\n- rollout_path: /Users/example/.codex/sessions/private.jsonl\n\nrendered conversation (pre-rendered from rollout):\n[{"type":"message"}]'
    const got = collapseSystemSections(text)
    expect(got.collapsedCount).toBe(3)
    expect(got.body).toBe('')
  })
})
