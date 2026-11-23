import { useCallback, useEffect, useRef, useState } from 'react'
import { Alert, Badge, Button, Drawer, Input, Space, Spin, Typography, message } from 'antd'
import { RobotOutlined, SettingOutlined } from '@ant-design/icons'
import { useLocation, useNavigate } from 'react-router-dom'
import { diagnosticsApi, type DiagnosisInput, type DiagnosisSession, type DiagnosisSessionSummary } from '../../services/api'
import { useAuthStore } from '../../stores/auth'
import { useDiagnosisContext } from '../../stores/diagnosisContext'
import { isConsoleAdministratorRole } from '../../utils/access'
import DiagnosisCard from './DiagnosisCard'
import DiagnosisSettings from './DiagnosisSettings'

export default function DiagnosisBot() {
  const user = useAuthStore((state) => state.user)
  if (!user || user.role === 'chat_user') return null
  return <DiagnosisBotSession key={`${user.tenant_id}:${user.id}:${user.role}`} admin={isConsoleAdministratorRole(user.role)} />
}

function recentTitle(item: DiagnosisSessionSummary) {
  return item.input?.text || (item.input?.kind === 'health' ? '一键体检' : '诊断记录')
}

function recentTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function DiagnosisBotSession({ admin }: { admin: boolean }) {
  const location = useLocation()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [hasIssue, setHasIssue] = useState(false)
  const [text, setText] = useState('')
  const [followup, setFollowup] = useState('')
  const [recent, setRecent] = useState<DiagnosisSessionSummary[]>([])
  const [session, setSession] = useState<DiagnosisSession | null>(null)
  const [target, setTarget] = useState<{ id: string; round: number } | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const mounted = useRef(false)
  const submittingRef = useRef(false)
  const historyVersion = useRef(0)
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; historyVersion.current += 1 }
  }, [])

  useEffect(() => {
    let active = true
    const refresh = async () => {
      try { const response = await diagnosticsApi.getBadge(); if (active) setHasIssue(response.data.has_issue) }
      catch { /* 红点刷新失败不打扰当前操作。 */ }
    }
    void refresh()
    const timer = window.setInterval(refresh, 60_000)
    return () => { active = false; window.clearInterval(timer) }
  }, [])

  const refreshHistory = useCallback(async () => {
    const version = ++historyVersion.current
    try {
      const response = await diagnosticsApi.listSessions()
      const rows = (response.data || []).slice(0, 5)
      if (mounted.current && version === historyVersion.current) setRecent(rows)
      return rows
    } catch { /* 历史不可用时仍可开始诊断。 */ return [] }
  }, [])

  useEffect(() => {
    if (!target) return
    let active = true
    let timer: number | undefined
    const poll = async () => {
      try {
        const response = await diagnosticsApi.getSession(target.id)
        if (!active) return
        setSession(response.data)
        if (response.data.status === 'running') timer = window.setTimeout(poll, 1000)
        else {
          void refreshHistory()
          if (response.data.status === 'failed') setError('诊断失败，请重试或重新开始诊断')
        }
      } catch {
        if (active) {
          setError('诊断进度读取失败，请从最近诊断重新打开')
          setSession({ status: 'failed', steps: [] })
        }
      }
    }
    void poll()
    return () => { active = false; window.clearTimeout(timer) }
  }, [target, refreshHistory])

  useEffect(() => {
    const report = session?.report
    if (report?.tier !== 'L3' || !report.model) return
    try {
      if (localStorage.getItem('diag_ai_notice_seen')) return
      message.info(`本次使用模型 ${report.model} 解读，数据不出本环境`)
      localStorage.setItem('diag_ai_notice_seen', '1')
    } catch { /* 浏览器禁用存储时仍可诊断。 */ }
  }, [session?.report])

  const openDrawer = () => {
    const context = useDiagnosisContext.getState().context
    const search = new URLSearchParams(location.search)
    const prefill = context?.requestId || search.get('request_id') || search.get('model')
    if (prefill) setText(prefill)
    if (context) useDiagnosisContext.getState().clear()
    setOpen(true)
    void refreshHistory().then((rows) => {
      // 红点亮着时，打开就直接展示最近一次体检结果，让红点自己解释原因。
      if (!hasIssue || prefill || !mounted.current || submittingRef.current) return
      const latest = rows.find((item) => item.input?.kind === 'health' && item.status === 'done')
      if (latest) startPolling(latest.id)
    })
  }
  const startPolling = (id: string) => {
    setError('')
    setSession({ status: 'running', steps: [] })
    setTarget((previous) => ({ id, round: (previous?.round || 0) + 1 }))
  }
  const send = async (input?: DiagnosisInput) => {
    if (submittingRef.current || session?.status === 'running') return
    const question = followup.trim()
    if (!input && (!target || !question)) return
    submittingRef.current = true
    setSubmitting(true)
    setError('')
    try {
      const response = input ? await diagnosticsApi.createSession(input) : await diagnosticsApi.sendMessage(target!.id, question)
      if (!mounted.current) return
      startPolling(response.data.session_id || target!.id)
      if (input) setText('')
      else setFollowup('')
      void refreshHistory()
    } catch { if (mounted.current) setError('诊断发送失败，请重试') }
    finally { submittingRef.current = false; if (mounted.current) setSubmitting(false) }
  }
  const create = () => {
    if (text.trim()) void send({ kind: 'question', text: text.trim(), ref: '', window_hours: 1 })
  }
  const busy = submitting || session?.status === 'running'
  const finished = session && session.status !== 'running'
  return <>
    <Badge dot={hasIssue}><Button type="text" icon={<RobotOutlined />} aria-label="诊断助手" onClick={openDrawer} /></Badge>
    <Drawer title="诊断助手" placement="right" width={480} open={open} onClose={() => { setOpen(false); void refreshHistory() }} destroyOnClose={false}
      extra={admin && <Button type="text" icon={<SettingOutlined />} aria-label="诊断设置" onClick={() => setSettingsOpen(true)} />}>
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Input.TextArea aria-label="诊断问题" autoSize={{ minRows: 3, maxRows: 8 }} placeholder="粘贴报错、请求编号，或直接描述问题" value={text} onChange={(event) => setText(event.target.value)} onKeyDown={(event) => {
          if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); create() }
        }} />
        <Space>
          <Button type="primary" disabled={busy || !text.trim()} onClick={create}>发送</Button>
          <Button disabled={busy} onClick={() => void send({ kind: 'health', text: '', ref: '', window_hours: 1 })}>一键体检</Button>
        </Space>
        {!!recent.length && <section aria-label="最近诊断">
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>最近诊断</Typography.Text>
          <div style={{ marginTop: 4 }}>
            {recent.map((item) => <Button key={item.id} type="text" block disabled={busy} onClick={() => startPolling(item.id)}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, height: 36, padding: '0 8px', textAlign: 'left' }}>
              <span style={{ minWidth: 0, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{recentTitle(item)}</span>
              {item.created_at && <Typography.Text type="secondary" style={{ flex: 'none', fontSize: 12 }}>{recentTime(item.created_at)}</Typography.Text>}
            </Button>)}
          </div>
        </section>}
        {error && <Alert type="error" message={error} />}
        {session?.status === 'running' && <section aria-label="诊断进度"><Spin size="small" /><ol>{session.steps?.map((step, index) => <li key={index}>{step.summary}</li>)}</ol></section>}
        {finished && session.report && <DiagnosisCard report={session.report} onOpenRequest={(requestId) => { setOpen(false); navigate(`/cost/records?request_id=${encodeURIComponent(requestId)}`) }} />}
        {finished && <>
          <Input.TextArea aria-label="追问" placeholder="继续追问" value={followup} autoSize={{ minRows: 2, maxRows: 6 }} onChange={(event) => setFollowup(event.target.value)} onKeyDown={(event) => {
            if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); void send() }
          }} />
          <Button disabled={busy || !followup.trim()} onClick={() => void send()}>发送追问</Button>
        </>}
      </Space>
    </Drawer>
    {admin && <DiagnosisSettings open={settingsOpen} onClose={() => setSettingsOpen(false)} />}
  </>
}
