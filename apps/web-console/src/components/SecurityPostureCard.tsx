import { Alert, Button, Spin, Tag, Tooltip } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { securityModeLabel } from '../services/securityExecutionMode'
import { securityPostureApi, type PostureMode } from '../services/securityPosture'
import './SecurityPostureCard.css'

const text = {
  title: '\u5b89\u5168\u59ff\u6001\u603b\u89c8',
  channel: '\u901a\u9053', configured: '\u914d\u7f6e\u6a21\u5f0f', effective: '\u5b9e\u9645\u6a21\u5f0f',
  failure: '\u5931\u8d25\u6a21\u5f0f', controls: '\u5f00\u5173\u4e0e\u63a5\u7ebf',
  refresh: '\u5237\u65b0\u72b6\u6001', unknown: '\u5f85\u786e\u8ba4',
  mixed: '\u8282\u70b9\u4e0d\u4e00\u81f4', verified: '\u8fd0\u884c\u5df2\u786e\u8ba4',
  failed: '\u59ff\u6001\u8bfb\u53d6\u5931\u8d25',
  enabled: '\u5df2\u542f\u7528', disabled: '\u5df2\u5173\u95ed',
  wired: '\u5df2\u63a5\u7ebf', unwired: '\u672a\u63a5\u7ebf',
  ml: 'ML', warnings: '\u8986\u76d6\u7f3a\u53e3',
}
const channelLabels: Record<string, string> = {
  chat: 'Chat', mcp: 'MCP', skill: 'Skill',
  forward_proxy: '\u6b63\u5411\u4ee3\u7406', reverse_proxy: '\u53cd\u5411\u4ee3\u7406',
}

function modeLabel(mode: PostureMode) {
  if (mode === 'mixed') return text.mixed
  return mode === 'unknown' ? text.unknown : securityModeLabel(mode)
}
function boolLabel(value: boolean | null | undefined) {
  return value === true ? text.enabled : value === false ? text.disabled : text.unknown
}

export default function SecurityPostureCard() {
  const identity = useAuditQueryIdentity()
  const query = useQuery({
    queryKey: ['security-posture', identity], queryFn: securityPostureApi.get,
    refetchInterval: 30_000, retry: false,
  })
  const posture = query.isError ? undefined : query.data
  return (
    <section className="security-posture-card" aria-label={text.title}>
      <div className="security-posture-heading">
        <h2>{text.title}</h2>
        <div>
          <Tag color={posture?.runtime_verified ? 'green' : 'default'}>{posture?.runtime_verified ? text.verified : text.unknown}</Tag>
          <Tooltip title={text.refresh}><Button data-testid="posture-refresh" aria-label={text.refresh} icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()} /></Tooltip>
        </div>
      </div>
      {query.isError ? <Alert data-testid="posture-load-error" type="error" showIcon message={text.failed} /> : null}
      {query.isLoading ? <div className="security-posture-loading"><Spin /></div> : null}
      {posture ? <>
        <table className="security-posture-table">
          <thead><tr>{[text.channel, text.configured, text.effective, text.failure, text.controls].map((label) => <th key={label}>{label}</th>)}</tr></thead>
          <tbody>{posture.channels.map((channel) => {
            const verified = channel.runtime_verified === true
            const effective = channel.effective_mode === 'mixed' ? 'mixed' : verified ? channel.effective_mode : 'unknown'
            return <tr key={channel.id} data-testid={`posture-channel-${channel.id}`} data-verified={verified}>
              <th scope="row">{channelLabels[channel.id] || channel.id}</th>
              <td data-label={text.configured}><span>{modeLabel(channel.configured_mode)}</span></td>
              <td data-label={text.effective}><Tag data-testid={`posture-effective-${channel.id}`} data-mode={effective} color={effective === 'protect' ? 'green' : effective === 'record' || effective === 'mixed' ? 'gold' : 'default'}>{modeLabel(effective)}</Tag></td>
              <td data-label={text.failure}><div>{channel.fail_modes.map((failure) => {
                const mode = verified ? failure.mode : 'unknown'
                return <div className="security-posture-fact" key={failure.id} data-testid={`posture-fail-${channel.id}-${failure.id}`} data-mode={mode}><code>{failure.id}</code><span>{mode === 'unknown' ? text.unknown : mode}</span></div>
              })}</div></td>
              <td data-label={text.controls}><div>{channel.controls.map((control) => {
                const enabled = verified ? control.enabled : null
                const wired = verified ? control.wired : null
                return <div className="security-posture-fact" key={control.id} data-testid={`posture-control-${channel.id}-${control.id}`} data-enabled={enabled ?? 'unknown'} data-wired={wired ?? 'unknown'}>
                  <code>{control.id}</code><span>{boolLabel(enabled)} / {wired === true ? text.wired : wired === false ? text.unwired : text.unknown}</span>
                </div>
              })}</div></td>
            </tr>
          })}</tbody>
        </table>
        <div className="security-posture-ml" aria-label={text.ml}>
          <strong>{text.ml}</strong>{posture.ml_layers.map((layer) => {
            const enabled = layer.runtime_verified ? layer.runtime_enabled : null
            return <span key={layer.id} data-testid={`posture-ml-${layer.id}`} data-enabled={enabled ?? 'unknown'}><code>{layer.id}</code><span>{text.configured}: {boolLabel(layer.configured_enabled)}</span><span>{text.effective}: {boolLabel(enabled)}</span></span>
          })}
        </div>
        {posture.warnings.length ? <Alert className="security-posture-warnings" data-testid="posture-warnings" type="warning" showIcon message={text.warnings} description={<ul>{posture.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>} /> : null}
        <time className="security-posture-time" dateTime={posture.generated_at}>{new Date(posture.generated_at).toLocaleString('zh-CN')}</time>
      </> : null}
    </section>
  )
}
