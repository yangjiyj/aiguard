import { useEffect, useState } from 'react'
import { Alert, Typography } from 'antd'
import { consoleLoginSecurityApi, type PortalLoginBaselineReport } from '../../services/api'
import { PORTAL_BASELINE_TEXT } from './text'

// W3 3.8 (D7): upgrades never rewrite an installed portal realm. This notice only reports the gap and the
// operator command; it renders nothing when compliant, unavailable, or when the viewer lacks permission.
function PortalBaselineNotice() {
  const [report, setReport] = useState<PortalLoginBaselineReport | null>(null)

  useEffect(() => {
    let cancelled = false
    consoleLoginSecurityApi.portalBaseline()
      .then((response) => {
        if (!cancelled) setReport(response.data)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [])

  if (!report || report.status !== 'not_compliant') return null
  const gaps = (report.items ?? []).filter((item) => !item.compliant)

  return (
    <Alert
      type="warning"
      showIcon
      role="alert"
      message={PORTAL_BASELINE_TEXT.notMet}
      description={(
        <>
          <Typography.Paragraph style={{ marginBottom: 8 }}>{PORTAL_BASELINE_TEXT.detail}</Typography.Paragraph>
          {report.apply_hint && <Typography.Paragraph code copyable>{report.apply_hint}</Typography.Paragraph>}
          {gaps.length > 0 && (
            <ul data-testid="portal-baseline-gaps" style={{ margin: 0, paddingLeft: 20 }}>
              {gaps.map((item) => (
                <li key={item.key}>
                  <Typography.Text code>{item.key}</Typography.Text>
                  {': '}
                  {String(item.current ?? '-')}
                  {' -> '}
                  {String(item.target ?? '-')}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    />
  )
}

export default PortalBaselineNotice
