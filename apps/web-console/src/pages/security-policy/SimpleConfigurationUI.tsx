import { Alert, Button, Modal, Segmented } from 'antd'
import { Link } from 'react-router-dom'
import type { SaveItemResult } from './simpleConfigurationModel'

export type ScenarioActionOption<T extends string> = {
  value: T
  label: string
}

export type ScenarioActionRowProps<T extends string> = {
  title: string
  description: string
  effectiveLabel: string
  effectiveLabelPrefix?: string
  configuredLabel?: string
  configuredLabelPrefix?: string
  recordHref?: string
  recordLinkLabel?: string
  mismatchReason?: string
  value: T
  options: ScenarioActionOption<T>[]
  disabled?: boolean
  onChange: (value: T) => void
}

export function ScenarioActionRow<T extends string>({
  title,
  description,
  effectiveLabel,
  effectiveLabelPrefix,
  configuredLabel,
  configuredLabelPrefix,
  recordHref,
  recordLinkLabel = '查看命中记录',
  mismatchReason,
  value,
  options,
  disabled = false,
  onChange,
}: ScenarioActionRowProps<T>) {
  const differs = Boolean(mismatchReason || (configuredLabel && configuredLabel !== effectiveLabel))
  return (
    <section className="simple-config-scenario-row" aria-label={title}>
      <div className="simple-config-scenario-copy">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
      <div className="simple-config-scenario-status">
        {(differs || configuredLabelPrefix) && configuredLabel ? <span>{configuredLabelPrefix ?? "已配置"}：{configuredLabel}</span> : null}
        <strong>{effectiveLabelPrefix ?? '当前生效'}：{effectiveLabel}</strong>
        {mismatchReason ? <span className="simple-config-mismatch">{mismatchReason}</span> : null}
        {recordHref ? <Link className="simple-config-record-link" to={recordHref}>{recordLinkLabel}</Link> : null}
      </div>
      <Segmented<T>
        aria-label={`${title}处理方式`}
        block
        disabled={disabled}
        value={value}
        options={options}
        onChange={(nextValue) => onChange(nextValue)}
      />
    </section>
  )
}

export type SaveImpactChange = {
  key: string
  label: string
  from: string
  to: string
}

export type SaveImpactDialogProps = {
  open: boolean
  changes: SaveImpactChange[]
  impact: string
  notice?: string
  confirmLoading?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export function SaveImpactDialog({
  open,
  changes,
  impact,
  notice,
  confirmLoading = false,
  onConfirm,
  onCancel,
}: SaveImpactDialogProps) {
  return (
    <Modal
      title="确认保存全部调整"
      open={open}
      okText="确认保存"
      cancelText="取消"
      confirmLoading={confirmLoading}
      onOk={onConfirm}
      onCancel={onCancel}
    >
      {notice ? <Alert type="warning" showIcon message={notice} /> : null}
      <p>{impact}</p>
      <ul className="simple-config-impact-list">
        {changes.map((change) => (
          <li key={change.key}>{change.label}：{change.from} -&gt; {change.to}</li>
        ))}
      </ul>
    </Modal>
  )
}

export type SaveResultBannerProps = {
  results: SaveItemResult[]
  itemLabels: Record<string, string>
  onRetry?: (keys: string[]) => void
}

export function SaveResultBanner({ results, itemLabels, onRetry }: SaveResultBannerProps) {
  if (results.length === 0) return null
  const saved = results.filter((result) => result.status === 'saved')
  const failed = results.filter((result) => result.status !== 'saved')
  const failedKeys = failed.map((result) => result.key)
  const label = (key: string) => itemLabels[key] || key
  const description = (
    <div className="simple-config-save-result">
      {saved.length > 0 ? <p>已保存：{saved.map((result) => label(result.key)).join('、')}</p> : null}
      {failed.length > 0 ? (
        <p>未保存：{failed.map((result) => `${label(result.key)}${result.message ? `（${result.message}）` : ''}`).join('、')}</p>
      ) : null}
      {failed.length > 0 && onRetry ? (
        <Button size="small" onClick={() => onRetry(failedKeys)}>重试未保存项</Button>
      ) : null}
    </div>
  )
  return (
    <Alert
      showIcon
      type={failed.length > 0 ? 'warning' : 'success'}
      message={failed.length > 0 ? '部分调整未保存' : '全部保存成功'}
      description={description}
    />
  )
}
