import type { CSSProperties, ReactNode } from 'react'
import { Modal, Select } from 'antd'

// 改成放行类取值时先二次确认的下拉。可直接放进 Form.Item。确认框默认焦点在“取消”上。
export default function ConfirmSelect({
  value,
  onChange,
  options,
  riskyValues,
  confirmTitle,
  confirmContent,
  okText = '确认放行',
  ariaLabel,
  style,
  disabled,
}: {
  value?: string
  onChange?: (value: string) => void
  options: Array<{ value: string; label: string }>
  riskyValues: string[]
  confirmTitle: string
  confirmContent: ReactNode
  okText?: string
  ariaLabel?: string
  style?: CSSProperties
  disabled?: boolean
}) {
  return (
    <Select
      aria-label={ariaLabel}
      style={style}
      disabled={disabled}
      value={value}
      options={options}
      onChange={(next: string) => {
        if (next === value || !riskyValues.includes(next)) {
          onChange?.(next)
          return
        }
        Modal.confirm({
          title: confirmTitle,
          content: confirmContent,
          okText,
          cancelText: '取消',
          okType: 'danger',
          autoFocusButton: 'cancel',
          onOk: () => onChange?.(next),
        })
      }}
    />
  )
}
