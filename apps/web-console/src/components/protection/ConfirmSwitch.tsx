import type { ReactNode } from 'react'
import { Modal, Switch } from 'antd'
import { EGRESS_RISK_CONTENT } from './constants'

// 打开时先二次确认、关闭时直接生效的开关。可直接放进 Form.Item（valuePropName="checked"）。
// 确认框默认焦点在“取消”上，防止回车误开。
export default function ConfirmSwitch({
  checked,
  onChange,
  disabled,
  loading,
  confirmTitle,
  confirmContent = EGRESS_RISK_CONTENT,
  okText = '确认打开',
  ariaLabel,
  allowEnable = true,
}: {
  checked?: boolean
  onChange?: (checked: boolean) => void
  disabled?: boolean
  loading?: boolean
  confirmTitle: string
  confirmContent?: ReactNode
  okText?: string
  ariaLabel?: string
  // false：只能关、不能开（已打开的仍可关闭）。
  allowEnable?: boolean
}) {
  return (
    <Switch
      aria-label={ariaLabel}
      checked={Boolean(checked)}
      // 没传 disabled 时保持 undefined，让外层 Form 的禁用状态生效。
      disabled={!allowEnable && !checked ? true : disabled}
      loading={loading}
      onChange={(next) => {
        if (!next) {
          onChange?.(false)
          return
        }
        Modal.confirm({
          title: confirmTitle,
          content: confirmContent,
          okText,
          cancelText: '取消',
          okType: 'danger',
          autoFocusButton: 'cancel',
          onOk: () => onChange?.(true),
        })
      }}
    />
  )
}
