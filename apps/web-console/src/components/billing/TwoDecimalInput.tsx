import { InputNumber, type InputNumberProps } from 'antd'

type TwoDecimalInputProps = Omit<InputNumberProps<number>, 'precision' | 'formatter' | 'parser' | 'stringMode' | 'changeOnBlur'>

const inputText = (value: string) => value.replace(/。/g, '.').replace(/,/g, '').replace(/(\.\d{2})\d+/g, '$1')
const formatter: NonNullable<InputNumberProps<number>['formatter']> = (value, info) => {
  if (info.userTyping) return inputText(info.input)
  return value == null || String(value) === '' || !Number.isFinite(Number(value)) ? '' : Number(value).toFixed(2)
}
const parser: NonNullable<InputNumberProps<number>['parser']> = value => {
  const text = inputText(value || '')
  // 空白文本（空格、制表、换行）视为「空」；Number(' ') 是 0，会把价格悄悄清零。
  return text.trim() === '' ? '' as unknown as number : Number(text)
}

// Display two decimals without modifying an existing precise value on focus,
// blur, Enter or an unrelated form save. Only a deliberate edit changes it.
export default function TwoDecimalInput({ onChange, onInput, onKeyDownCapture, onPasteCapture, ...props }: TwoDecimalInputProps) {
  return <InputNumber<number> {...props} precision={2} step={props.step ?? 0.01} changeOnBlur={false}
    formatter={formatter} parser={parser}
    onChange={onChange}
    onInput={onInput}
    onKeyDownCapture={event => {
      onKeyDownCapture?.(event)
      if (event.defaultPrevented) return
      if (event.key === 'Enter') {
        event.stopPropagation()
        props.onPressEnter?.(event)
        return
      }
      if (/^[0-9.]$/.test(event.key) && !event.ctrlKey && !event.metaKey && !event.altKey) {
        const input = event.target as HTMLInputElement
        const start = input.selectionStart ?? input.value.length
        const end = input.selectionEnd ?? start
        const next = input.value.slice(0, start) + event.key + input.value.slice(end)
        if (!/^-?\d*(\.\d{0,2})?$/.test(next)) event.preventDefault()
      }
    }}
    onPasteCapture={event => {
      onPasteCapture?.(event)
      if (event.defaultPrevented || props.disabled || props.readOnly) return
      const input = event.target as HTMLInputElement
      const start = input.selectionStart ?? 0
      const end = input.selectionEnd ?? input.value.length
      const text = input.value.slice(0, start) + event.clipboardData.getData('text').trim() + input.value.slice(end)
      if (text.trim() === '') {
        // 粘贴空白后整体为空：按「清空」处理，Number('') 是 0，不能当成 0。
        event.preventDefault()
        onChange?.(null)
        return
      }
      if (/^-?\d*(\.\d*)?$/.test(text) && Number.isFinite(Number(text))) {
        event.preventDefault()
        onChange?.(Number(Number(text).toFixed(2)))
      }
    }} />
}


type TwoDecimalStringInputProps = Omit<InputNumberProps<string>, 'precision' | 'formatter' | 'parser' | 'stringMode' | 'changeOnBlur'>

function stringToTwoDecimals(value: string): string {
  const match = /^(-?)(\d+)(?:\.(\d*))?$/.exec(value)
  if (!match) return Number.isFinite(Number(value)) ? Number(value).toFixed(2) : ''
  const fraction = (match[3] || '').padEnd(3, '0')
  const cents = BigInt(match[2]) * 100n + BigInt(fraction.slice(0, 2)) + (fraction[2] >= '5' ? 1n : 0n)
  return `${match[1]}${cents / 100n}.${(cents % 100n).toString().padStart(2, '0')}`
}

// Budgets use decimal strings so large amounts retain their exact micro-unit value.
export function TwoDecimalStringInput({ onChange, onInput, onKeyDownCapture, onPasteCapture, ...props }: TwoDecimalStringInputProps) {
  return <InputNumber<string> {...props} stringMode precision={2} step={props.step ?? '0.01'} changeOnBlur={false}
    formatter={(value, info) => info.userTyping ? inputText(info.input) : value == null || value === '' ? '' : stringToTwoDecimals(value)}
    parser={value => inputText(value || '')}
    onChange={onChange}
    onInput={onInput}
    onKeyDownCapture={event => {
      onKeyDownCapture?.(event)
      if (event.defaultPrevented) return
      if (event.key === 'Enter') {
        event.stopPropagation()
        props.onPressEnter?.(event)
        return
      }
      if (/^[0-9.]$/.test(event.key) && !event.ctrlKey && !event.metaKey && !event.altKey) {
        const input = event.target as HTMLInputElement
        const start = input.selectionStart ?? input.value.length
        const end = input.selectionEnd ?? start
        const next = input.value.slice(0, start) + event.key + input.value.slice(end)
        if (!/^-?\d*(\.\d{0,2})?$/.test(next)) event.preventDefault()
      }
    }}
    onPasteCapture={event => {
      onPasteCapture?.(event)
      if (event.defaultPrevented || props.disabled || props.readOnly) return
      const input = event.target as HTMLInputElement
      const start = input.selectionStart ?? 0
      const end = input.selectionEnd ?? input.value.length
      const text = input.value.slice(0, start) + event.clipboardData.getData('text').trim() + input.value.slice(end)
      if (/^-?\d+(\.\d*)?$/.test(text)) {
        event.preventDefault()
        onChange?.(stringToTwoDecimals(text))
      }
    }} />
}
