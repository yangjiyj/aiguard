import { Button, Space, type InputNumberProps } from 'antd'
import TwoDecimalInput from './TwoDecimalInput'

type Props = Pick<InputNumberProps<number>, 'value' | 'onChange' | 'disabled' | 'prefix' | 'id' | 'aria-label'>

export default function AllowanceAmountInput({ onChange, ...props }: Props) {
  return <Space.Compact block>
    <TwoDecimalInput {...props} onChange={onChange} min={0} max={1000000000} style={{ width: '100%', minWidth: 120 }} />
    {[100, 500, 1000].map(value => <Button key={value} disabled={props.disabled} onClick={() => onChange?.(value)}>{value}</Button>)}
  </Space.Compact>
}
