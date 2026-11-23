import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import TwoDecimalInput from '../components/billing/TwoDecimalInput'

afterEach(cleanup)

// 现场价格被清零的根因之一：空白文本被解析成 0。
describe('TwoDecimalInput 空白文本不得变成 0', () => {
  function Editor({ initial = null, onChange }: { initial?: number | null; onChange: (value: number | null) => void }) {
    const [value, setValue] = useState<number | null>(initial)
    return <TwoDecimalInput aria-label="价格" value={value} onChange={next => { onChange(next); setValue(next) }} />
  }

  it.each([[' '], ['   '], ['\t'], ['\n']])('在空框里输入空白 %j 得到空值而不是 0', async text => {
    const user = userEvent.setup()
    const change = vi.fn()
    render(<Editor onChange={change} />)
    const input = screen.getByRole('spinbutton')
    await user.click(input)
    await user.paste(text)
    expect(change).not.toHaveBeenCalledWith(0)
    await user.tab()
    expect(input).toHaveValue('')
  })

  it('敲一个空格不会让受控值变成 0', async () => {
    const user = userEvent.setup()
    const change = vi.fn()
    render(<Editor onChange={change} />)
    const input = screen.getByRole('spinbutton')
    await user.type(input, ' ')
    expect(change).not.toHaveBeenCalledWith(0)
    await user.tab()
    expect(change).not.toHaveBeenCalledWith(0)
    // 输入框里可能残留肉眼不可见的空格，但受控值不是 0
    expect((input as HTMLInputElement).value.trim()).toBe('')
  })

  it('全选后粘贴空白文本按清空处理（null），不是 0', async () => {
    const user = userEvent.setup()
    const change = vi.fn()
    render(<Editor initial={3} onChange={change} />)
    const input = screen.getByRole('spinbutton')
    await user.click(input)
    await user.keyboard('{Control>}a{/Control}')
    await user.paste('   ')
    expect(change).toHaveBeenLastCalledWith(null)
    expect(change).not.toHaveBeenCalledWith(0)
    expect(input).toHaveValue('')
  })

  it('既有行为不变：合法数字粘贴仍按两位小数取整，输入 0 仍是 0', async () => {
    const user = userEvent.setup()
    const change = vi.fn()
    render(<Editor initial={3} onChange={change} />)
    const input = screen.getByRole('spinbutton')
    await user.click(input)
    await user.keyboard('{Control>}a{/Control}')
    await user.paste('1.238')
    expect(change).toHaveBeenLastCalledWith(1.24)
    await user.clear(input)
    await user.type(input, '0')
    expect(change).toHaveBeenLastCalledWith(0)
  })
})
