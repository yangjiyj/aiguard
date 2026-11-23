import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import TwoDecimalInput, { TwoDecimalStringInput } from '../components/billing/TwoDecimalInput'

afterEach(cleanup)

describe('two decimal billing inputs', () => {
  it('preserves exact decimal-string budgets across focus, blur and Enter, including the maximum amount', async () => {
    const user = userEvent.setup()
    const change = vi.fn()
    const view = render(<TwoDecimalStringInput value="9007199254.740991" onChange={change} />)
    const input = screen.getByRole('spinbutton')
    expect(input).toHaveValue('9007199254.74')
    await user.click(input)
    await user.keyboard('{Enter}')
    await user.tab()
    view.rerender(<TwoDecimalStringInput value="0.000001" onChange={change} />)
    expect(input).toHaveValue('0.00')
    await user.click(input)
    await user.keyboard('{Enter}')
    await user.tab()
    expect(change).not.toHaveBeenCalled()
  })

  it('limits deliberate decimal-string edits to two places and rounds numeric pastes', async () => {
    const user = userEvent.setup()
    const change = vi.fn()
    function Editor() {
      const [value, setValue] = useState<string | null>('1.234567')
      return <TwoDecimalStringInput value={value} onChange={next => { change(next); setValue(next) }} />
    }
    render(<Editor />)
    const input = screen.getByRole('spinbutton')
    await user.clear(input)
    await user.type(input, '2.1234')
    await user.tab()
    expect(input).toHaveValue('2.12')
    expect(change).toHaveBeenLastCalledWith('2.12')
    await user.click(input)
    await user.keyboard('{Control>}a{/Control}')
    await user.paste('9007199254.745001')
    expect(change).toHaveBeenLastCalledWith('9007199254.75')
  })

  it('preserves a precise existing value on focus, blur, Enter and unrelated rerenders', async () => {
    const user = userEvent.setup()
    const change = vi.fn()
    const view = render(<TwoDecimalInput aria-label="价格" value={1.234567} onChange={change} />)
    const input = screen.getByRole('spinbutton')
    expect(input).toHaveValue('1.23')
    await user.click(input)
    await user.tab()
    await user.click(input)
    await user.keyboard('{Enter}')
    view.rerender(<TwoDecimalInput aria-label="价格" value={0.000007} onChange={change} />)
    expect(input).toHaveValue('0.00')
    await user.keyboard('{Enter}')
    await user.tab()
    expect(change).not.toHaveBeenCalled()
  })

  it('accepts two decimal edits and blocks additional decimal digits', async () => {
    const user = userEvent.setup()
    const change = vi.fn()
    function Editor() {
      const [value, setValue] = useState<number | null>(1.234567)
      return <TwoDecimalInput aria-label="价格" value={value} onChange={next => { change(next); setValue(next) }} />
    }
    render(<Editor />)
    const input = screen.getByRole('spinbutton')
    await user.clear(input)
    await user.type(input, '2.123456')
    await user.tab()
    expect(input).toHaveValue('2.12')
    expect(change).toHaveBeenLastCalledWith(2.12)
  })

  it('rounds an explicit paste while keeping subsequent Enter from changing a newly loaded precise value', async () => {
    const user = userEvent.setup()
    const change = vi.fn()
    const view = render(<TwoDecimalInput value={0} onChange={change} />)
    const input = screen.getByRole('spinbutton')
    await user.click(input)
    await user.keyboard('{Control>}a{/Control}')
    await user.paste('1.238')
    expect(change).toHaveBeenLastCalledWith(1.24)
    change.mockClear()
    view.rerender(<TwoDecimalInput value={0.123456} onChange={change} />)
    await user.keyboard('{Enter}')
    await user.tab()
    expect(change).not.toHaveBeenCalled()
  })
})
