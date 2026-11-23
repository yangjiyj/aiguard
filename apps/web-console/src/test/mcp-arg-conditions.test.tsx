import { describe, expect, it } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Form } from 'antd'
import McpArgConditionsEditor from '../pages/McpArgConditionsEditor'
import { fromArgConditions, toArgConditions } from '../pages/McpArgConditionUtils'

describe('MCP policy arg conditions (W1 1.12)', () => {
  it('converts form rows to typed conditions', () => {
    expect(toArgConditions([
      { path: '$.path', op: 'prefix', value: '/etc/' },
      { path: '$.rows', op: 'gt', value: '1000' },
      { path: '$.env', op: 'in', value: '["prod","staging"]' },
      { path: '$.force', op: 'exists', value: 'ignored' },
      { path: '$.recursive', op: 'eq', value: 'true' },
      { path: '$.name', op: 'eq', value: 'plain text' },
      { path: '', op: 'eq', value: 'dropped' },
    ])).toEqual([
      { path: '$.path', op: 'prefix', value: '/etc/' },
      { path: '$.rows', op: 'gt', value: 1000 },
      { path: '$.env', op: 'in', value: ['prod', 'staging'] },
      { path: '$.force', op: 'exists' },
      { path: '$.recursive', op: 'eq', value: true },
      { path: '$.name', op: 'eq', value: 'plain text' },
    ])
  })

  it('rejects malformed numeric and list values', () => {
    expect(() => toArgConditions([{ path: '$.n', op: 'gte', value: 'abc' }])).toThrow()
    expect(() => toArgConditions([{ path: '$.e', op: 'not_in', value: 'prod' }])).toThrow()
  })

  it('round-trips conditions back into editable rows', () => {
    const conds = [
      { path: '$.path', op: 'suffix' as const, value: '.pem' },
      { path: '$.n', op: 'lt' as const, value: 5 },
      { path: '$.x', op: 'not_exists' as const },
    ]
    expect(toArgConditions(fromArgConditions(conds))).toEqual(conds)
  })

  it('adds and removes condition rows', () => {
    function Harness() {
      const [form] = Form.useForm()
      return (
        <Form form={form} initialValues={{ arg_conditions: [] }}>
          <McpArgConditionsEditor />
        </Form>
      )
    }
    render(<Harness />)
    fireEvent.click(screen.getByRole('button', { name: /添加参数条件/ }))
    expect(screen.getByLabelText('参数路径 1')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '删除条件 1' }))
    expect(screen.queryByLabelText('参数路径 1')).toBeNull()
  })
})
