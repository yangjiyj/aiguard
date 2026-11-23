import { expect, it } from 'vitest'
import { REDLINE_LABELS } from '../pages/McpRedlineLabels'

it('names the configurable destructive command redline', () => {
  const label = REDLINE_LABELS.destructive_command
  expect(label).toBeDefined()
  expect(Array.from(label.title).map((char) => char.codePointAt(0))).toEqual([0x7834, 0x574f, 0x6027, 0x547d, 0x4ee4])
  expect(label.hint).toContain('rm -rf')
  expect(label.hint).toContain('DROP TABLE')
})
