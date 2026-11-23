import { describe, it, expect, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import ResizableTable from '../components/ResizableTable'

describe('ResizableTable', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  it('lets users resize a table column with the mouse and remembers the width', () => {
    render(
      <ResizableTable
        columnStorageKey="test-audit-table"
        dataSource={[{ id: 'row-1', request_id: 'req_001', model: 'qwen3.6-plus' }]}
        rowKey="id"
        pagination={false}
        columns={[
          { title: '请求ID', dataIndex: 'request_id', key: 'request_id', width: 120 },
          { title: '模型', dataIndex: 'model', key: 'model', width: 100 },
        ]}
      />,
    )

    const resizeHandle = screen.getByRole('separator', { name: '拖拽调整列宽：请求ID' })

    fireEvent.mouseDown(resizeHandle, { clientX: 100 })
    fireEvent.mouseMove(window, { clientX: 148 })
    fireEvent.mouseUp(window)

    expect(window.localStorage.getItem('test-audit-table')).toContain('"request_id":168')
  })
})
