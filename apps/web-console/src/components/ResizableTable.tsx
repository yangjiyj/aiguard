import { useCallback, useEffect, useMemo, useState } from 'react'
import { Table } from 'antd'
import type { MouseEvent as ReactMouseEvent, ReactNode } from 'react'
import type { TableProps } from 'antd'
import type { ColumnGroupType, ColumnType, ColumnsType } from 'antd/es/table'

type WidthMap = Record<string, number>

type ResizableColumn<T extends object> = ColumnType<T> | ColumnGroupType<T>

type ResizableTableProps<T extends object> = TableProps<T> & {
  columnStorageKey?: string
  minColumnWidth?: number
  maxColumnWidth?: number
}

const getNumericWidth = (width: ColumnType<object>['width']) => {
  if (typeof width === 'number') return width
  if (typeof width === 'string' && /^\d+$/.test(width)) return Number(width)
  return undefined
}

const getColumnId = <T extends object>(column: ResizableColumn<T>, index: number) => {
  if (column.key !== undefined) return String(column.key)
  if ('dataIndex' in column) {
    const dataIndex = column.dataIndex
    if (Array.isArray(dataIndex)) return dataIndex.map(String).join('.')
    if (dataIndex !== undefined) return String(dataIndex)
  }
  return `column_${index}`
}

const getTitleLabel = (title: ReactNode, fallback: string) => {
  if (typeof title === 'string' || typeof title === 'number') return String(title)
  return fallback
}

function ResizableTable<T extends object>({
  columns = [],
  columnStorageKey,
  minColumnWidth = 72,
  maxColumnWidth = 520,
  scroll,
  ...rest
}: ResizableTableProps<T>) {
  const [columnWidths, setColumnWidths] = useState<WidthMap>(() => {
    if (!columnStorageKey || typeof window === 'undefined') return {}
    try {
      return JSON.parse(window.localStorage.getItem(columnStorageKey) || '{}') as WidthMap
    } catch {
      return {}
    }
  })

  useEffect(() => {
    if (!columnStorageKey || typeof window === 'undefined') return
    window.localStorage.setItem(columnStorageKey, JSON.stringify(columnWidths))
  }, [columnStorageKey, columnWidths])

  const startResize = useCallback((columnId: string, currentWidth: number, event: ReactMouseEvent<HTMLSpanElement>) => {
    event.preventDefault()
    event.stopPropagation()

    const startX = event.clientX
    const onMouseMove = (moveEvent: MouseEvent) => {
      const nextWidth = Math.min(maxColumnWidth, Math.max(minColumnWidth, currentWidth + moveEvent.clientX - startX))
      setColumnWidths((prev) => ({ ...prev, [columnId]: Math.round(nextWidth) }))
    }
    const onMouseUp = () => {
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
    }

    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
  }, [maxColumnWidth, minColumnWidth])

  const resizableColumns = useMemo(() => {
    const decorateColumn = (column: ResizableColumn<T>, index: number): ResizableColumn<T> => {
      if ('children' in column && column.children) {
        return {
          ...column,
          children: column.children.map((child, childIndex) => decorateColumn(child, childIndex)),
        }
      }
      if (typeof column.title === 'function') return column

      const columnId = getColumnId(column, index)
      // 没有显式宽度（也没有用户拖拽记录）的列保持弹性，由 antd 按容器宽度分配，
      // 表格才能随浏览器宽度自适应；不再强制 140px 默认宽把表格撑出视口。
      const userWidth = columnWidths[columnId]
      const explicitWidth = getNumericWidth((column as ColumnType<object>).width)
      if (userWidth === undefined && explicitWidth === undefined) return column
      const width = userWidth ?? explicitWidth
      const titleLabel = getTitleLabel(column.title, columnId)

      return {
        ...column,
        width,
        title: (
          <span className="resizable-table-title">
            <span className="resizable-table-title-content">{column.title}</span>
            <span
              aria-label={`拖拽调整列宽：${titleLabel}`}
              className="resizable-table-handle"
              role="separator"
              tabIndex={0}
              onMouseDown={(event) => startResize(columnId, width, event)}
            />
          </span>
        ),
      }
    }

    return columns.map((column, index) => decorateColumn(column, index)) as ColumnsType<T>
  }, [columns, columnWidths, startResize])

  const mergedScroll = useMemo(() => ({ x: 'max-content' as const, ...scroll }), [scroll])

  return <Table<T> {...rest} columns={resizableColumns} scroll={mergedScroll} />
}

export default ResizableTable
