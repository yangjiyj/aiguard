// W8 8.7：审计页通用的时间筛选与服务端全量导出按钮。
// 导出不在前端拼数据：按当前筛选条件请求服务端，由服务端全量生成 CSV / XLSX 并写操作审计。
import { useState } from 'react'
import { Button, DatePicker, Space, Typography, message } from 'antd'
import { DownloadOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import type { ReportExportFormat } from '../services/api'
import { downloadBlob, safeFilename } from '../utils/reportExport'
import { nowInTimezone } from '../utils/ws8ReportRange'
import type { AuditDateRange } from '../utils/ws8ReportRange'

const { RangePicker } = DatePicker
const { Text } = Typography

// 类型与 auditRangeParams 放在 utils/ws8ReportRange（本文件只导出组件，满足 react-refresh 规则）。
export type { AuditDateRange } from '../utils/ws8ReportRange'

export function AuditDateRangeFilter({ value, onChange, timezone }: { value: AuditDateRange; onChange: (next: AuditDateRange) => void; timezone?: string }) {
  return (
    <Space size={4}>
      <RangePicker
        aria-label="时间范围"
        allowClear
        value={value ? [dayjs(value[0]), dayjs(value[1])] : null}
        disabledDate={(current) => Boolean(current) && current.isAfter(dayjs().endOf('day'))}
        onChange={(dates) => {
          if (!dates || !dates[0] || !dates[1]) onChange(null)
          else onChange([dates[0].format('YYYY-MM-DD'), dates[1].format('YYYY-MM-DD')])
        }}
      />
      {timezone ? <Text type="secondary" style={{ fontSize: 12 }}>{timezone}</Text> : null}
    </Space>
  )
}

async function blobErrorMessage(error: any): Promise<string> {
  const status = error?.response?.status
  const data = error?.response?.data
  if (status === 413) return '符合条件的记录超过 10 万条，请缩小时间范围后再导出'
  if (status === 403) return '当前账号没有导出权限'
  if (data instanceof Blob) {
    try {
      const parsed = JSON.parse(await data.text())
      return parsed?.error?.message || parsed?.message || '导出失败，请重试'
    } catch {
      return '导出失败，请重试'
    }
  }
  return '导出失败，请重试'
}

export function ServerExportButton({ name, timezone, run }: {
  name: string
  timezone?: string
  run: (format: ReportExportFormat) => Promise<{ data: Blob }>
}) {
  const [busy, setBusy] = useState(false)
  const exportAs = async (format: ReportExportFormat) => {
    setBusy(true)
    try {
      const response = await run(format)
      downloadBlob(response.data, safeFilename([name, nowInTimezone(timezone, 'YYYYMMDD-HHmmss')]) + '.' + format)
      message.success('已按当前筛选条件导出全部记录，本次导出已写入操作审计')
    } catch (error) {
      message.error(await blobErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Space size={4}>
      <Button icon={<DownloadOutlined />} loading={busy} onClick={() => void exportAs('csv')}>导出 CSV</Button>
      <Button icon={<DownloadOutlined />} loading={busy} onClick={() => void exportAs('xlsx')}>导出 Excel</Button>
    </Space>
  )
}
