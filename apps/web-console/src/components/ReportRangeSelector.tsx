// W8 时间范围选择：预设档 + 自然周/月 + 自定义起止。口径见 utils/ws8ReportRange.ts。
import type { CSSProperties } from 'react'
import { DatePicker, Segmented, Space, Typography } from 'antd'
import dayjs from 'dayjs'
import type { CustomDateRange, ReportRangeKey } from '../utils/ws8ReportRange'
import { REPORT_RANGE_LABELS } from '../utils/ws8ReportRange'

const { Text } = Typography
const { RangePicker } = DatePicker

export interface ReportRangeSelectorProps {
  value: ReportRangeKey
  options: ReportRangeKey[]
  custom: CustomDateRange | null
  onChange: (key: ReportRangeKey, custom: CustomDateRange | null) => void
  label?: string
  timezone?: string
  style?: CSSProperties
}

export default function ReportRangeSelector({ value, options, custom, onChange, label = '统计范围', timezone, style }: ReportRangeSelectorProps) {
  return (
    <Space size={8} wrap style={style}>
      <Text type="secondary" style={{ fontSize: 12 }}>{label}</Text>
      <Segmented
        value={value}
        onChange={(next) => onChange(next as ReportRangeKey, next === 'custom' ? custom : null)}
        options={options.map((key) => ({ label: REPORT_RANGE_LABELS[key], value: key }))}
        style={{ maxWidth: '100%', overflowX: 'auto' }}
      />
      {value === 'custom' ? (
        <RangePicker
          aria-label="自定义起止日期"
          allowClear={false}
          value={custom ? [dayjs(custom[0]), dayjs(custom[1])] : null}
          disabledDate={(current) => Boolean(current) && current.isAfter(dayjs().endOf('day'))}
          onChange={(dates) => {
            if (!dates || !dates[0] || !dates[1]) return
            onChange('custom', [dates[0].format('YYYY-MM-DD'), dates[1].format('YYYY-MM-DD')])
          }}
        />
      ) : null}
      {timezone ? <Text type="secondary" style={{ fontSize: 12 }}>统计时区 {timezone}</Text> : null}
    </Space>
  )
}
