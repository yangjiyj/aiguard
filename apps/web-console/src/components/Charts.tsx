import { formatDecimalAmount, formatMicrosDecimal, UNKNOWN_MONEY } from '../utils/money'
import { useMemo, type ReactNode } from 'react'
import {
  ResponsiveContainer,
  AreaChart, Area,
  LineChart, Line,
  PieChart, Pie, Cell,
  BarChart, Bar, LabelList,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts'
import { theme } from 'antd'
import { billingTrendTheme } from '../utils/billingTrendTheme'
import { chartColor } from '../utils/chartPalette'
import { useThemeStore } from '../stores/theme'

const { useToken } = theme

// 排行条形图专用：单一品牌蓝色相梯度（深→浅按名次递减），避免绿/黄被误读为安全状态色
const RANKING_BLUES = ['#0958d9', '#1677ff', '#4096ff', '#69b1ff', '#91caff']

interface SeriesConfig {
  key: string
  label: string
  color?: string
}

interface BaseProps {
  height?: number
}

function useColors() {
  const { token } = useToken()
  const isDark = useThemeStore((state) => state.isDark)
  return {
    /** 按实体下标取色；第 7 个起统一「其他」色，不循环 */
    c: (index: number) => chartColor(isDark, index),
    text: token.colorTextSecondary,
    grid: token.colorBorderSecondary,
    tooltipBg: token.colorBgElevated,
    tooltipBorder: token.colorBorderSecondary,
  }
}

function formatDateTick(value: string) {
  // 2026-07-01 → 07-01
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return value.slice(5)
  return value
}

export function TrendArea({ data, series, height = 240, currencyFormatter }: BaseProps & {
  data: any[]
  series: SeriesConfig[]
  currencyFormatter?: (v: number) => string
}) {
  const colors = useColors()
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
        <defs>
          {series.map((s, i) => (
            <linearGradient key={s.key} id={`grad-${s.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={s.color || colors.c(i)} stopOpacity={0.3} />
              <stop offset="95%" stopColor={s.color || colors.c(i)} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
        <XAxis dataKey="date" tickFormatter={formatDateTick} tick={{ fontSize: 11, fill: colors.text }} />
        <YAxis tick={{ fontSize: 11, fill: colors.text }} width={56} />
        <Tooltip
          contentStyle={{ background: colors.tooltipBg, border: `1px solid ${colors.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
          labelFormatter={(value: any) => formatDateTick(String(value))}
          formatter={(value: any, name: any) => {
            const cfg = series.find((s) => s.label === name)
            if (cfg && currencyFormatter && cfg.key.includes('cost')) return [currencyFormatter(Number(value)), name]
            return [typeof value === 'number' ? value.toLocaleString() : value, name]
          }}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        {series.map((s, i) => (
          <Area
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.label}
            stroke={s.color || colors.c(i)}
            fill={`url(#grad-${s.key})`}
            strokeWidth={2}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function TrendLine({ data, series, height = 240 }: BaseProps & {
  data: any[]
  series: SeriesConfig[]
}) {
  const colors = useColors()
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
        <XAxis dataKey="date" tickFormatter={formatDateTick} tick={{ fontSize: 11, fill: colors.text }} />
        <YAxis tick={{ fontSize: 11, fill: colors.text }} width={56} />
        <Tooltip
          contentStyle={{ background: colors.tooltipBg, border: `1px solid ${colors.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
          labelFormatter={(value: any) => formatDateTick(String(value))}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        {series.map((s, i) => (
          <Line key={s.key} type="monotone" dataKey={s.key} name={s.label} stroke={s.color || colors.c(i)} strokeWidth={2} dot={false} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}

export function DistributionPie({ data, height = 240, unit, empty }: BaseProps & {
  data: { name: string; value: number; amount_micros?: number | string }[]
  unit?: string
  empty?: ReactNode
}) {
  const colors = useColors()
  const total = useMemo(() => data.reduce((sum, d) => sum + d.value, 0), [data])
  if (total === 0) {
    return <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: colors.text, fontSize: 13, textAlign: 'center', padding: '0 16px' }}>{empty || '所选范围内还没有可统计的数据'}</div>
  }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} innerRadius={40} label={({ percent }: any) => `${(percent * 100).toFixed(0)}%`} labelLine={false}>
          {data.map((_, i) => (
            <Cell key={i} fill={colors.c(i)} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: colors.tooltipBg, border: `1px solid ${colors.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
          formatter={(value: any, name: any, item: any) => [`${unit === '元' || unit === '美元' ? (item?.payload?.amount_micros != null ? formatMicrosDecimal(item.payload.amount_micros, { grouped: true }) : formatDecimalAmount(value, { grouped: true })) ?? UNKNOWN_MONEY : Number(value).toLocaleString()}${unit || ''}`, name]}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  )
}

export type RankedListItem = { name: string; value: number; key?: string }

export function RankedList({ data, height = 240, unit, onItemClick }: BaseProps & {
  data: RankedListItem[]
  unit?: string
  onItemClick?: (item: RankedListItem) => void
}) {
  const colors = useColors()
  const max = Math.max(...data.map((item) => item.value), 1)
  return (
    // 用 minHeight 而不是固定 height：行数由数据决定（最多 8 行约 285px），
    // 定高会让内容上下各溢出一半，顶部行直接压到面板标题/描述上（实测复现），
    // 底部行又被 .enterprise-section 的 overflow:hidden 裁掉。
    // minHeight 让短列表仍垂直居中、长列表把盒子撑高，不再溢出。
    <div className="chart-ranked-list" style={{ minHeight: height }}>
      {data.map((item, index) => {
        const content = (
          <>
            <span className={`chart-ranked-list-index${index < 3 ? ' chart-ranked-list-index--top' : ''}`}>{index + 1}</span>
            <span className="chart-ranked-list-main">
              <span className="chart-ranked-list-row">
                <span className="chart-ranked-list-name" title={item.name}>{item.name}</span>
                <span className="chart-ranked-list-value">{item.value.toLocaleString()}{unit || ''}</span>
              </span>
              <span className="chart-ranked-list-track" aria-hidden="true">
                <span className="chart-ranked-list-fill" style={{ width: `${Math.max((item.value / max) * 100, 2)}%`, background: RANKING_BLUES[index % RANKING_BLUES.length] }} />
              </span>
            </span>
          </>
        )
        return onItemClick ? (
          <button key={item.name} type="button" className="chart-ranked-list-item chart-ranked-list-item--interactive" onClick={() => onItemClick(item)} aria-label={`查看安全告警分类 ${item.name}`}>
            {content}
          </button>
        ) : (
          <div key={item.name} className="chart-ranked-list-item">{content}</div>
        )
      })}
      {data.length === 0 ? <div style={{ color: colors.text, fontSize: 13 }}>暂无数据</div> : null}
    </div>
  )
}

export function ModelShareRadial({ data, height = 240, unit }: BaseProps & {
  data: { name: string; value: number }[]
  unit?: string
}) {
  const colors = useColors()
  const total = useMemo(() => data.reduce((sum, item) => sum + item.value, 0), [data])
  const radialData = useMemo(() => data.map((item, index) => ({
    ...item,
    fill: colors.c(index),
  })), [data])
  if (total === 0) {
    return <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: colors.text, fontSize: 13 }}>暂无数据</div>
  }
  return (
    <div className="chart-model-share" style={{ height }}>
      <div className="chart-model-share-radial">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={radialData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius="58%" outerRadius="88%" startAngle={90} endAngle={-270} paddingAngle={1} stroke="none">
              {radialData.map((item, index) => <Cell key={index} fill={item.fill} />)}
            </Pie>
            <Tooltip
              contentStyle={{ background: colors.tooltipBg, border: `1px solid ${colors.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
              formatter={(value: any, _name: any, entry: any) => [`${Number(value).toLocaleString()}${unit || ''} · ${((Number(value) / total) * 100).toFixed(1)}%`, entry?.payload?.name || '']}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="chart-model-share-center">
          <span>模型调用</span>
          <strong>{total.toLocaleString()}</strong>
        </div>
      </div>
      <div className="chart-model-share-legend">
        {radialData.map((item) => (
          <div className="chart-model-share-legend-item" key={item.name}>
            <span className="chart-model-share-dot" style={{ background: item.fill }} />
            <span className="chart-model-share-name" title={item.name}>{item.name}</span>
            <strong>{((item.value / total) * 100).toFixed(1)}%</strong>
          </div>
        ))}
      </div>
    </div>
  )
}

export function RankingBar({ data, height = 240, unit, horizontal = true, onItemClick }: BaseProps & {
  data: { name: string; value: number }[]
  unit?: string
  horizontal?: boolean
  onItemClick?: (item: { name: string; value: number }) => void
}) {
  const colors = useColors()
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout={horizontal ? 'vertical' : 'horizontal'} margin={{ top: 8, right: horizontal ? 44 : 16, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} horizontal={!horizontal} vertical={horizontal} />
        {horizontal ? (
          <>
            <XAxis type="number" tick={{ fontSize: 11, fill: colors.text }} />
            <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: colors.text }} width={100} />
          </>
        ) : (
          <>
            <XAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: colors.text }} />
            <YAxis type="number" tick={{ fontSize: 11, fill: colors.text }} width={56} />
          </>
        )}
        <Tooltip
          contentStyle={{ background: colors.tooltipBg, border: `1px solid ${colors.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
          formatter={(value: any) => [`${Number(value).toLocaleString()}${unit || ''}`, '']}
          cursor={{ fill: colors.grid, opacity: 0.3 }}
        />
        <Bar dataKey="value" radius={horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]}>
          {data.map((item, i) => (
            <Cell
              key={i}
              fill={RANKING_BLUES[i % RANKING_BLUES.length]}
              onClick={() => onItemClick?.(item)}
              style={{ cursor: onItemClick ? 'pointer' : 'default' }}
            />
          ))}
          <LabelList
            dataKey="value"
            position={horizontal ? 'right' : 'top'}
            formatter={(v: any) => Number(v).toLocaleString()}
            style={{ fontSize: 11, fill: colors.text }}
          />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export type BillingTrendPoint = { date: string; cost: number; cost_micros?: number | string; tokens: number }

// 费用总览的计费金额趋势：左轴金额、右轴 Token，空态给出下一步动作。
export function BillingTrendChart({ data, currency, height = 260, empty }: BaseProps & {
  data: BillingTrendPoint[]
  currency: string
  empty?: ReactNode
}) {
  const colors = useColors()
  const theme = billingTrendTheme(currency)
  if (!data.length) {
    return <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: colors.text, fontSize: 13, textAlign: 'center', padding: '0 24px' }}>{empty || '所选时段还没有已计费调用。'}</div>
  }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: 8, bottom: 0 }}>
        <defs>
          <linearGradient id="grad-billing-cost" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={colors.c(0)} stopOpacity={0.3} />
            <stop offset="95%" stopColor={colors.c(0)} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
        <XAxis dataKey="date" tickFormatter={theme.axisDate} tick={{ fontSize: 11, fill: colors.text }} />
        <YAxis yAxisId="amount" tickFormatter={theme.amountTick} tick={{ fontSize: 11, fill: colors.text }} width={72} />
        <YAxis yAxisId="tokens" orientation="right" tickFormatter={theme.tokenTick} tick={{ fontSize: 11, fill: colors.text }} width={56} />
        <Tooltip
          contentStyle={{ background: colors.tooltipBg, border: `1px solid ${colors.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
          labelFormatter={(value: any) => theme.tooltipLabel(String(value))}
          formatter={(value: any, name: any, item: any) => [item?.dataKey === 'cost' ? item?.payload?.cost_micros != null ? theme.amountTooltipMicros(item.payload.cost_micros) : theme.amountTooltip(Number(value)) : theme.tokenTooltip(Number(value)), name]}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Area yAxisId="amount" type="monotone" dataKey="cost" name="计费金额" stroke={colors.c(0)} fill="url(#grad-billing-cost)" strokeWidth={2} />
        <Line yAxisId="tokens" type="monotone" dataKey="tokens" name="Token 用量" stroke={colors.c(1)} strokeWidth={1.5} dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

