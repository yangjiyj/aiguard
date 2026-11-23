import { Alert, Button, Space, Typography } from 'antd'
import { MinusSquareOutlined, PlusSquareOutlined } from '@ant-design/icons'
import type { CursorPageState } from '../../hooks/useCursorPager'

// 计费控制台共享展示组件：从原 BillingOperations.tsx 原样迁出，行为不变。
const { Text } = Typography

export const Identifier = ({ value }: { value?: string }) => value ? <Text className="billing-identifier" code ellipsis={{ tooltip: value }} copyable={{ text: value }}>{value}</Text> : <Text type="secondary">—</Text>

// 游标分页条：翻页能力完全由服务端 has_more/next_cursor 决定。
// 服务端声称还有更多却没给游标时如实告警，绝不退化成「重新拉第一页」，
// 也不把这种情况显示成「已到最后一页」。
export const CursorPagerBar = ({ pager, unit }: { pager: CursorPageState; unit: string }) => {
  // 响应还没到（或查询失败）时不能对协议下结论：那会把「还没加载」说成
  // 「服务端不支持游标分页」。加载中不显示分页条，出错交给上层错误态处理。
  if (!pager.responded) return null
  if (!pager.cursorAware) return <Alert type="warning" showIcon style={{ marginTop: 12 }}
    message="游标分页协议异常" description="服务端本次响应没有游标信息，无法判断是否还有更多数据；当前只显示这一页，请缩小筛选范围或直接查询接口确认。" />
  return <div style={{ marginTop: 12 }}>
    {pager.blockedByMissingCursor ? <Alert type="warning" showIcon style={{ marginBottom: 8 }}
      message="服务端称还有更多数据但未返回游标" description="无法安全翻到下一页；重复请求第一页会重复或漏掉记录，请核查后端游标实现。" /> : null}
    <Space style={{ display: 'flex', justifyContent: 'space-between' }}>
      <Text type="secondary">第 {pager.pageIndex + 1} 页 · 本页 {pager.rows.length} 条{unit}{pager.cursorAware && !pager.hasMore && !pager.blockedByMissingCursor ? ' · 已到最后一页' : ''}</Text>
      <Space>
        {/* aria-label 固定可达名：antd 的 loading 图标会把按钮名变成「loading上一页」 */}
        <Button aria-label="上一页" disabled={!pager.canPrev} loading={pager.query.isFetching} onClick={pager.goPrev}>上一页</Button>
        <Button aria-label="下一页" disabled={!pager.hasMore} loading={pager.query.isFetching} onClick={pager.goNext}>下一页</Button>
      </Space>
    </Space>
  </div>
}

// 展开按钮的可达名固定为中文（antd 默认按语言包，测试或缺语言包时会露出英文）。
export function ZhExpandIcon({ expanded, expandable, record, onExpand }: any) {
  if (!expandable) return null
  return <Button type="text" size="small" aria-label={expanded ? '收起明细' : '展开明细'} aria-expanded={expanded}
    icon={expanded ? <MinusSquareOutlined /> : <PlusSquareOutlined />} onClick={(event) => onExpand(record, event)} />
}
