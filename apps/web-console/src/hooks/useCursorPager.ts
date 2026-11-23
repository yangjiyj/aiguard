import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

export type CursorPageState = {
  rows: any[]
  // 服务端是否声明了游标协议；false 表示本次响应没有 has_more，不能据此判断是否还有更多
  cursorAware: boolean
  // 可以点「下一页」：服务端 has_more 为真且给出了非空 next_cursor
  hasMore: boolean
  // 本页是否已拿到响应：false 表示还在加载/出错，上层不该下协议结论
  responded: boolean
  // 服务端声称还有更多但没给游标：如实暴露，绝不退化成回到第一页
  blockedByMissingCursor: boolean
  canPrev: boolean
  pageIndex: number
  goNext: () => void
  goPrev: () => void
  query: any
}

export function useCursorPager(options: {
  // 作用域标识（通常是租户 ID）：变化时整个游标栈作废
  scopeKey: string
  queryKey: unknown[]
  fetchPage: (cursor?: string) => Promise<any>
  enabled: boolean
}): CursorPageState {
  const { scopeKey, queryKey, fetchPage, enabled } = options
  const [state, setState] = useState<{ scope: string; stack: string[] }>({ scope: scopeKey, stack: [''] })
  // 切作用域（租户）时整个游标栈作废。
  // 关键：queryKey 里已经带了租户（['billing-customers', tenantID]），换租户
  // 本身就是一次新query，会以首cursor（空）重新取数。所以这里**不能**靠
  // 渲染期 setState 去纠正——那一帧会拿旧栈的 cursor 发一次跨租户请求，
  // 而且首cursor 被吃掉。改为：作用域不匹配时直接按首cursor 渲染，
  // 栈的同步放到 effect 里做，纯状态清理，不参与本次请求的游标计算。
  const scopeMatches = state.scope === scopeKey
  const stack = scopeMatches ? state.stack : ['']
  const pageIndex = stack.length - 1
  const cursor = stack[pageIndex] || ''
  useEffect(() => {
    setState((prev) => (prev.scope === scopeKey ? prev : { scope: scopeKey, stack: [''] }))
  }, [scopeKey])

  const query = useQuery({
    queryKey: [...queryKey, cursor],
    queryFn: () => fetchPage(cursor),
    enabled,
  })

  // 只有拿到这一页的响应才谈得上下游标协议：响应未到/出错时 cursorAware=false，
  // 上层显示加载态而不是谎称「未启用游标分页」
  const body: any = query.data?.data
  const responded = query.data !== undefined && query.data !== null
  const rows = Array.isArray(body?.data) ? body.data : []
  // has_more 必须是**布尔值**才认定服务端声明了游标协议；
  // 字符串/数字/缺失一律视为「没有游标信息」，绝不用 truthy 猜
  const cursorAware = responded && typeof body?.meta?.has_more === 'boolean'
  const serverHasMore = cursorAware && body.meta.has_more === true
  const nextCursor = typeof body?.meta?.next_cursor === 'string' ? body.meta.next_cursor : ''
  // 空游标串不算游标：has_more 为真却给不出可前进的令牌就是协议缺陷
  const usableNextCursor = nextCursor.trim() ? nextCursor : ''
  const blockedByMissingCursor = serverHasMore && !usableNextCursor

  return {
    rows,
    cursorAware,
    hasMore: serverHasMore && !!usableNextCursor,
    blockedByMissingCursor,
    canPrev: pageIndex > 0,
    pageIndex,
    responded,
    query,
    goNext: () => {
      if (!serverHasMore || !usableNextCursor) return
      setState((prev) => (
        prev.scope !== scopeKey || prev.stack.length !== pageIndex + 1
          ? prev
          : { scope: scopeKey, stack: [...prev.stack, usableNextCursor] }
      ))
    },
    goPrev: () => {
      setState((prev) => (
        prev.scope !== scopeKey || prev.stack.length <= 1
          ? prev
          : { scope: scopeKey, stack: prev.stack.slice(0, -1) }
      ))
    },
  }
}

export const CURSOR_PAGE_SIZE = 100