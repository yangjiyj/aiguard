// 只给策略中心的链接带事件编号，抽屉据此显示“本次命中”。命中内容本身不进网址。
export const withEvent = (path: string, eventId?: string) =>
  eventId && path.startsWith('/security/policies?') ? `${path}&event=${encodeURIComponent(eventId)}` : path
