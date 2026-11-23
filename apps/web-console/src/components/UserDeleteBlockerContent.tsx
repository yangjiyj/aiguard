import { Space, Tag, Typography } from 'antd'

const { Text } = Typography

export interface DeleteBlockerItem {
  id?: string
  name?: string
  route?: string
}

export interface DeleteBlocker {
  kind?: string
  label?: string
  count?: number
  entry?: string
  action?: string
  route?: string
  items?: DeleteBlockerItem[]
}

export interface DeleteBlockerError {
  message?: string
  details?: {
    blockers?: DeleteBlocker[]
  }
}

const blockerRoute = (blocker: DeleteBlocker, item?: DeleteBlockerItem) => item?.route || blocker.route || ''

function UserDeleteBlockerContent({ error, onNavigate }: { error: DeleteBlockerError; onNavigate?: (route: string) => void }) {
  const renderRouteLink = (route: string) => (
    <a
      className="user-delete-blocker-action"
      href={route}
      onClick={(event) => {
        if (!onNavigate) return
        event.preventDefault()
        onNavigate(route)
      }}
    >去处理</a>
  )

  const blockers = Array.isArray(error.details?.blockers) ? error.details?.blockers || [] : []

  if (blockers.length === 0) {
    return <div style={{ whiteSpace: 'pre-line' }}>{error.message || '该用户仍有资源占用，请先处理后再删除。'}</div>
  }

  return (
    <div className="user-delete-blocker-content" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <Text>这个用户还占用下面这些资源，先点进去处理完再回来删。</Text>
      {blockers.map((blocker, index) => {
        const items = Array.isArray(blocker.items) ? blocker.items : []
        const fallbackRoute = blockerRoute(blocker)
        return (
          <div
            key={`${blocker.kind || blocker.label || index}`}
            className="user-delete-blocker-card"
            data-testid={`user-delete-blocker-${blocker.kind || index}`}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
              <Space size={6} wrap>
                <Tag color="warning">{blocker.label || '资源占用'}</Tag>
                <Text strong>{blocker.count || items.length} 个</Text>
                {blocker.entry && <Tag>{blocker.entry}</Tag>}
              </Space>
              {fallbackRoute && items.length === 0 && renderRouteLink(fallbackRoute)}
            </div>
            {blocker.action && <Text type="secondary" style={{ display: 'block', marginBottom: 8 }}>{blocker.action}</Text>}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {items.map((item) => {
                const route = blockerRoute(blocker, item)
                return (
                  <div
                    key={item.id || item.name || route}
                    style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}
                  >
                    <Text strong ellipsis style={{ minWidth: 0 }}>{item.name || item.id || '未命名资源'}</Text>
                    {route && renderRouteLink(route)}
                  </div>
                )
              })}
            </div>
            {(blocker.count || 0) > items.length && (
              <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
                还剩 {(blocker.count || 0) - items.length} 个同类资源，请进入页面筛选处理。
              </Text>
            )}
          </div>
        )
      })}
      <Text type="secondary">处理完上述资源后，可回到用户列表重新删除。</Text>
    </div>
  )
}

export default UserDeleteBlockerContent
