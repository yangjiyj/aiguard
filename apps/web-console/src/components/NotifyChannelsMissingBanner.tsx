import { Alert, Button } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useInRouterContext, useNavigate } from 'react-router-dom'
import { notifyApi } from '../services/api'

const NOTIFY_CHANNELS_PATH = '/system/notify-channels'

// 消息中心顶部常驻提示：租户 0 个告警通知渠道时，告警不会外发，只留在消息中心。
// 只在明确拿到「0 个渠道」时显示；接口失败（如无权限）时不显示，避免误导。
function GoConfigureButton() {
  const navigate = useNavigate()
  return (
    <Button size="small" type="primary" onClick={() => navigate(NOTIFY_CHANNELS_PATH)}>
      去配置
    </Button>
  )
}

export default function NotifyChannelsMissingBanner() {
  // 页面在应用路由内渲染时走前端跳转；脱离路由（如独立单测）时退化为普通链接。
  const inRouter = useInRouterContext()
  const { data } = useQuery({
    queryKey: ['notify-channels'],
    queryFn: async () => {
      const res = await notifyApi.list()
      return ((res.data as any)?.channels ?? []) as unknown[]
    },
    staleTime: 60_000,
    retry: false,
  })
  if (!Array.isArray(data) || data.length > 0) return null
  return (
    <Alert
      type="warning"
      showIcon
      role="alert"
      style={{ marginBottom: 16 }}
      message="尚未配置告警通知渠道，告警只会留在本页"
      action={
        inRouter ? <GoConfigureButton /> : (
          <Button size="small" type="primary" href={NOTIFY_CHANNELS_PATH}>去配置</Button>
        )
      }
    />
  )
}
