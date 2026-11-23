import { Alert, Card, Col, Row, Statistic, Typography } from 'antd'
import { ApartmentOutlined, CheckCircleOutlined, WarningOutlined } from '@ant-design/icons'

interface Props {
  multiRouteModelCount: number
  exceptionCount: number
  defaultLabel: string
  unhealthyRouteCount?: number
}

export default function RoutingOverview({ multiRouteModelCount, exceptionCount, defaultLabel, unhealthyRouteCount }: Props) {
  return (
    <section aria-labelledby="routing-overview-title">
      <div className="model-routing-section-heading">
        <div>
          <Typography.Title id="routing-overview-title" level={5}>运行概览</Typography.Title>
          <Typography.Text type="secondary">后台按请求模型自动匹配健康线路，单线路模型无需配置。</Typography.Text>
        </div>
      </div>
      <Row gutter={[12, 12]}>
        <Col xs={24} sm={12} xl={6}><Card className="model-routing-stat"><Statistic title="多线路模型" value={multiRouteModelCount} prefix={<ApartmentOutlined />} suffix="个" /></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card className="model-routing-stat"><Statistic title="全局默认方式" value={defaultLabel} prefix={<CheckCircleOutlined />} /></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card className="model-routing-stat"><Statistic title="特殊配置" value={exceptionCount} suffix="个" /></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card className="model-routing-stat"><Statistic title="异常 / 熔断线路" value={unhealthyRouteCount ?? '—'} prefix={<WarningOutlined />} /></Card></Col>
      </Row>
      {unhealthyRouteCount == null && <Alert className="model-routing-health-note" type="info" showIcon message="异常线路统计接入后将在此显示；当前不以未知数据推断健康状态。" />}
    </section>
  )
}
