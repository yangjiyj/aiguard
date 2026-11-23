import { Card, Tag, Space, Typography, Spin, Alert } from "antd"
import { Link } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { SafetyCertificateOutlined, ApartmentOutlined, ArrowRightOutlined } from "@ant-design/icons"
import { identityApi, directoryApi, type IdentityOverview } from "../services/api"
import { EnterprisePageHeader } from "../components/EnterpriseUI"
import IdentityEgressSettings from "../components/identity/IdentityEgressSettings"
import { useAccess } from "../hooks/useAccess"

const { Text } = Typography

function toArr(r: any): any[] {
  if (Array.isArray(r?.data)) return r.data
  if (Array.isArray(r?.items)) return r.items
  if (Array.isArray(r)) return r
  return []
}

// 状态标签映射：后端 overview 返回的权威 state -> 客户可见中文标签 + 颜色。
const STATE_LABELS: Record<string, { text: string; color: string }> = {
  unconfigured: { text: "未配置", color: "default" },
  draft: { text: "草稿", color: "orange" },
  tested: { text: "测试通过", color: "blue" },
  active: { text: "启用中", color: "green" },
  abnormal: { text: "异常", color: "red" },
}

// 任务 12：总览页只展示后端权威 overview 状态 + 客户可执行建议。
// 不再从 sources/directory 列表前端推断状态，避免与运行态真相不一致。
export default function IdentitySources() {
  // overview 是权威状态源；directoryApi.getDraft 仅用于展示 display_name。
  const overviewQ = useQuery({ queryKey: ["identity-overview"], queryFn: () => identityApi.getOverview() })
  const sourcesQ = useQuery({ queryKey: ["identity-sources"], queryFn: () => identityApi.getSources() })
  const directoryQ = useQuery({ queryKey: ["directory-draft"], queryFn: () => directoryApi.getDraft() })
  // 出站地址存在系统设置里，写入沿用系统设置的权限（系统管理员）。
  // 与后端 UpdateSystemSettings 一致，只认平台管理员。
  const canManageEgress = useAccess().canWriteSystemSettings

  const overview: IdentityOverview | undefined =
    overviewQ.data?.data ?? (overviewQ.data as any)
  const sources = toArr(sourcesQ.data?.data)
  const directory = directoryQ.data?.data?.data ?? directoryQ.data?.data

  const login = overview?.login
  const directoryState = overview?.directory
  const reconciliationRequired = overview?.reconciliation_required ?? 0

  const loginLabel = STATE_LABELS[login?.state ?? "unconfigured"] ?? STATE_LABELS.unconfigured
  const directoryLabel = STATE_LABELS[directoryState?.state ?? "unconfigured"] ?? STATE_LABELS.unconfigured

  const loading = overviewQ.isLoading

  return (
    <div>
      <EnterprisePageHeader
        eyebrow="身份与访问"
        title="企业身份源"
        description="统一接入企业 SSO 与目录账号源。每个身份源独立配置与启用，互不影响。"
      />

      {reconciliationRequired > 0 ? (
        <Alert
          style={{ marginBottom: 16 }}
          type="warning"
          showIcon
          message={`有 ${reconciliationRequired} 个账号需要重新对账`}
          description="目录同步或身份绑定过程中出现需人工复核的账号，请在用户管理中处理。"
        />
      ) : null}

      {loading ? (
        <Spin />
      ) : (
        <Space size={16} wrap align="start" style={{ display: "flex" }}>
          <Card
            style={{ width: 380 }}
            title={<Space><SafetyCertificateOutlined /><span>企业 SSO</span></Space>}
            extra={<Link to="/identity-sources/login">配置 <ArrowRightOutlined /></Link>}
          >
            <Space direction="vertical" size={12} style={{ width: "100%" }}>
              <div>
                <Tag color={loginLabel.color}>{loginLabel.text}</Tag>
                {login?.state === "active" && login.runtime_healthy === false ? (
                  <Tag color="volcano">运行态不可达</Tag>
                ) : null}
              </div>
              <Text type="secondary">通过标准 OIDC 协议接入企业统一身份，支持部门属性映射。</Text>
              <Text strong>
                {sources.find((s: any) => s.status === "active")?.display_name || "尚未配置"}
              </Text>
              {(login?.state === "active" || login?.state === "abnormal") && login.runtime_message ? (
                <Text type="warning" style={{ fontSize: 12 }}>{login.runtime_message}</Text>
              ) : null}
            </Space>
          </Card>

          <Card
            style={{ width: 380 }}
            title={<Space><ApartmentOutlined /><span>目录账号</span></Space>}
            extra={<Link to="/identity-sources/directory">配置 <ArrowRightOutlined /></Link>}
          >
            <Space direction="vertical" size={12} style={{ width: "100%" }}>
              <div>
                <Tag color={directoryLabel.color}>{directoryLabel.text}</Tag>
                {directoryState?.state === "active" && directoryState.runtime_healthy === false ? (
                  <Tag color="volcano">运行态不可达</Tag>
                ) : null}
              </div>
              <Text type="secondary">连接企业 AD 或 LDAP，按同步范围将目录账号映射到 JJDGuard。</Text>
              <Text strong>{directory?.display_name || "尚未配置"}</Text>
              {directoryState?.last_sync_summary ? (
                <Text type="secondary" style={{ fontSize: 12 }}>
                  最近同步：新增 {directoryState.last_sync_summary.created}、更新 {directoryState.last_sync_summary.updated}、禁用 {directoryState.last_sync_summary.disabled}、冲突 {directoryState.last_sync_summary.conflicts}
                </Text>
              ) : null}
              {(directoryState?.state === "active" || directoryState?.state === "abnormal") && directoryState.runtime_message ? (
                <Text type="warning" style={{ fontSize: 12 }}>{directoryState.runtime_message}</Text>
              ) : null}
            </Space>
          </Card>
        </Space>
      )}
      <IdentityEgressSettings canManage={canManageEgress} />
    </div>
  )
}
