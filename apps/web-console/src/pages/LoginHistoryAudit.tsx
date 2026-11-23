import { Tag } from "antd"
import { useQuery } from "@tanstack/react-query"
import dayjs from "dayjs"
import ResizableTable from "../components/ResizableTable"
import { EnterprisePageHeader } from "../components/EnterpriseUI"
import { loginHistoryAuditApi, type LoginHistoryAuditEntry } from "../services/api"

// W4: tenant-wide login history, read-only, for the auditor.
// Backend: GET /admin/v1/audit/login-history (SoD class login_history).
function LoginHistoryAudit() {
  const query = useQuery({
    queryKey: ["audit-login-history"],
    queryFn: () => loginHistoryAuditApi.list({ limit: 200 }).then((r) => r.data),
  })
  const rows: LoginHistoryAuditEntry[] = Array.isArray(query.data?.data) ? query.data!.data : []

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader eyebrow="审计合规" title="登录历史" />
      <div className="enterprise-section">
        <ResizableTable
          rowKey="id"
          size="small"
          loading={query.isLoading}
          dataSource={rows}
          locale={{ emptyText: "暂无登录记录" }}
          columns={[
            { title: "时间", dataIndex: "logged_at", key: "logged_at", width: 150, render: (t: string) => dayjs(t).format("YYYY-MM-DD HH:mm:ss") },
            { title: "用户", dataIndex: "username", key: "username", width: 130, ellipsis: true, render: (v: string, r: LoginHistoryAuditEntry) => v || r.user_id },
            { title: "IP", dataIndex: "ip", key: "ip", width: 125, ellipsis: true },
            {
              title: "结果",
              dataIndex: "success",
              key: "success",
              width: 76,
              render: (s: boolean) => <Tag color={s ? "green" : "red"}>{s ? "成功" : "失败"}</Tag>,
            },
            { title: "失败原因", dataIndex: "failure_reason", key: "failure_reason", ellipsis: true, render: (v?: string) => v || "-" },
            { title: "User-Agent", dataIndex: "user_agent", key: "user_agent", ellipsis: true },
          ]}
        />
      </div>
    </div>
  )
}

export default LoginHistoryAudit
