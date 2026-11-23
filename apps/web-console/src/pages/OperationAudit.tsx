import { useState } from "react"
import { Input, Select, Space, Tag, Typography } from "antd"
import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { useSearchParams } from "react-router-dom"
import ResizableTable from "../components/ResizableTable"
import { EnterprisePageHeader, SectionPanel, StatusPill } from "../components/EnterpriseUI"
import { AuditDateRangeFilter, ServerExportButton } from "../components/AuditExportControls"
import type { AuditDateRange } from "../components/AuditExportControls"
import { ws8AuditApi } from "../services/api"
import { useAuditQueryIdentity } from "../hooks/useAuditQueryIdentity"
import { auditRangeParams, formatInTimezone, useReportContext } from "../utils/ws8ReportRange"
import { AuditIntegrityStatusLine } from "../components/AuditIntegrityStatus"

const { Text } = Typography

const actionMap: Record<string, string> = {
  update_system_settings: "修改系统设置",
  update_semantic_settings: "修改语义检测配置",
  "evidence.read": "查阅证据原文",
  reveal_raw_evidence: "查看脱敏原文",
  update_raw_evidence_setting: "修改脱敏原文留证开关",
  "user.delete": "删除用户",
  "local_identity.cleanup_queued": "身份服务清理已排队重试",
  "local_identity.cleanup_exhausted": "身份服务清理重试失败",
  create_user: "创建用户",
  update_user: "修改用户",
  disable_user: "禁用用户",
  reset_password: "重置密码",
  change_password: "修改密码",
  create_project: "创建应用",
  update_project: "修改应用",
  delete_project: "删除应用",
  create_key: "创建密钥",
  revoke_key: "吊销密钥",
  delete_key: "删除密钥",
  create_provider: "创建渠道",
  update_provider: "修改渠道",
  rotate_provider_credential: "轮换渠道凭据",
  delete_provider: "删除渠道",
  delete_provider_rejected: "拒绝删除在用模型上游",
  restore_provider: "恢复模型上游",
  sync_models: "同步模型目录",
  model_routing_default_saved: "保存默认模型路由",
  model_routing_override_saved: "保存模型路由例外",
  model_routing_override_deleted: "删除模型路由例外",
  update_model_routing: "修改模型路由",
  update_model_status: "修改模型状态",
  update_model_pricing: "修改模型价格",
  update_model_proxy_config: "修改模型代理配置",
  delete_model: "删除模型",
  create_rule: "创建安全规则",
  update_rule: "修改安全规则",
  delete_rule: "删除安全规则",
  toggle_rule: "启停安全规则",
  "security_policy.create": "创建安全策略",
  "security_policy.update": "修改安全策略",
  "security_policy.batch_update": "批量修改安全策略",
  "security_policy.delete": "删除安全策略",
  batch_update_detector: "批量修改检测器",
  init_detectors: "初始化检测规则",
  create_tool_config: "创建工具策略",
  update_tool_config: "修改工具策略",
  delete_tool_config: "删除工具策略",
  batch_upsert_tool_configs: "批量导入工具策略",
  create_reverse_proxy_route: "创建反向代理路由",
  update_reverse_proxy_route: "修改反向代理路由",
  delete_reverse_proxy_route: "删除反向代理路由",
  create_proxy_whitelist: "创建历史代理策略",
  update_proxy_whitelist: "修改历史代理策略",
  delete_proxy_whitelist: "删除历史代理策略",
  generate_ca: "生成 CA 证书",
  "fx.update": "更新汇率",
  "audit_disposition.upsert": "更新处置状态",
  create_quota_policy: "创建配额策略",
  update_quota_policy: "修改配额策略",
  delete_quota_policy: "删除配额策略",
  upsert_routing_policy: "保存路由策略",
  delete_routing_policy: "删除路由策略",
  create_team: "创建部门",
  update_team: "修改部门",
  delete_team: "删除部门",
  create_tenant: "创建单位",
  update_tenant: "修改单位",
  login: "登录",
  logout: "退出登录",
  // W8 8.7：服务端全量导出的留痕记录。
  export_operation_audit: "导出操作审计",
  export_block_records: "导出阻断记录",
  export_alert_inbox: "导出消息中心",
  "alert_inbox.bulk_read": "批量标记消息已读",
  "billing.tariff.create": "新建资费草稿",
  "billing.tariff.edit": "编辑资费",
  "billing.tariff.publish": "发布资费",
  "billing.tariff.delete": "删除资费草稿",
  "billing.price.create": "新增模型价格版本",
  "billing.ratio_price.create": "新增倍率价格版本",
  "billing.price.zero_rejected": "拦截价格清零",
  "billing.price.unchanged": "价格未变化（未新增版本）",
}

const actionColor: Record<string, string> = {
  update_system_settings: "orange",
  update_semantic_settings: "orange",
  "evidence.read": "geekblue",
  reveal_raw_evidence: "red",
  update_raw_evidence_setting: "orange",
  "user.delete": "red",
  "local_identity.cleanup_queued": "gold",
  "local_identity.cleanup_exhausted": "red",
  create_user: "green",
  update_user: "blue",
  disable_user: "red",
  reset_password: "purple",
  change_password: "purple",
  create_project: "green",
  update_project: "blue",
  delete_project: "red",
  create_key: "green",
  revoke_key: "orange",
  delete_key: "red",
  create_provider: "green",
  update_provider: "blue",
  rotate_provider_credential: "gold",
  delete_provider: "red",
  delete_provider_rejected: "orange",
  restore_provider: "green",
  sync_models: "cyan",
  model_routing_default_saved: "blue",
  model_routing_override_saved: "blue",
  model_routing_override_deleted: "red",
  update_model_routing: "blue",
  update_model_status: "orange",
  update_model_pricing: "gold",
  update_model_proxy_config: "blue",
  delete_model: "red",
  create_rule: "green",
  update_rule: "blue",
  delete_rule: "red",
  toggle_rule: "orange",
  "security_policy.create": "green",
  "security_policy.update": "blue",
  "security_policy.batch_update": "gold",
  "security_policy.delete": "red",
  batch_update_detector: "gold",
  init_detectors: "cyan",
  create_tool_config: "green",
  update_tool_config: "blue",
  delete_tool_config: "red",
  batch_upsert_tool_configs: "cyan",
  create_reverse_proxy_route: "green",
  update_reverse_proxy_route: "blue",
  delete_reverse_proxy_route: "red",
  create_proxy_whitelist: "green",
  update_proxy_whitelist: "blue",
  delete_proxy_whitelist: "red",
  generate_ca: "purple",
  "fx.update": "gold",
  "audit_disposition.upsert": "blue",
}

const targetTypeMap: Record<string, string> = {
  system: "系统配置",
  settings: "系统设置",
  user: "用户",
  project: "应用",
  internal_key: "密钥",
  provider: "模型渠道",
  model: "模型",
  rule: "安全规则",
  rule_set: "安全规则集",
  security_policy: "安全策略",
  tool_call: "工具调用",
  fx_rate: "汇率设置",
}

const detailLabelMap: Record<string, string> = {
  security_audit_only: "安全审计模式",
  file_content_dlp_enabled: "文件内容 DLP",
  rules_created: "新增规则",
  effective_at: "生效时间",
  rate: "汇率",
  status: "处置状态",
  subject_id: "对象编号",
  subject_type: "对象类型",
  key_id: "密钥编号",
  change_summary: "价格变化",
  old_version: "原版本",
  model_name: "模型",
  zero_price_confirmed: "已确认改为 0",
  version: "新版本",
  policy_id: "策略编号",
  name: "名称",
}

const PAGE_SIZE = 20

// 时间一律按租户时区显示（W8 8.9），与导出文件一致。
function formatDate(value: string | undefined, timezone: string) {
  if (!value) return "-"
  if (Number.isNaN(new Date(value).getTime())) return value
  return formatInTimezone(value, timezone)
}

const CURRENCY_LABELS: Record<string, string> = {
  USD_CNY: "美元兑人民币",
  EUR_CNY: "欧元兑人民币",
  GBP_CNY: "英镑兑人民币",
  JPY_CNY: "日元兑人民币",
  HKD_CNY: "港币兑人民币",
}

function displayTargetId(value?: string) {
  if (!value) return "-"
  if (CURRENCY_LABELS[value]) return CURRENCY_LABELS[value]
  return value
}

function displayUser(value?: string, username?: string) {
  if (username && username.trim()) return username
  return value && value.trim() ? value : "系统任务"
}

function displayAction(value?: string) {
  if (!value) return "未知操作"
  return actionMap[value] || "系统操作"
}

function displayTargetType(value?: string) {
  if (!value) return "-"
  return targetTypeMap[value] || "业务对象"
}

function displayDetailValue(key: string, value: any, timezone: string) {
  if (value === undefined || value === null || value === "") return "-"
  if (key === "effective_at") return formatDate(String(value), timezone)
  if (key === "zero_price_confirmed") return value === true || value === "true" ? "是" : "否"
  if (typeof value === "object") return "已记录"
  return String(value)
}

function renderDetails(detail: any, timezone: string) {
  if (!detail || typeof detail !== "object") return <Text type="secondary">无补充详情</Text>
  const entries = Object.entries(detail).filter(([, value]) => value !== undefined && value !== null && value !== "")
  if (!entries.length) return <Text type="secondary">无补充详情</Text>
  return (
    <Space direction="vertical" size={2}>
      {entries.slice(0, 4).map(([key, value]) => (
        <Text key={key} style={{ fontSize: 12 }}>
          {detailLabelMap[key] || "补充信息"}：{displayDetailValue(key, value, timezone)}
        </Text>
      ))}
    </Space>
  )
}

function OperationAudit() {
  const auditIdentity = useAuditQueryIdentity()
  const [searchParams] = useSearchParams()
  const userIDParam = searchParams.get("user_id") || undefined
  const auditIDParam = searchParams.get("audit_id") || undefined
  const reportCtx = useReportContext()

  // W8 8.7：时间 / 操作人 / 操作类型 / 对象类型筛选，服务端分页；导出与列表共用同一组条件。
  const [range, setRange] = useState<AuditDateRange>(null)
  const [userID, setUserID] = useState<string | undefined>(userIDParam)
  const [actionType, setActionType] = useState<string | undefined>()
  const [targetType, setTargetType] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const filters = {
    ...auditRangeParams(range, reportCtx.timezone),
    ...(userID ? { user_id: userID } : {}),
    ...(actionType ? { action_type: actionType } : {}),
    ...(targetType ? { target_type: targetType } : {}),
  }

  const auditQ = useQuery({
    queryKey: ["audit-operations", auditIdentity, filters, page],
    queryFn: () => ws8AuditApi.listOperations({ ...filters, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }).then(r => r.data),
    placeholderData: keepPreviousData,
  })

  const rows: any[] = auditQ.data?.data || []
  const total = Number(auditQ.data?.total) || 0
  const resetPage = () => setPage(1)
  const configChanges = rows.filter((row: any) => ["system", "settings", "fx_rate", "rule_set"].includes(row.target_type)).length
  const userChanges = rows.filter((row: any) => String(row.target_type || "").includes("user") || String(row.action_type || "").includes("user")).length

  const cols = [
    {
      title: "时间",
      dataIndex: "created_at",
      key: "created_at",
      width: 170,
      render: (value: string) => formatDate(value, reportCtx.timezone),
    },
    {
      title: "操作人",
      dataIndex: "user_id",
      key: "user_id",
      width: 140,
      ellipsis: true,
      render: (v: string, row: any) => <Text strong style={{ color: "var(--text-primary)" }}>{displayUser(v, row.username)}</Text>,
    },
    {
      title: "操作内容",
      dataIndex: "action_type",
      key: "action_type",
      width: 220,
      render: (t: string, row: any) => (
        <Space direction="vertical" size={4}>
          <Tag color={actionColor[t] || "default"}>{displayAction(t)}</Tag>
          {renderDetails(row.action_detail, reportCtx.timezone)}
        </Space>
      ),
    },
    {
      title: "影响对象",
      key: "target",
      width: 220,
      render: (_: unknown, row: any) => (
        <Space direction="vertical" size={2}>
          <Text>{displayTargetType(row.target_type)}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{displayTargetId(row.target_id)}</Text>
        </Space>
      ),
    },
    { title: "来源 IP", dataIndex: "ip_address", key: "ip_address", width: 140, render: (value: string) => value || "-" },
  ]

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="审计合规"
        title="操作审计"
        description="记录系统配置、账号、密钥、模型和安全策略的管理动作，便于追溯责任人与变更原因。"
        meta={(
          <Space size={8} wrap>
            <StatusPill tone="blue">符合条件 {total} 条</StatusPill>
            <StatusPill tone="orange">本页配置变更 {configChanges} 条</StatusPill>
            <StatusPill tone="purple">本页账号相关 {userChanges} 条</StatusPill>
            <StatusPill tone="gray">统计时区 {reportCtx.timezone}</StatusPill>
          </Space>
        )}
      />
      <div style={{ marginBottom: 16 }}>
        <AuditIntegrityStatusLine timezone={reportCtx.timezone} />
      </div>
      <SectionPanel
        title="审计记录"
        description="默认按最近操作展示，详情已转换为管理员可读的审计语言。导出为服务端按当前筛选条件的全量记录，导出动作本身也会记入操作审计。"
      >
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, width: "100%", minWidth: 0, marginBottom: 16 }}>
          <AuditDateRangeFilter value={range} onChange={(next) => { setRange(next); resetPage() }} />
          <Input.Search
            allowClear
            aria-label="按操作人筛选"
            placeholder="操作人 ID"
            style={{ width: 180 }}
            defaultValue={userIDParam}
            onSearch={(value) => { setUserID(value.trim() || undefined); resetPage() }}
          />
          <Select
            allowClear
            showSearch
            aria-label="按操作类型筛选"
            placeholder="全部操作"
            style={{ width: 180 }}
            value={actionType}
            optionFilterProp="label"
            onChange={(value) => { setActionType(value); resetPage() }}
            options={Object.entries(actionMap).map(([value, label]) => ({ value, label }))}
          />
          <Select
            allowClear
            aria-label="按对象类型筛选"
            placeholder="全部对象"
            style={{ width: 140 }}
            value={targetType}
            onChange={(value) => { setTargetType(value); resetPage() }}
            options={Object.entries(targetTypeMap).map(([value, label]) => ({ value, label }))}
          />
          <ServerExportButton
            name="操作审计"
            timezone={reportCtx.timezone}
            run={(format) => ws8AuditApi.exportOperations(format, filters)}
          />
        </div>
        <ResizableTable
          columnStorageKey="operation-audit-columns"
          columns={cols}
          dataSource={rows}
          rowKey="id"
          loading={auditQ.isLoading}
          onRow={(record: any) => ({ style: record.id === auditIDParam ? { background: "rgba(22, 119, 255, 0.08)" } : undefined })}
          pagination={{
            current: page,
            pageSize: PAGE_SIZE,
            total,
            showSizeChanger: false,
            showTotal: (t: number) => `共 ${t} 条`,
            onChange: (next: number) => setPage(next),
          }}
        />
      </SectionPanel>
    </div>
  )
}

export default OperationAudit
