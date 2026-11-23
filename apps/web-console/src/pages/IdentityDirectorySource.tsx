import { useEffect, useState } from "react"
import { Alert, Button, Card, Collapse, Form, Input, Select, Space, Tag, Typography, message } from "antd"
import { Link } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { directoryApi, type DirectorySourceSummary, type DirectoryPreview, type DirectorySyncRun } from "../services/api"
import { EnterprisePageHeader } from "../components/EnterpriseUI"
import DirectoryPreviewPanel from "../components/identity/DirectoryPreview"
import DirectorySyncHistory from "../components/identity/DirectorySyncHistory"

const { Text } = Typography

// safeErrorMessage 对后端 error.message 做脱敏：若含 DB/连接/堆栈等敏感细节，
// 只返回友好提示 + error.code，绝不向用户暴露 pq:/SQLSTATE/connection refused 等。
// 信任 error.code（白名单枚举），不信任 message（可能是原始底层错误）。
const DB_LEAK_PATTERNS = [/pq:\s|SQLSTATE|connection refused|pgx\.|dial tcp|panic:|goroutine /i]

function safeErrorMessage(error: any, fallback: string): string {
  const code: string = error?.response?.data?.error?.code || ""
  const raw: string = error?.response?.data?.error?.message || ""
  if (!raw) return fallback
  if (DB_LEAK_PATTERNS.some((p) => p.test(raw))) {
    return code ? `${fallback}（${code}）` : fallback
  }
  return raw
}

// 目录源页：复用目录配置表单内容，但改为任务5的预览—激活流程。
// 客户化：数据库 ID 不显示；Base DN/Filter/稳定 ID 属性折叠到「高级设置」；
// 「立即同步」改为「生成同步预览」；测试成功明确提示「尚未生效」。
//
// 任务 9：预览/激活/历史抽成独立组件（DirectoryPreview / DirectorySyncHistory）。
// 工作流：配置并测试 → 生成预览 → 确认激活。增量定时同步只在首次激活成功后开放；
// 全量重新同步放在历史页的受控操作中（不在本页暴露危险按钮）。

// 后端统一返回 {"data": ...}，axios 又包一层 response.data，
// 真实载荷在 response.data.data。少解一层会让所有计数变成
// undefined（现场表现为「已激活：新增 undefined」）。
function unwrapEnvelope(response: any): any {
  const first = response?.data ?? response
  if (first && typeof first === 'object' && 'data' in first) {
    return (first as any).data
  }
  return first
}

export default function IdentityDirectorySource() {
  const [form] = Form.useForm()
  const queryClient = useQueryClient()
  // preview === null 表示无活动预览；previewStale=true 表示配置已变更，预览作废不可激活。
  const [preview, setPreview] = useState<DirectoryPreview | null>(null)
  const [previewStale, setPreviewStale] = useState(false)

  const draftQuery = useQuery({ queryKey: ["directory-draft"], queryFn: () => directoryApi.getDraft() })
  const draft: DirectorySourceSummary | undefined = draftQuery.data?.data?.data ?? draftQuery.data?.data
  const runsQuery = useQuery({ queryKey: ["directory-sync-runs"], queryFn: () => directoryApi.listSyncRuns() })
  const runsResponse = runsQuery.data?.data
  const runsPayload = Array.isArray(runsResponse) ? runsResponse : runsResponse?.data
  const runs: DirectorySyncRun[] = Array.isArray(runsPayload) ? runsPayload : []

  useEffect(() => {
    if (!draft) return
    form.setFieldsValue({
      kind: draft.kind,
      display_name: draft.display_name,
      stable_id_attribute: draft.stable_id_attribute,
      username_attribute: draft.username_attribute,
      email_attribute: draft.email_attribute,
      name_attribute: draft.name_attribute,
      version: draft.version,
    })
    form.setFieldsValue({
      connection_url: undefined, bind_dn: undefined, bind_password: undefined,
      base_dn: undefined, users_dn: undefined, user_filter: undefined, ca_cert_pem: undefined,
    })
  }, [draft, form])

  // 草稿保存：配置变更后作废旧预览（previewStale=true 让 DirectoryPreview 隐藏激活入口）。
  // onError 不清空表单 —— 草稿内容仍在，用户可改后重试（任务 9：API 错误不丢失草稿）。
  const saveMutation = useMutation({
    mutationFn: (value: any) => directoryApi.saveDraft(value),
    onSuccess: () => {
      form.setFieldsValue({
        connection_url: undefined, bind_dn: undefined, bind_password: undefined,
        base_dn: undefined, users_dn: undefined, user_filter: undefined, ca_cert_pem: undefined,
      })
      message.success("目录草稿已保存")
      queryClient.invalidateQueries({ queryKey: ["directory-draft"] })
      setPreviewStale(preview !== null)
    },
    onError: (error: any) => {
      message.error(safeErrorMessage(error, "保存目录草稿失败"))
    },
  })

  const [testOk, setTestOk] = useState(false)
  const testMutation = useMutation({
    mutationFn: () => directoryApi.testConnection(),
    onSuccess: (response: any) => {
      const result = response?.data ?? response
      if (result?.success) {
        message.success("LDAPS 连接、绑定账号与目录能力验证通过")
        setTestOk(true)
      } else {
        message.error(result?.error || "目录连接测试未通过")
        setTestOk(false)
      }
      queryClient.invalidateQueries({ queryKey: ["directory-draft"] })
    },
    onError: (error: any) => {
      setTestOk(false)
      message.error(safeErrorMessage(error, "目录连接测试失败"))
    },
  })

  // 「生成同步预览」调 preview，激活调 activate（任务5流程）。
  // 生成预览时清空 stale 标记，因为这是基于最新配置的全新预览。
  const previewMutation = useMutation({
    mutationFn: () => directoryApi.previewDirectory(),
    onSuccess: (response: any) => {
      const p = unwrapEnvelope(response)
      setPreview(p)
      setPreviewStale(false)
      message.success(`预览完成：将新增 ${p?.created ?? 0}，更新 ${p?.updated ?? 0}，冲突 ${p?.conflict ?? 0}`)
    },
    onError: (error: any) => message.error(safeErrorMessage(error, "生成同步预览失败")),
  })

  // 激活：onError 不清空 preview/表单，用户可重试。成功后才清 preview 并刷新历史。
  const activateMutation = useMutation({
    mutationFn: () => directoryApi.activatePreview(preview?.preview_id || ""),
    onSuccess: (response: any) => {
      const r = unwrapEnvelope(response)
      message.success(`已激活：新增 ${r?.created ?? 0}，更新 ${r?.updated ?? 0}，禁用 ${r?.disabled ?? 0}`)
      setPreview(null)
      setPreviewStale(false)
      queryClient.invalidateQueries({ queryKey: ["directory-sync-runs"] })
    },
    onError: (error: any) => message.error(safeErrorMessage(error, "激活失败")),
  })

  const statusTag = !draft
    ? <Tag>未配置</Tag>
    : draft.status === "tested"
      ? <Tag color="blue">测试通过</Tag>
      : draft.status === "active" || draft.status === "synced"
        ? <Tag color="green">启用中</Tag>
        : <Tag color="orange">草稿</Tag>

  // 预览按钮可用条件：草稿存在 + 已通过连接测试（status=tested）。
  // 任务 9：连接测试前禁止预览。
  const previewDisabled = !draft || draft.status !== "tested"

  return (
    <div>
      <EnterprisePageHeader
        eyebrow="身份与访问 · 企业身份源"
        title="目录账号"
        description="连接企业 AD 或 LDAP，按同步范围将目录账号映射到 JJDGuard。"
      />

      <Space style={{ marginTop: 16, marginBottom: 16 }}>
        <Link to="/identity-sources">← 企业身份源</Link>
      </Space>

      <Alert
        style={{ marginBottom: 16 }}
        type="info"
        showIcon
        message="配置草稿与预览—激活流程"
        description="配置并测试连接 → 生成同步预览 → 确认激活。保存仅维护草稿，不会创建、停用或修改任何账号。"
      />

      <Card title="目录连接" extra={statusTag} style={{ marginBottom: 16 }}>
        <Form
          form={form}
          layout="vertical"
          onFinish={(value) => saveMutation.mutate(value)}
          initialValues={{ kind: "ldap", user_filter: "(objectClass=person)", email_attribute: "mail", name_attribute: "displayName" }}
        >
          <Form.Item name="kind" label="目录类型" rules={[{ required: true }]}>
            <Select options={[{ value: "ad", label: "Microsoft Active Directory" }, { value: "ldap", label: "标准 LDAP" }]} />
          </Form.Item>
          <Form.Item name="display_name" label="显示名称" rules={[{ required: true, message: "请输入目录名称" }]}>
            <Input placeholder="如：总部员工目录" maxLength={128} />
          </Form.Item>
          <Form.Item
            name="connection_url"
            label="地址"
            extra="ldaps:// 为加密直连（默认 636，AD 全局编录 3269）；ldap:// 会先执行 StartTLS 再认证（默认 389，AD 全局编录 3268），不支持明文。端口需在部署批准清单内。"
            rules={[{ required: true, message: "请输入目录地址" }, { pattern: /^ldaps?:\/\//, message: "仅支持 ldaps:// 或 ldap://（StartTLS）安全连接" }]}
          >
            <Input placeholder="ldaps://ldap.company.example:636" />
          </Form.Item>
          <Form.Item name="bind_dn" label="管理员账号" rules={[{ required: true, message: "请输入绑定 DN" }]}>
            <Input placeholder="cn=svc-jjdguard,ou=Service Accounts,dc=company,dc=example" />
          </Form.Item>
          <Form.Item name="bind_password" label="服务账号密码" extra={draft?.bind_password_set ? <Text type="secondary">已配置；留空保留当前密码</Text> : undefined}>
            <Input.Password placeholder={draft?.bind_password_set ? "留空保留当前密码" : "首次保存必须填写"} autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="users_dn" label="用户/组范围" rules={[{ required: true, message: "请输入用户 OU" }]}>
            <Input placeholder="ou=People,dc=company,dc=example" />
          </Form.Item>
          <Form.Item name="email_attribute" label="邮箱属性">
            <Input placeholder="mail" />
          </Form.Item>
          <Form.Item name="name_attribute" label="姓名属性">
            <Input placeholder="displayName" />
          </Form.Item>

          <Collapse
            ghost
            items={[{
              key: "advanced",
              label: "高级设置",
              children: (
                <>
                  <Form.Item name="base_dn" label="Base DN">
                    <Input placeholder="dc=company,dc=example" />
                  </Form.Item>
                  <Form.Item name="user_filter" label="用户筛选条件（Filter）">
                    <Input placeholder="(objectClass=person)" />
                  </Form.Item>
                  <Form.Item name="stable_id_attribute" label="稳定 ID 属性">
                    <Input placeholder="objectGUID / entryUUID" />
                  </Form.Item>
                  <Form.Item name="ca_cert_pem" label="私有 CA 证书（可选）" extra={draft?.ca_cert_set ? <Text type="secondary">已配置；留空保留当前证书</Text> : "仅当企业 AD/LDAP 使用私有 CA 时粘贴 PEM 证书"}>
                    <Input.TextArea rows={4} placeholder="-----BEGIN CERTIFICATE-----" />
                  </Form.Item>
                </>
              ),
            }]}
          />

          <Space wrap>
            <Button type="primary" htmlType="submit" loading={saveMutation.isPending}>保存草稿</Button>
            <Button onClick={() => testMutation.mutate()} disabled={!draft} loading={testMutation.isPending}>测试连接</Button>
            {testOk && (
              <Alert type="warning" showIcon banner message="测试成功，尚未生效：请生成同步预览并确认后再激活" />
            )}
            <Button onClick={() => previewMutation.mutate()} disabled={previewDisabled} loading={previewMutation.isPending}>生成同步预览</Button>
          </Space>
        </Form>
      </Card>

      {/* 任务 9：预览面板抽成独立组件（含脱敏冲突明细 + 二次确认激活 + 过期作废） */}
      {preview && (
        <DirectoryPreviewPanel
          preview={preview}
          previewStale={previewStale}
          activating={activateMutation.isPending}
          onActivate={() => activateMutation.mutate()}
          onDismiss={() => { setPreview(null); setPreviewStale(false) }}
        />
      )}

      {/* 任务 9：同步历史抽成独立组件（状态/耗时/操作者/失败摘要） */}
      <DirectorySyncHistory runs={runs} loading={runsQuery.isLoading} />
    </div>
  )
}
