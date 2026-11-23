import { useMemo, useState } from 'react'
import {
  Alert,
  Button,
  Checkbox,
  Descriptions,
  Modal,
  Popconfirm,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import {
  DeleteOutlined,
  DownloadOutlined,
  PlusOutlined,
  SwapOutlined,
} from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { caApi, type CACertificate } from '../services/api'

const { Text, Title } = Typography

const statusPresentation: Record<CACertificate['status'], { label: string; color: string }> = {
  active: { label: '当前使用', color: 'green' },
  pending: { label: '待切换', color: 'blue' },
  deprecated: { label: '已退役', color: 'default' },
  expired: { label: '已过期', color: 'red' },
}

const formatTime = (value?: string) => value ? new Date(value).toLocaleString() : '-'

const formatFingerprint = (value?: string) => {
  if (!value) return '-'
  return value.toUpperCase().match(/.{1,2}/g)?.join(':') || value.toUpperCase()
}

function CACertificateManager() {
  const queryClient = useQueryClient()
  const [generateOpen, setGenerateOpen] = useState(false)
  const [activating, setActivating] = useState<CACertificate | null>(null)
  const [activationAcknowledged, setActivationAcknowledged] = useState(false)

  const caQuery = useQuery({
    queryKey: ['caCertificates'],
    queryFn: () => caApi.list(),
  })

  const certificates = useMemo(() => {
    const raw = caQuery.data?.data
    const items = Array.isArray(raw?.data) ? raw.data : []
    return [...items].sort((left, right) =>
      new Date(right.created_at).getTime() - new Date(left.created_at).getTime())
  }, [caQuery.data])
  const current = certificates.find((certificate) => certificate.status === 'active')
  const activeCount = certificates.filter((certificate) => certificate.status === 'active').length
  const cleanupCandidates = certificates.filter((certificate) =>
    certificate.status === 'deprecated' || certificate.status === 'expired')

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['caCertificates'] })

  const generateMutation = useMutation({
    mutationFn: (validityDays: number) => caApi.generate(validityDays),
    onSuccess: (response) => {
      setGenerateOpen(false)
      message.success(response.data.status === 'active'
        ? '首张 CA 已生成并启用'
        : '待切换 CA 已生成，请先部署到客户端再执行切换')
      refresh()
    },
    onError: (error: any) =>
      message.error(error?.response?.data?.error?.message || '生成 CA 失败'),
  })

  const activateMutation = useMutation({
    mutationFn: (id: string) => caApi.activate(id),
    onSuccess: () => {
      setActivating(null)
      setActivationAcknowledged(false)
      message.success('CA 已切换，正向代理将在 5 秒内开始使用新证书')
      refresh()
    },
    onError: (error: any) =>
      message.error(error?.response?.data?.error?.message || '切换 CA 失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => caApi.delete(id),
    onSuccess: () => {
      message.success('CA 记录已删除')
      refresh()
    },
    onError: (error: any) =>
      message.error(error?.response?.data?.error?.message || '删除 CA 失败'),
  })

  const cleanupMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(ids.map((id) => caApi.delete(id)))
      const failedCount = results.filter((result) => result.status === 'rejected').length
      if (failedCount > 0) {
        throw new Error(`有 ${failedCount} 张旧 CA 未能删除`)
      }
      return ids.length
    },
    onSuccess: (count) => {
      message.success(`已清理 ${count} 张旧 CA`)
      refresh()
    },
    onError: (error: Error) => {
      message.error(error.message || '清理旧 CA 失败')
      refresh()
    },
  })

  const downloadCertificate = async (certificate?: CACertificate) => {
    try {
      const response = await caApi.download(certificate?.id)
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.download = `jjdguard-ca-${certificate?.id || 'current'}.crt`
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch {
      message.error('下载 CA 证书失败')
    }
  }

  const columns = [
    {
      title: '证书',
      key: 'certificate',
      width: 250,
      render: (_: unknown, certificate: CACertificate) => (
        <Space direction="vertical" size={2}>
          <Text copyable={{ text: certificate.id }} code>{certificate.id}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {certificate.fingerprint_sha256
              ? `SHA-256 ${formatFingerprint(certificate.fingerprint_sha256).slice(0, 35)}…`
              : '未提供指纹'}
          </Text>
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 110,
      render: (status: CACertificate['status']) => {
        const presentation = statusPresentation[status] || { label: status, color: 'default' }
        return <Tag color={presentation.color}>{presentation.label}</Tag>
      },
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: formatTime,
    },
    {
      title: '过期时间',
      dataIndex: 'expires_at',
      key: 'expires_at',
      width: 180,
      render: formatTime,
    },
    {
      title: '操作',
      key: 'actions',
      width: 250,
      render: (_: unknown, certificate: CACertificate) => (
        <Space size={4}>
          <Button aria-label="下载证书" type="link" size="small" icon={<DownloadOutlined />} onClick={() => downloadCertificate(certificate)}>
            下载
          </Button>
          {certificate.status === 'pending' && (
            <Button
              aria-label="切换为当前"
              type="link"
              size="small"
              icon={<SwapOutlined />}
              onClick={() => {
                setActivationAcknowledged(false)
                setActivating(certificate)
              }}
            >
              切换为当前
            </Button>
          )}
          {certificate.status !== 'active' && (
            <Popconfirm
              title="删除这张 CA？"
              description="删除后无法再下载。已经安装到客户端的证书不会自动移除。"
              okText="删除"
              cancelText="取消"
              okButtonProps={{ danger: true }}
              onConfirm={() => deleteMutation.mutate(certificate.id)}
            >
              <Button aria-label="删除" type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
            </Popconfirm>
          )}
        </Space>
      ),
      fixed: 'right' as const,
    },
  ]

  return (
    <div style={{ padding: '0 20px 20px' }}>
      {activeCount > 1 && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message="检测到多张当前 CA"
          description="这是旧版本遗留的异常状态。请先完成数据库迁移，不要继续生成或切换证书。"
        />
      )}

      {current ? (
        <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, padding: 18, marginBottom: 16 }}>
          <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 12 }}>
            <Title level={5} style={{ margin: 0 }}>当前正向代理 CA</Title>
            <Button aria-label="下载当前 CA" icon={<DownloadOutlined />} onClick={() => downloadCertificate(current)}>下载当前 CA</Button>
          </Space>
          <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 4 }}>
            <Descriptions.Item label="证书 ID"><Text copyable>{current.id}</Text></Descriptions.Item>
            <Descriptions.Item label="状态"><Tag color="green">当前使用</Tag></Descriptions.Item>
            <Descriptions.Item label="创建时间">{formatTime(current.created_at)}</Descriptions.Item>
            <Descriptions.Item label="过期时间">{formatTime(current.expires_at)}</Descriptions.Item>
            <Descriptions.Item label="SHA-256 指纹" span={{ xs: 1, sm: 2, lg: 4 }}>
              <Text copyable={{ text: formatFingerprint(current.fingerprint_sha256) }} code>
                {formatFingerprint(current.fingerprint_sha256)}
              </Text>
            </Descriptions.Item>
          </Descriptions>
        </div>
      ) : (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message="当前没有可用 CA"
          description="HTTPS 正向代理无法稳定工作。请立即生成首张 CA，并将其安装到客户端信任库。"
        />
      )}

      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 12 }} align="end">
        <Space direction="vertical" size={2}>
          <Text strong>证书生命周期</Text>
          <Text type="secondary">当前 CA 受保护；待切换 CA 可逐条删除，已退役或过期 CA 可一键清理。</Text>
        </Space>
        <Space wrap>
          <Popconfirm
            title={`清理 ${cleanupCandidates.length} 张旧 CA？`}
            description="只会删除已退役或已过期的 CA，当前 CA 和待切换 CA 不受影响。删除后无法恢复。"
            okText="确认清理"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            disabled={cleanupCandidates.length === 0}
            onConfirm={() => cleanupMutation.mutate(cleanupCandidates.map((certificate) => certificate.id))}
          >
            <Button
              aria-label={`清理旧证书 (${cleanupCandidates.length})`}
              danger
              icon={<DeleteOutlined />}
              disabled={cleanupCandidates.length === 0}
              loading={cleanupMutation.isPending}
            >
              清理旧证书 ({cleanupCandidates.length})
            </Button>
          </Popconfirm>
          <Button
            aria-label={current ? '生成待切换 CA' : '生成首张 CA'}
            type="primary"
            icon={<PlusOutlined />}
            disabled={activeCount > 1}
            onClick={() => {
              setGenerateOpen(true)
            }}
          >
            {current ? '生成待切换 CA' : '生成首张 CA'}
          </Button>
        </Space>
      </Space>

      <Table
        columns={columns}
        dataSource={certificates}
        rowKey="id"
        loading={caQuery.isLoading}
        scroll={{ x: 1000 }}
        pagination={{ defaultPageSize: 10, showSizeChanger: true, showTotal: (total) => `共 ${total} 条` }}
      />

      <Modal
        title={current ? '生成待切换 CA' : '生成首张 CA'}
        open={generateOpen}
        okText="生成"
        cancelText="取消"
        okButtonProps={{ 'aria-label': '生成' }}
        confirmLoading={generateMutation.isPending}
        onCancel={() => setGenerateOpen(false)}
        onOk={() => generateMutation.mutate(3650)}
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message={current ? '生成后不会立即影响现有客户端' : '生成后会成为当前 CA'}
          description={current ? '新证书先处于“待切换”状态，可安全下载和预部署。' : '这是部署中的第一张 CA，请生成后立即下发到客户端。'}
        />
        <Text strong>有效期：10 年</Text>
      </Modal>

      <Modal
        title="切换正向代理 CA"
        open={!!activating}
        okText="确认切换"
        cancelText="取消"
        okButtonProps={{ danger: true, disabled: !activationAcknowledged }}
        confirmLoading={activateMutation.isPending}
        onCancel={() => {
          setActivating(null)
          setActivationAcknowledged(false)
        }}
        onOk={() => activating && activateMutation.mutate(activating.id)}
      >
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message="未信任新 CA 的客户端会立即出现 HTTPS 证书错误"
          description="切换后，正向代理会在 5 秒内停止使用旧 CA 签发新连接。旧 CA 记录会保留为“已退役”，便于宽限期核对。"
        />
        <Text code copyable>{activating?.id}</Text>
        <div style={{ marginTop: 16 }}>
          <Checkbox checked={activationAcknowledged} onChange={(event) => setActivationAcknowledged(event.target.checked)}>
            我已下载并将这张 CA 部署到需要使用正向代理的客户端
          </Checkbox>
        </div>
      </Modal>
    </div>
  )
}

export default CACertificateManager
