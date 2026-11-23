import { Button, Popconfirm, Table, Tag, message } from 'antd'
import { DeleteOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { tenantApi } from '../../services/api'
import { extractApiError } from '../../utils/apiError'

export function TenantProjectsTab({ tenantId }: { tenantId: string }) {
  const queryClient = useQueryClient()
  const q = useQuery({ queryKey: ['tenant-projects', tenantId], enabled: !!tenantId,
    queryFn: () => tenantApi.listProjects(tenantId) })
  const deleteMutation = useMutation({
    mutationFn: (projectId: string) => tenantApi.deleteProject(tenantId, projectId),
    onSuccess: () => {
      message.success('应用已删除，关联密钥已吊销')
      queryClient.invalidateQueries({ queryKey: ['tenant-projects', tenantId] })
      queryClient.invalidateQueries({ queryKey: ['tenant-keys', tenantId] })
      queryClient.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: (e: any) => message.error(extractApiError(e) || '删除失败'),
  })
  const raw = q.data?.data
  const rows = Array.isArray(raw?.data) ? raw.data : Array.isArray(raw) ? raw : []
  return (
    <Table size="small" rowKey="id" loading={q.isLoading} dataSource={rows}
      pagination={{ defaultPageSize: 10, showTotal: (t) => `共 ${t} 个应用` }}
      columns={[
        { title: '名称', dataIndex: 'name', width: 200, ellipsis: true },
        { title: 'ID', dataIndex: 'id', width: 200, ellipsis: true },
        { title: '状态', dataIndex: 'status', width: 100,
          render: (s: string) => <Tag color={s === 'active' ? 'success' : 'default'}>{s === 'active' ? '启用' : '禁用'}</Tag> },
        { title: '创建时间', dataIndex: 'created_at', width: 180 },
        { title: '操作', key: 'action', width: 100,
          render: (_: unknown, record: any) => (
            <Popconfirm
              title={`删除应用「${record.name}」?`}
              description="应用将停用，关联密钥会被吊销；历史调用与安全审计记录会保留。"
              okText="删除"
              cancelText="取消"
              okType="danger"
              onConfirm={() => deleteMutation.mutate(record.id)}
            >
              <Button danger size="small" icon={<DeleteOutlined />} loading={deleteMutation.isPending}>删除</Button>
            </Popconfirm>
          ) },
      ]} />
  )
}
