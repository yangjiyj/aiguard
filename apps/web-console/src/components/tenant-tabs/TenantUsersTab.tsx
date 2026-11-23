import { Button, Popconfirm, Table, Tag, message } from 'antd'
import { DeleteOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { tenantApi, userApi } from '../../services/api'
import { showUserDeleteBlockerModal } from '../UserDeleteBlockerModal'
import { extractApiError } from '../../utils/apiError'

export function TenantUsersTab({ tenantId }: { tenantId: string }) {
  const queryClient = useQueryClient()
  const q = useQuery({ queryKey: ['tenant-users', tenantId], enabled: !!tenantId,
    queryFn: () => tenantApi.listUsers(tenantId) })
  const deleteMutation = useMutation({
    mutationFn: (id: string) => userApi.delete(id),
    onSuccess: () => {
      message.success('用户已删除')
      queryClient.invalidateQueries({ queryKey: ['tenant-users', tenantId] })
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (e: any) => {
      const err = e?.response?.data?.error
      if (err?.code === 'user_has_references') {
        showUserDeleteBlockerModal(err)
        return
      }
      message.error(extractApiError(e) || '删除失败')
    },
  })
  const raw = q.data?.data
  const rows = Array.isArray(raw?.data) ? raw.data : Array.isArray(raw) ? raw : []
  return (
    <Table size="small" rowKey="id" loading={q.isLoading} dataSource={rows}
      pagination={{ defaultPageSize: 10, showTotal: (t) => `共 ${t} 人` }}
      columns={[
        { title: '用户名', dataIndex: 'username', width: 160, ellipsis: true },
        { title: '邮箱', dataIndex: 'email', width: 200, ellipsis: true },
        { title: '角色', dataIndex: 'role', width: 130, render: (v: string) => <Tag>{v}</Tag> },
        { title: '状态', dataIndex: 'status', width: 100,
          render: (s: string) => <Tag color={s === 'active' ? 'success' : 'default'}>{s === 'active' ? '启用' : '禁用'}</Tag> },
        { title: '操作', key: 'action', width: 100,
          render: (_: unknown, record: any) => (
            <Popconfirm
              title={`删除用户「${record.username}」?`}
              description="仅无资源和历史引用的用户可删除；已有引用请先移交资源或禁用。"
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
