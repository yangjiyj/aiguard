import { Table, Tag } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { tenantApi } from '../../services/api'

export function TenantKeysTab({ tenantId }: { tenantId: string }) {
  const q = useQuery({ queryKey: ['tenant-keys', tenantId], enabled: !!tenantId,
    queryFn: () => tenantApi.listKeys(tenantId) })
  const raw = q.data?.data
  const rows = Array.isArray(raw?.data) ? raw.data : Array.isArray(raw) ? raw : []
  return (
    <Table size="small" rowKey="id" loading={q.isLoading} dataSource={rows}
      pagination={{ defaultPageSize: 10, showTotal: (t) => `共 ${t} 个密钥` }}
      columns={[
        { title: '名称', dataIndex: 'name', width: 160,
          render: (v: string) => v || '-' },
        { title: '前缀', dataIndex: 'key_prefix', width: 160, ellipsis: true },
        { title: '应用', dataIndex: 'project_id', width: 180, ellipsis: true },
        { title: '状态', dataIndex: 'status', width: 100,
          render: (s: string) => <Tag color={s === 'active' ? 'success' : 'default'}>{s === 'active' ? '启用' : '禁用'}</Tag> },
      ]} />
  )
}
