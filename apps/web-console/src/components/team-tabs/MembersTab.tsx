import { useState } from 'react'
import { Table, Button, Modal, Select, Space, message, Popconfirm, Tag } from 'antd'
import { UserAddOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { orgApi, userApi } from '../../services/api'

interface MembersTabProps {
  teamId: string
}

export function MembersTab({ teamId }: MembersTabProps) {
  const qc = useQueryClient()
  const [batchModalOpen, setBatchModalOpen] = useState(false)
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([])
  const [selectedRole, setSelectedRole] = useState('member')

  const membersQ = useQuery({
    queryKey: ['team-members', teamId],
    queryFn: () => orgApi.listMembers(teamId),
    enabled: !!teamId,
  })

  const usersQ = useQuery({
    queryKey: ['users'],
    queryFn: () => userApi.list(),
  })

  const removeMutation = useMutation({
    mutationFn: (userId: string) => orgApi.removeMember(teamId, userId),
    onSuccess: () => {
      message.success('已移除')
      qc.invalidateQueries({ queryKey: ['team-members', teamId] })
    },
    onError: () => message.error('移除失败'),
  })

  const batchAddMutation = useMutation({
    mutationFn: (data: { user_ids: string[]; role: string }) => orgApi.batchAddMembers(teamId, data),
    onSuccess: () => {
      message.success(`已添加 ${selectedUserIds.length} 人`)
      qc.invalidateQueries({ queryKey: ['team-members', teamId] })
      setBatchModalOpen(false)
      setSelectedUserIds([])
      setSelectedRole('member')
    },
    onError: () => message.error('添加失败'),
  })

  const raw = membersQ.data?.data
  const members = Array.isArray(raw?.items) ? raw.items : Array.isArray(raw) ? raw : []

  const rawUsers = usersQ.data?.data
  const allUsers = Array.isArray(rawUsers?.items) ? rawUsers.items : Array.isArray(rawUsers?.data) ? rawUsers.data : Array.isArray(rawUsers) ? rawUsers : []
  const existingIds = new Set(members.map((m: any) => m.user_id))
  const userOptions = allUsers
    .filter((u: any) => !existingIds.has(u.id))
    .map((u: any) => ({ value: u.id, label: u.username || u.id }))

  const roleColors: Record<string, string> = { owner: 'purple', member: 'blue', viewer: 'default' }

  const columns = [
    { title: '用户', dataIndex: 'user_id', key: 'user_id',
      render: (id: string, row: any) => row.username || id },
    { title: '角色', dataIndex: 'role', key: 'role',
      render: (r: string) => <Tag color={roleColors[r] || 'default'}>{r || 'member'}</Tag> },
    { title: '加入时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
    {
      title: '操作', key: 'action',
      render: (_: any, row: any) => (
        <Popconfirm title="确定移除此成员？" onConfirm={() => removeMutation.mutate(row.user_id)}>
          <Button type="link" danger size="small">移除</Button>
        </Popconfirm>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<UserAddOutlined />} onClick={() => setBatchModalOpen(true)}>
          添加成员
        </Button>
      </div>
      <Table
        dataSource={members}
        columns={columns}
        rowKey="user_id"
        loading={membersQ.isLoading}
        size="small"
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title="批量添加成员"
        open={batchModalOpen}
        onCancel={() => { setBatchModalOpen(false); setSelectedUserIds([]); setSelectedRole('member') }}
        onOk={() => {
          if (selectedUserIds.length === 0) { message.warning('请选择至少一个用户'); return }
          batchAddMutation.mutate({ user_ids: selectedUserIds, role: selectedRole })
        }}
        confirmLoading={batchAddMutation.isPending}
        okText="确认添加"
        width={520}
      >
        <Space direction="vertical" style={{ width: '100%' }} size={16}>
          <div>
            <div style={{ marginBottom: 6, fontWeight: 500 }}>选择用户</div>
            <Select
              mode="multiple"
              style={{ width: '100%' }}
              placeholder="搜索并选择用户"
              options={userOptions}
              value={selectedUserIds}
              onChange={setSelectedUserIds}
              showSearch
              filterOption={(input, opt) => (opt?.label as string || '').toLowerCase().includes(input.toLowerCase())}
            />
          </div>
          <div>
            <div style={{ marginBottom: 6, fontWeight: 500 }}>角色</div>
            <Select
              style={{ width: 200 }}
              value={selectedRole}
              onChange={setSelectedRole}
              options={[
                { value: 'owner', label: '部门主 (owner)' },
                { value: 'member', label: '成员 (member)' },
                { value: 'viewer', label: '只读 (viewer)' },
              ]}
            />
          </div>
        </Space>
      </Modal>
    </div>
  )
}
