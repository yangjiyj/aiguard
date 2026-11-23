import { useState } from 'react'
import { Table, Button, Modal, Select, message, Popconfirm, Tag } from 'antd'
import { AppstoreAddOutlined, LinkOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { orgApi, projectApi } from '../../services/api'

interface AppsTabProps {
  teamId: string
  tenantId?: string
}

export function AppsTab({ teamId }: AppsTabProps) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [assignModalOpen, setAssignModalOpen] = useState(false)
  const [selectedProjectIds, setSelectedProjectIds] = useState<string[]>([])

  const teamProjectsQ = useQuery({
    queryKey: ['team-projects', teamId],
    queryFn: () => orgApi.listProjects(teamId),
    enabled: !!teamId,
  })

  const allProjectsQ = useQuery({
    queryKey: ['projects'],
    queryFn: () => projectApi.list(),
  })

  const assignMutation = useMutation({
    mutationFn: async (projectIds: string[]) => {
      await Promise.all(projectIds.map(pid => orgApi.patchProjectTeam(pid, teamId)))
    },
    onSuccess: () => {
      message.success(`已归属 ${selectedProjectIds.length} 个应用`)
      qc.invalidateQueries({ queryKey: ['team-projects', teamId] })
      qc.invalidateQueries({ queryKey: ['projects'] })
      setAssignModalOpen(false)
      setSelectedProjectIds([])
    },
    onError: () => message.error('归属失败'),
  })

  const unassignMutation = useMutation({
    mutationFn: (projectId: string) => orgApi.patchProjectTeam(projectId, ''),
    onSuccess: () => {
      message.success('已取消归属')
      qc.invalidateQueries({ queryKey: ['team-projects', teamId] })
      qc.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: () => message.error('操作失败'),
  })

  const rawTeamProjects = teamProjectsQ.data?.data
  const teamProjects = Array.isArray(rawTeamProjects?.data) ? rawTeamProjects.data
    : Array.isArray(rawTeamProjects) ? rawTeamProjects : []

  const rawAllProjects = allProjectsQ.data?.data
  const allProjects = Array.isArray(rawAllProjects?.data) ? rawAllProjects.data
    : Array.isArray(rawAllProjects?.items) ? rawAllProjects.items
    : Array.isArray(rawAllProjects) ? rawAllProjects : []

  const existingIds = new Set(teamProjects.map((p: any) => p.id))
  const unassignedOptions = allProjects
    .filter((p: any) => !existingIds.has(p.id))
    .map((p: any) => ({ value: p.id, label: p.name || p.id }))

  const columns = [
    { title: '应用名称', dataIndex: 'name', key: 'name',
      render: (name: string, row: any) => (
        <Button type="link" size="small" icon={<LinkOutlined />}
          onClick={() => navigate(`/apps?highlight=${row.id}`)}>
          {name}
        </Button>
      )
    },
    { title: '环境', dataIndex: 'environment', key: 'environment',
      render: (e: string) => e ? <Tag>{e}</Tag> : '-' },
    { title: '状态', dataIndex: 'status', key: 'status',
      render: (s: string) => <Tag color={s === 'active' ? 'success' : 'default'}>{s}</Tag> },
    {
      title: '操作', key: 'action',
      render: (_: any, row: any) => (
        <Popconfirm title="确定取消此应用的部门归属？" onConfirm={() => unassignMutation.mutate(row.id)}>
          <Button type="link" size="small">移除归属</Button>
        </Popconfirm>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12, gap: 8 }}>
        <Button
          icon={<AppstoreAddOutlined />}
          onClick={() => setAssignModalOpen(true)}
        >
          归属应用
        </Button>
        <Button type="primary" onClick={() => navigate(`/apps?team_id=${teamId}`)}>
          新建应用
        </Button>
      </div>
      <Table
        dataSource={teamProjects}
        columns={columns}
        rowKey="id"
        loading={teamProjectsQ.isLoading}
        size="small"
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title="选择要归属到此部门的应用"
        open={assignModalOpen}
        onCancel={() => { setAssignModalOpen(false); setSelectedProjectIds([]) }}
        onOk={() => {
          if (selectedProjectIds.length === 0) { message.warning('请选择至少一个应用'); return }
          assignMutation.mutate(selectedProjectIds)
        }}
        confirmLoading={assignMutation.isPending}
        okText="确认归属"
      >
        <Select
          mode="multiple"
          style={{ width: '100%' }}
          placeholder="搜索并选择应用"
          options={unassignedOptions}
          value={selectedProjectIds}
          onChange={setSelectedProjectIds}
          showSearch
          filterOption={(input, opt) => (opt?.label as string || '').toLowerCase().includes(input.toLowerCase())}
        />
        {unassignedOptions.length === 0 && (
          <div style={{ marginTop: 8, color: '#999' }}>所有应用已归属到各部门</div>
        )}
      </Modal>
    </div>
  )
}
