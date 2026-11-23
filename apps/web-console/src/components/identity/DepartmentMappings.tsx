import { useRef, useState } from 'react'
import { Alert, Button, Card, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tag, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { orgApi, type IdentitySourceWithAlias } from '../../services/api'
import {
  identityDepartmentMappingsApi,
  type DepartmentMappingMatchType,
  type DepartmentMappingPreview,
  type IdentityDepartmentMapping,
  type IdentityDepartmentMappingInput,
} from '../../services/identityDepartmentMappings'

const { Text } = Typography

const MATCH_LABELS: Record<DepartmentMappingMatchType, string> = {
  department: '部门编码',
  groups: '用户组',
  ou: '目录组织单位',
  member_of: '目录用户组',
}
const MATCH_OPTIONS = [
  { value: 'department', label: MATCH_LABELS.department },
  { value: 'groups', label: MATCH_LABELS.groups },
]

type MappingSource = Pick<IdentitySourceWithAlias, 'id' | 'display_name' | 'status' | 'version'>
type DepartmentOption = { id: string; name: string }
type MappingFormValues = Pick<IdentityDepartmentMappingInput, 'external_group' | 'match_type' | 'department_id' | 'priority' | 'enabled'>

function listData<T>(raw: unknown): T[] {
  if (Array.isArray(raw)) return raw
  if (raw && typeof raw === 'object' && 'data' in raw && Array.isArray(raw.data)) return raw.data
  return []
}

function mappingError(error: unknown, fallback: string): string {
  const response = (error as { response?: { status?: number; data?: { error?: { message?: string } } } })?.response
  if (response?.status === 409) return '相同匹配值的规则已存在，请编辑已有规则或使用其他匹配值'
  return response?.data?.error?.message || fallback
}

function previewValues(text?: string): string[] {
  return [...new Set((text || '').split(/\r?\n/).map((value) => value.trim()).filter(Boolean))]
}

function scopeLabel(source: MappingSource): string {
  if (source.status === 'active') return '当前生效配置'
  if (source.status === 'disabled') return '已停用配置'
  return '待启用配置'
}

export default function DepartmentMappings({ sources }: { sources: MappingSource[] }) {
  const [chosenID, setChosenID] = useState('')
  const active = sources.find((source) => source.status === 'active')
  const pending = sources.find((source) => source.status === 'draft' || source.status === 'tested')
  const disabled = !active ? sources.find((source) => source.status === 'disabled') : undefined
  const available = [active, pending, disabled].filter((source): source is MappingSource => !!source)
  const source = available.find((item) => item.id === chosenID) || available[0]

  return (
    <Card
      title="部门属性映射"
      style={{ marginBottom: 16 }}
      extra={available.length > 1 ? (
        <Select
          aria-label="映射作用范围"
          style={{ minWidth: 170 }}
          value={source?.id}
          options={available.map((item) => ({ value: item.id, label: scopeLabel(item) }))}
          onChange={setChosenID}
        />
      ) : undefined}
    >
      {source ? <MappingEditor key={source.id} source={source} /> : (
        <Space direction="vertical">
          <Alert type="info" showIcon message="请先保存身份源草稿，再配置部门映射" />
          <Button type="primary" disabled>新增映射</Button>
        </Space>
      )}
    </Card>
  )
}

function MappingEditor({ source }: { source: MappingSource }) {
  const qc = useQueryClient()
  const [editorForm] = Form.useForm<MappingFormValues>()
  const [previewForm] = Form.useForm<{ departments?: string; groups?: string }>()
  const selectedDepartmentID = Form.useWatch('department_id', editorForm)
  const [editorOpen, setEditorOpen] = useState(false)
  const [editing, setEditing] = useState<IdentityDepartmentMapping | null>(null)
  const [deleting, setDeleting] = useState<IdentityDepartmentMapping | null>(null)
  const [previewOpen, setPreviewOpen] = useState(false)
  const [previewResult, setPreviewResult] = useState<DepartmentMappingPreview | null>(null)
  const [previewError, setPreviewError] = useState('')
  const previewRequestSequence = useRef(0)
  const previewOpenRef = useRef(false)
  const invalidatePreview = () => {
    previewRequestSequence.current += 1
    setPreviewResult(null)
    setPreviewError('')
  }
  const queryKey = ['identity-department-mappings', 'oidc', source.id]

  const mappingsQ = useQuery({
    queryKey,
    queryFn: () => identityDepartmentMappingsApi.list('oidc', source.id),
    enabled: !!source.id,
  })
  const departmentsQ = useQuery({ queryKey: ['teams'], queryFn: () => orgApi.listTeams() })
  const mappings = listData<IdentityDepartmentMapping>(mappingsQ.data?.data)
  const departments = listData<DepartmentOption>(departmentsQ.data?.data)
  const departmentsUnavailable = !departmentsQ.isSuccess
  const listedDepartmentOptions = departments.map((department) => ({ value: department.id, label: department.name }))
  // Select otherwise falls back to displaying the raw selected ID when its
  // option is absent. Preserve the rule's name while loading, and keep an
  // unavailable target visible in domain language until it is reselected.
  const departmentOptions = editing && !departments.some((department) => department.id === editing.department_id)
    ? [...listedDepartmentOptions, {
      value: editing.department_id,
      label: editing.department_name?.trim()
        ? editing.department_name + (departmentsUnavailable ? '' : '（原部门不可用）')
        : '原目标部门不可用，请重新选择',
      disabled: true,
    }]
    : listedDepartmentOptions
  const targetUnavailable = !departmentsUnavailable && !!selectedDepartmentID && !departments.some((department) => department.id === selectedDepartmentID)
  const departmentName = (id?: string, name?: string) => name || departments.find((department) => department.id === id)?.name || '目标部门不可用，请重新选择'

  const refreshRules = () => {
    invalidatePreview()
    qc.invalidateQueries({ queryKey })
  }
  const saveM = useMutation({
    mutationFn: ({ id, values }: { id?: string; values: MappingFormValues }) => {
      const body: IdentityDepartmentMappingInput = {
        source_type: 'oidc',
        source_id: source.id,
        external_group: values.external_group.trim(),
        match_type: values.match_type,
        department_id: values.department_id,
        priority: values.priority,
        enabled: values.enabled,
      }
      return id ? identityDepartmentMappingsApi.update(id, body) : identityDepartmentMappingsApi.create(body)
    },
    onSuccess: () => {
      message.success('部门映射已保存')
      setEditorOpen(false)
      refreshRules()
    },
    onError: (error) => message.error(mappingError(error, '保存部门映射失败，请重试')),
  })
  const toggleM = useMutation({
    mutationFn: (mapping: IdentityDepartmentMapping) => identityDepartmentMappingsApi.update(mapping.id, {
      source_type: 'oidc', source_id: source.id, external_group: mapping.external_group,
      match_type: mapping.match_type || 'groups', department_id: mapping.department_id,
      priority: mapping.priority, enabled: !mapping.enabled,
    }),
    onSuccess: () => {
      message.success('规则状态已更新')
      refreshRules()
    },
    onError: (error) => message.error(mappingError(error, '更新规则状态失败，请重试')),
  })
  const deleteM = useMutation({
    mutationFn: (id: string) => identityDepartmentMappingsApi.delete(id),
    onSuccess: () => {
      message.success('部门映射已删除')
      setDeleting(null)
      refreshRules()
    },
    onError: (error) => message.error(mappingError(error, '删除部门映射失败，请重试')),
  })
  const previewM = useMutation({
    mutationFn: (request: { sequence: number; external_departments: string[]; external_groups: string[] }) =>
      identityDepartmentMappingsApi.preview({
        source_type: 'oidc', source_id: source.id,
        external_departments: request.external_departments, external_groups: request.external_groups,
      }),
    onSuccess: (response, request) => {
      if (previewOpenRef.current && request.sequence === previewRequestSequence.current) {
        setPreviewResult(response.data)
      }
    },
    onError: (error, request) => {
      if (previewOpenRef.current && request.sequence === previewRequestSequence.current) {
        setPreviewError(mappingError(error, '预览失败，请重试'))
      }
    },
  })

  const edit = (mapping?: IdentityDepartmentMapping) => {
    setEditing(mapping || null)
    editorForm.resetFields()
    editorForm.setFieldsValue(mapping ? {
      external_group: mapping.external_group, match_type: mapping.match_type || 'groups',
      department_id: mapping.department_id, priority: mapping.priority, enabled: mapping.enabled,
    } : { external_group: '', match_type: 'department', department_id: undefined, priority: 100, enabled: true })
    setEditorOpen(true)
  }
  const runPreview = (values: { departments?: string; groups?: string }) => {
    const external_departments = previewValues(values.departments)
    const external_groups = previewValues(values.groups)
    invalidatePreview()
    if (!external_departments.length && !external_groups.length) {
      setPreviewError('请填写至少一个部门编码或用户组')
      return
    }
    previewM.mutate({ sequence: previewRequestSequence.current, external_departments, external_groups })
  }
  const busy = saveM.isPending || toggleM.isPending || deleteM.isPending
  const matchOptions = editing && !MATCH_OPTIONS.some((item) => item.value === editing.match_type)
    ? [...MATCH_OPTIONS, { value: editing.match_type, label: MATCH_LABELS[editing.match_type] || '其他属性' }]
    : MATCH_OPTIONS
  const candidateNames = (previewResult?.candidate_departments?.length
    ? previewResult.candidate_departments.map((department) => departmentName(department.department_id, department.department_name))
    : (previewResult?.candidate_ids || []).map((id) => departmentName(id)))

  return (
    <>
      <Alert
        style={{ marginBottom: 12 }}
        type="info"
        showIcon
        message={scopeLabel(source) + ' · ' + source.display_name}
        description={source.status === 'active'
          ? '保存规则后，下次通过该生效配置登录时按新规则分配部门。优先级数字越小越优先；同优先级指向不同部门会产生冲突。'
          : '此处规则属于待启用或已停用的配置。启用该配置后才用于登录，不会修改当前生效配置的部门映射。'}
      />
      <Space style={{ marginBottom: 12 }}>
        <Button type="primary" disabled={busy} onClick={() => edit()}>新增映射</Button>
        <Button disabled={busy} onClick={() => {
          previewForm.resetFields()
          previewOpenRef.current = true
          invalidatePreview()
          setPreviewOpen(true)
        }}>预览映射</Button>
      </Space>
      {mappingsQ.isError && <Alert type="error" showIcon message="部门映射加载失败" action={<Button onClick={() => mappingsQ.refetch()}>重试</Button>} style={{ marginBottom: 12 }} />}
      {departmentsQ.isError && <Alert type="warning" showIcon message="部门列表加载失败，请重试后选择目标部门" action={<Button onClick={() => departmentsQ.refetch()}>重试</Button>} style={{ marginBottom: 12 }} />}
      <Table<IdentityDepartmentMapping>
        loading={mappingsQ.isLoading}
        dataSource={mappings}
        rowKey="id"
        size="small"
        pagination={false}
        locale={{ emptyText: '暂无部门映射，新增规则后可预览部门分配结果' }}
        columns={[
          { title: '匹配来源', dataIndex: 'match_type', render: (type: DepartmentMappingMatchType) => MATCH_LABELS[type || 'groups'] || '其他属性' },
          { title: '匹配值', dataIndex: 'external_group' },
          { title: '目标部门', render: (_, mapping) => departmentName(mapping.department_id, mapping.department_name) },
          { title: '优先级', dataIndex: 'priority', width: 100 },
          { title: '状态', dataIndex: 'enabled', width: 100, render: (enabled: boolean) => enabled ? <Tag color="green">启用</Tag> : <Tag>停用</Tag> },
          { title: '操作', render: (_, mapping) => (
            <Space>
              <Button size="small" disabled={busy} onClick={() => edit(mapping)}>编辑</Button>
              <Button size="small" disabled={busy} onClick={() => toggleM.mutate(mapping)}>{mapping.enabled ? '停用规则' : '启用规则'}</Button>
              <Button size="small" danger disabled={busy} onClick={() => setDeleting(mapping)}>删除</Button>
            </Space>
          ) },
        ]}
      />
      <Modal
        title={editing ? '编辑部门映射' : '新增部门映射'}
        open={editorOpen}
        onCancel={() => setEditorOpen(false)}
        onOk={() => editorForm.submit()}
        okText="保存映射"
        okButtonProps={{ disabled: departmentsUnavailable }}
        cancelText="取消"
        confirmLoading={saveM.isPending}
        forceRender
      >
        <Form form={editorForm} layout="vertical" onFinish={(values) => saveM.mutate({ id: editing?.id, values })}>
          <Form.Item name="match_type" label="匹配来源" rules={[{ required: true, message: '请选择匹配来源' }]}>
            <Select options={matchOptions} />
          </Form.Item>
          <Form.Item name="external_group" label="匹配值" extra="填写身份源返回的一个部门编码或用户组名称，按完整值匹配。" rules={[{ required: true, whitespace: true, message: '请输入匹配值' }]}>
            <Input maxLength={2048} placeholder="如：RD001 或 engineers" />
          </Form.Item>
          <Form.Item
            name="department_id"
            label="目标部门"
            extra={targetUnavailable ? '原目标部门已不可用，请重新选择本单位部门' : undefined}
            rules={[
              { required: true, message: '请选择目标部门' },
              { validator: (_, value) => {
                if (!value) return Promise.resolve()
                if (departmentsUnavailable) return Promise.reject(new Error('部门列表尚不可用，请加载成功后重试'))
                return departments.some((department) => department.id === value)
                  ? Promise.resolve()
                  : Promise.reject(new Error('目标部门不可用，请重新选择'))
              } },
            ]}
          >
            <Select showSearch optionFilterProp="label" options={departmentOptions} loading={departmentsQ.isLoading} disabled={departmentsUnavailable} placeholder="选择本单位已有部门" />
          </Form.Item>
          {departmentsQ.isLoading && (
            <Alert type="info" message="正在加载部门列表，加载完成后可保存" style={{ marginBottom: 12 }} />
          )}
          {departmentsQ.isError && (
            <Alert type="warning" message="部门列表加载失败，请重试后保存" action={<Button onClick={() => departmentsQ.refetch()}>重试</Button>} style={{ marginBottom: 12 }} />
          )}
          {!departmentsQ.isLoading && !departmentsQ.isError && !departments.length && (
            <Alert type="info" message="本单位暂无部门，请先在组织管理中创建部门" style={{ marginBottom: 12 }} />
          )}
          <Form.Item name="priority" label="优先级" extra="数字越小越优先。同优先级命中不同部门时需调整规则。" rules={[{ required: true, message: '请输入优先级' }, { type: 'integer', min: 1, max: 2147483647, message: '优先级应为 1 至 2147483647 的整数' }]}>
            <InputNumber min={1} max={2147483647} precision={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="enabled" label="启用规则" valuePropName="checked">
            <Switch aria-label="启用规则" />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title="确认删除映射"
        open={!!deleting}
        onCancel={() => setDeleting(null)}
        onOk={() => deleting && deleteM.mutate(deleting.id)}
        okText="确认删除"
        cancelText="取消"
        okButtonProps={{ danger: true }}
        confirmLoading={deleteM.isPending}
      >
        <p>删除匹配值「{deleting?.external_group}」到「{departmentName(deleting?.department_id, deleting?.department_name)}」的映射？</p>
        <Text type="secondary">删除后，下次登录将按其他启用规则或默认部门重新判断归属。</Text>
      </Modal>
      <Modal
        title="预览部门映射"
        open={previewOpen}
        onCancel={() => {
          previewOpenRef.current = false
          invalidatePreview()
          setPreviewOpen(false)
        }}
        onOk={() => previewForm.submit()}
        okText="查看结果"
        cancelText="关闭"
        okButtonProps={{ loading: previewM.isPending }}
        forceRender
      >
        <Text type="secondary">模拟身份源返回的属性，每行填写一个值。预览使用已保存的规则，不修改任何账号。</Text>
        <Form
          form={previewForm}
          layout="vertical"
          style={{ marginTop: 16 }}
          onFinish={runPreview}
          onValuesChange={invalidatePreview}
        >
          <Form.Item name="departments" label="预览部门编码">
            <Input.TextArea rows={3} placeholder="RD001" />
          </Form.Item>
          <Form.Item name="groups" label="预览用户组">
            <Input.TextArea rows={3} placeholder="engineers" />
          </Form.Item>
        </Form>
        {previewError && <Alert type="error" showIcon message={previewError} />}
        {previewResult && (
          <Alert
            showIcon
            type={previewResult.ambiguous ? 'warning' : previewResult.matched ? 'success' : 'info'}
            message={previewResult.ambiguous ? '命中多个部门，需调整规则'
              : previewResult.matched ? '将分配至「' + departmentName(previewResult.department_id, previewResult.department_name) + '」'
                : '未匹配到部门'}
            description={previewResult.ambiguous
              ? <><p>冲突部门：{candidateNames.join('、') || '部门名称不可用，请刷新'}</p><p>请调整优先级或停用重复规则，让最高优先级只指向一个部门。</p></>
              : previewResult.matched ? undefined : '请检查属性字段与匹配值，或新增对应部门映射。'}
          />
        )}
      </Modal>
    </>
  )
}
