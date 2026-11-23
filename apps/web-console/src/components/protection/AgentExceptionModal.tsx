import { Button, Col, Form, Input, Modal, Row, Select, Space, Switch, message } from 'antd'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import dayjs, { type Dayjs } from 'dayjs'
import { agentGuardApi, LONG_TERM_EXCEPTION_EXPIRY, type AgentGuardExceptionPayload } from '../../services/api'
import { extractApiError } from '../../utils/apiError'
import { AGENT_EXCEPTION_SCOPE_OPTIONS, FILE_TARGET_RULE } from './constants'
import ExpiryField from './ExpiryField'
import { AGENT_EXCEPTIONS_QUERY_KEY } from './protectionHooks'

export type AgentExceptionPrefill = {
  rule_id?: string
  target_pattern?: string
  scope_type?: string
}

// file：文件类防护项，目标按文件名、目录或路径匹配；mcp：目标写 mcp:<服务名>/<工具名>。
export type AgentExceptionTargetKind = 'file' | 'mcp'

type FormValues = {
  scope_type: string
  scope_ref?: string
  rule_id?: string
  target_pattern?: string
  decision: 'audit' | 'allow'
  expires_at?: Dayjs
  long_term?: boolean
  reason: string
  enabled?: boolean
}

// 智能体工具例外弹窗。与内容例外弹窗一样：要显示时才挂载，关闭即卸载。
export default function AgentExceptionModal({
  prefill,
  targetKind,
  onClose,
  onCreated,
}: {
  prefill?: AgentExceptionPrefill
  targetKind?: AgentExceptionTargetKind
  onClose: () => void
  onCreated?: () => void
}) {
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: (payload: AgentGuardExceptionPayload) => agentGuardApi.createException(payload),
    onSuccess: async () => {
      message.success('例外已创建')
      onClose()
      onCreated?.()
      await queryClient.invalidateQueries({ queryKey: AGENT_EXCEPTIONS_QUERY_KEY })
    },
    onError: (error) => message.error(extractApiError(error) || '例外创建失败'),
  })

  const submit = (values: FormValues) => {
    mutation.mutate({
      scope_type: values.scope_type,
      scope_ref: values.scope_type === 'tenant' ? '' : values.scope_ref?.trim() || '',
      rule_id: values.rule_id || '',
      target_pattern: values.target_pattern || '',
      decision: values.decision,
      reason: values.reason,
      expires_at: values.long_term ? LONG_TERM_EXCEPTION_EXPIRY : values.expires_at?.toISOString() ?? '',
      enabled: values.enabled !== false,
    })
  }

  const initialValues: Partial<FormValues> = {
    scope_type: prefill?.scope_type ?? 'project',
    rule_id: prefill?.rule_id ?? '',
    target_pattern: prefill?.target_pattern ?? '',
    decision: 'audit',
    enabled: true,
    expires_at: dayjs().add(7, 'day'),
    long_term: false,
  }

  return (
    <Modal title="新增例外放行" open onCancel={onClose} footer={null} width={620} destroyOnHidden>
      <Form<FormValues> layout="vertical" initialValues={initialValues} onFinish={submit} style={{ marginTop: 16 }}>
        <Row gutter={12}>
          <Col span={12}>
            <Form.Item name="scope_type" label="适用范围" rules={[{ required: true, message: '请选择适用范围' }]}>
              <Select options={AGENT_EXCEPTION_SCOPE_OPTIONS} />
            </Form.Item>
          </Col>
          <Col span={12}>
            <Form.Item noStyle shouldUpdate={(prev, next) => prev.scope_type !== next.scope_type}>
              {({ getFieldValue }) => (
                <Form.Item
                  name="scope_ref"
                  label="具体对象"
                  rules={[{ required: getFieldValue('scope_type') !== 'tenant', whitespace: true, message: '请输入具体对象' }]}
                >
                  <Input disabled={getFieldValue('scope_type') === 'tenant'} />
                </Form.Item>
              )}
            </Form.Item>
          </Col>
        </Row>
        <Form.Item name="rule_id" label="关联规则" rules={[{ required: true, whitespace: true, message: '请输入关联规则' }]}>
          <Input />
        </Form.Item>
        <Form.Item name="target_pattern" label="目标匹配" extra={targetKind === 'file' ? FILE_TARGET_RULE : undefined}>
          <Input placeholder={targetKind === 'mcp' ? 'mcp:服务名/工具名（工具可省）' : targetKind === 'file' ? 'id_rsa' : '例如已审批的合作方地址'} />
        </Form.Item>
        <Row gutter={12}>
          <Col span={12}>
            <Form.Item name="decision" label="降级动作" rules={[{ required: true, message: '请选择降级动作' }]}>
              <Select options={[{ value: 'audit', label: '记录审计' }, { value: 'allow', label: '放行' }]} />
            </Form.Item>
          </Col>
          <Col span={12}>
            <ExpiryField />
          </Col>
        </Row>
        <Form.Item name="reason" label="审批原因" rules={[{ required: true, message: '请输入审批原因' }]}>
          <Input.TextArea rows={3} placeholder="说明业务必要性和审批依据" />
        </Form.Item>
        <Form.Item name="enabled" label="启用状态" valuePropName="checked">
          <Switch checkedChildren="启用" unCheckedChildren="停用" />
        </Form.Item>
        <Form.Item style={{ marginBottom: 0 }}>
          <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
            <Button onClick={onClose}>取消</Button>
            <Button type="primary" htmlType="submit" loading={mutation.isPending}>创建例外</Button>
          </Space>
        </Form.Item>
      </Form>
    </Modal>
  )
}
